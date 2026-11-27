mod h3;
mod tcp;

use std::{
    collections::HashMap,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    time::{Duration, Instant},
};

use arc_swap::{ArcSwap, ArcSwapOption};
use http::{
    Request, Response, Uri, Version,
    uri::{Authority, PathAndQuery, Scheme},
};
use http_body_util::BodyExt;
use rustls::{RootCertStore, crypto::CryptoProvider, pki_types::ServerName};
use tokio::sync::Mutex;

use crate::{
    ConfigError, Result,
    config::{Limits, Provider, secret::Fingerprint},
    metrics::Stats,
    net::{egress::Egress, resolve::Overrides, tls},
    proxy::body::{Fault, ProxyBody},
};

#[derive(Clone)]
pub struct Origin {
    pub authority: Authority,
    dns: Arc<str>,
    pub(crate) resolve: Option<Arc<Overrides>>,
    port: u16,
    server_name: ServerName<'static>,
}

impl Origin {
    pub fn official(p: Provider) -> Self {
        Self {
            authority: Authority::from_static(p.host()),
            dns: p.dns_name().into(),
            resolve: None,
            port: 443,
            server_name: ServerName::try_from(p.host())
                .expect("valid static official TLS name")
                .to_owned(),
        }
    }
    pub fn uri(&self, path: PathAndQuery) -> std::result::Result<Uri, http::uri::InvalidUriParts> {
        let mut parts = http::uri::Parts::default();
        parts.scheme = Some(Scheme::HTTPS);
        parts.authority = Some(self.authority.clone());
        parts.path_and_query = Some(path);
        Uri::from_parts(parts)
    }
    #[cfg(test)]
    pub(crate) fn with_mock_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }
    #[cfg(test)]
    pub fn mock(addr: std::net::SocketAddr) -> Self {
        Self {
            authority: addr.to_string().parse().unwrap(),
            dns: addr.ip().to_string().into(),
            resolve: None,
            port: addr.port(),
            server_name: ServerName::try_from("localhost").unwrap().to_owned(),
        }
    }
}

pub struct PoolFactory {
    pub crypto: Arc<CryptoProvider>,
    pub roots: Arc<RootCertStore>,
    pub origins: [Origin; 3],
    pub limits: Limits,
    pub max_header_bytes: u32,
}

impl PoolFactory {
    pub fn build(
        &self,
        provider: Provider,
        egress: Arc<Egress>,
        stats: Arc<Stats>,
        h3: bool,
    ) -> Result<Arc<Pool>> {
        let origin = self.origins[provider.index()].clone();
        let config = |alpn: &[&[u8]], quic: bool, early: bool| {
            tls::client(self.crypto.clone(), self.roots.clone(), alpn, quic, early)
        };
        let tcp_tls = |alpn: &[&[u8]]| -> Result<[Option<Arc<rustls::ClientConfig>>; 2]> {
            let create = |v6| {
                egress
                    .local(v6)
                    .map(|_| config(alpn, false, false).map(Arc::new))
                    .transpose()
            };
            Ok([create(false)?, create(true)?])
        };
        let connect_timeout = Duration::from_secs(self.limits.connect_timeout_secs);
        let tcp = tcp::client(
            egress.clone(),
            tcp_tls(&[b"h2", b"http/1.1"])?,
            origin.clone(),
            connect_timeout,
            self.max_header_bytes,
            false,
        );
        #[cfg(feature = "websocket")]
        let ws = if self.limits.websocket {
            Some(tcp::client(
                egress.clone(),
                tcp_tls(&[b"http/1.1"])?,
                origin.clone(),
                connect_timeout,
                self.max_header_bytes,
                true,
            ))
        } else {
            None
        };
        // A plain HTTP CONNECT proxy carries TCP only. Never bypass the
        // configured proxy with a direct UDP/QUIC dial.
        let quic = if h3 && !egress.has_http_proxy() {
            let endpoints = egress.endpoints().map_err(|e| {
                ConfigError(format!(
                    "egress {}: cannot create isolated QUIC sockets: {e}",
                    egress.name
                ))
            })?;
            let transport = Arc::new(tls::transport(0, true));
            let make = |v6| -> Result<Option<quinn::ClientConfig>> {
                if egress.local(v6).is_none() {
                    return Ok(None);
                }
                let cfg = config(&[b"h3"], true, self.limits.upstream_0rtt)?;
                let cfg = quinn::crypto::rustls::QuicClientConfig::try_from(cfg)
                    .map_err(|_| "invalid upstream QUIC TLS config")?;
                let mut cfg = quinn::ClientConfig::new(Arc::new(cfg));
                cfg.transport_config(transport.clone());
                Ok(Some(cfg))
            };
            let cfg = [make(false)?, make(true)?];
            Some(h3::Pool::new(
                endpoints,
                cfg,
                egress,
                origin.clone(),
                self.max_header_bytes,
                &self.limits,
                stats.clone(),
            ))
        } else {
            None
        };
        Ok(Arc::new(Pool {
            origin,
            tcp,
            #[cfg(feature = "websocket")]
            ws,
            quic,
            stats,
            touched: AtomicU64::new(monotonic_ns()),
        }))
    }
}

pub struct Pool {
    origin: Origin,
    tcp: tcp::ClientPool,
    #[cfg(feature = "websocket")]
    ws: Option<tcp::ClientPool>,
    quic: Option<h3::Pool>,
    pub stats: Arc<Stats>,
    touched: AtomicU64,
}

impl Pool {
    pub fn origin(&self) -> &Origin {
        &self.origin
    }
    fn touch(&self) {
        // A delayed write from another worker must not move the timestamp back.
        self.touched.fetch_max(monotonic_ns(), Relaxed);
    }
    fn idle_for(&self, secs: u64) -> bool {
        Duration::from_nanos(monotonic_ns().saturating_sub(self.touched.load(Relaxed)))
            >= Duration::from_secs(secs)
    }
    pub fn reap_idle(&self) {
        if self.idle_for(55)
            && let Some(quic) = &self.quic
        {
            quic.reap_idle();
        }
    }
    pub async fn request(
        &self,
        mut request: Request<ProxyBody>,
        can_early: bool,
    ) -> std::result::Result<Response<ProxyBody>, Fault> {
        self.touch();
        if let Some(pool) = &self.quic {
            request = match pool.request(request, can_early).await? {
                h3::Outcome::Response(resp) => return Ok(resp),
                h3::Outcome::Fallback(req) => {
                    self.stats.h3_fallbacks.fetch_add(1, Relaxed);
                    req
                }
            };
        }
        // Hyper picks H2 from the connector's negotiated ALPN. Version 1.1
        // here allows both HTTP/1.1 fallback and pooled H2.
        *request.version_mut() = Version::HTTP_11;
        self.tcp
            .request(request)
            .await
            .map(|r| r.map(|b| b.map_err(|_| Fault::Response).boxed_unsync()))
            .map_err(tcp::classify)
    }
    #[cfg(feature = "websocket")]
    pub async fn upgrade(
        &self,
        request: Request<ProxyBody>,
    ) -> std::result::Result<Response<hyper::body::Incoming>, Fault> {
        self.touch();
        self.ws
            .as_ref()
            .ok_or(Fault::Connect)?
            .request(request)
            .await
            .map_err(tcp::classify)
    }
}

// All pools must share a clock epoch for their timestamps to be comparable.
fn monotonic_ns() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct PoolId(Provider, Arc<str>, Fingerprint);

// Index snapshots share slots rather than holding a separate reference to the
// pool per index generation. Only active requests retain the pool itself.
struct PoolSlot(ArcSwapOption<Pool>);
impl PoolSlot {
    fn get(&self) -> Option<Arc<Pool>> {
        let pool = self.0.load_full()?;
        pool.touch();
        Some(pool)
    }
    fn idle_touch(&self) -> Option<u64> {
        let pool = self.0.load_full()?;
        // One reference in the slot and one in this inspection.
        (Arc::strong_count(&pool) == 2).then(|| pool.touched.load(Relaxed))
    }
    fn retire_if_idle(&self, ttl_snapshot: Option<u64>) -> bool {
        // Close admission before checking again. ArcSwap's swap accounts for
        // concurrent readers, so a racing hit keeps the pool alive or retries
        // against the next index. Existing streams are never displaced.
        let Some(pool) = self.0.swap(None) else {
            return true;
        };
        if Arc::strong_count(&pool) == 1
            && ttl_snapshot.is_none_or(|touched| pool.touched.load(Relaxed) == touched)
        {
            true
        } else {
            self.0.store(Some(pool));
            false
        }
    }
}

type ByokIndex = HashMap<PoolId, Arc<PoolSlot>>;

pub struct ByokPools {
    cap: usize,
    idle: u64,
    entries: ArcSwap<ByokIndex>,
    write: Mutex<()>,
}

impl ByokPools {
    pub fn new(cap: usize, idle: u64) -> Self {
        Self {
            cap,
            idle,
            entries: ArcSwap::from_pointee(HashMap::new()),
            write: Mutex::new(()),
        }
    }
    fn expired(&self, touched: u64) -> bool {
        Duration::from_nanos(monotonic_ns().saturating_sub(touched))
            >= Duration::from_secs(self.idle)
    }
    pub(crate) async fn get(
        &self,
        factory: &PoolFactory,
        provider: Provider,
        egress: &Arc<Egress>,
        key: &[u8],
        stats: Arc<Stats>,
        h3: bool,
    ) -> Result<Arc<Pool>> {
        let id = PoolId(provider, egress.name.clone(), Fingerprint::new(key));
        if let Some(pool) = self.entries.load().get(&id).and_then(|slot| slot.get()) {
            return Ok(pool);
        }
        let _write = self.write.lock().await;
        let snapshot = self.entries.load();
        if let Some(pool) = snapshot.get(&id).and_then(|slot| slot.get()) {
            return Ok(pool);
        }
        let mut next = (*snapshot.as_ref()).clone();
        next.retain(|_, slot| {
            !slot
                .idle_touch()
                .is_some_and(|t| self.expired(t) && slot.retire_if_idle(Some(t)))
        });
        if next.len() >= self.cap {
            // Observe all idle candidates, oldest first. If a reader races an
            // eviction, consider the next candidate instead of evicting it.
            let mut candidates: Vec<_> = next
                .iter()
                .filter_map(|(id, slot)| Some((slot.idle_touch()?, id)))
                .collect();
            candidates.sort_unstable_by_key(|&(t, _)| t);
            let victim = candidates
                .into_iter()
                // At capacity this is an eviction, not a TTL expiration. If a
                // racing request has already finished, the slot is still
                // eligible; its new timestamp alone is not grounds for 503.
                .find_map(|(_, id)| next.get(id)?.retire_if_idle(None).then(|| id.clone()))
                .ok_or("all BYOK isolation pools are active")?;
            next.remove(&victim);
        }
        let pool = factory.build(provider, egress.clone(), stats, h3);
        if let Ok(pool) = &pool {
            next.insert(
                id,
                Arc::new(PoolSlot(ArcSwapOption::from(Some(pool.clone())))),
            );
        }
        // Publish retirements even when construction failed: the old slots
        // are no longer admitting requests and must not count toward capacity.
        self.entries.store(Arc::new(next));
        pool
    }
    pub async fn reap(&self) {
        let _write = self.write.lock().await;
        let snapshot = self.entries.load();
        let mut prune = false;
        for slot in snapshot.values() {
            {
                let pool = slot.0.load();
                if let Some(p) = pool.as_ref() {
                    p.reap_idle();
                }
            }
            prune |= slot
                .idle_touch()
                .is_some_and(|t| self.expired(t) && slot.retire_if_idle(Some(t)));
        }
        if prune {
            let next = snapshot
                .iter()
                .filter(|(_, slot)| slot.0.load().is_some())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            self.entries.store(Arc::new(next));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Snapshot;
    use std::path::Path;

    fn config() -> Snapshot {
        Snapshot::for_test(
            r#"
            dns_servers = ["127.0.0.1:53"]
            byok_egress = "loop"
            [egress.loop]
            mode = "v4_only"
            local_v4 = "127.0.0.1"
            [limits]
            byok_pool_capacity = 3
        "#,
            Path::new("."),
            Provider::ALL.map(Origin::official),
            Arc::new(RootCertStore::empty()),
        )
        .unwrap()
    }

    async fn pool(snapshot: &Snapshot, key: &[u8]) -> Arc<Pool> {
        let provider = Provider::Openai;
        let egress = snapshot.routes[provider.index()]
            .byok_egress
            .as_ref()
            .unwrap();
        snapshot
            .byok
            .get(
                &snapshot.factory,
                provider,
                egress,
                key,
                Arc::new(Stats::default()),
                false,
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn expired_idle_slots_are_pruned_even_with_old_index_readers() {
        let mut s = config();
        let a = pool(&s, b"one").await;
        let b = pool(&s, b"two").await;
        let old = s.byok.entries.load_full();
        let active = pool(&s, b"three").await;
        s.byok.idle = 0; // Simulate TTL expiry without wall-clock sleeps.
        drop(a);
        drop(b);
        let _new = pool(&s, b"four").await;
        assert_eq!(s.byok.entries.load().len(), 2);
        assert!(old.values().all(|slot| slot.0.load().is_none()));
        assert!(s.byok.entries.load().values().any(|slot| {
            slot.0
                .load()
                .as_ref()
                .is_some_and(|p| Arc::ptr_eq(p, &active))
        }));
    }
}
