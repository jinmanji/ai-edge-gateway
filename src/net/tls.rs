use std::{
    fmt,
    fs::File,
    io::BufReader,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    client::Resumption,
    crypto::{CryptoProvider, aws_lc_rs},
    server::{ServerSessionMemoryCache, StoresServerSessions},
};

use crate::{Result, config::TlsSpec};

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(aws_lc_rs::default_provider())
}

pub fn client(
    crypto: Arc<CryptoProvider>,
    roots: Arc<RootCertStore>,
    alpn: &[&[u8]],
    quic: bool,
    early: bool,
) -> Result<ClientConfig> {
    let versions: &[&rustls::SupportedProtocolVersion] = if quic {
        &[&rustls::version::TLS13]
    } else {
        &[&rustls::version::TLS13, &rustls::version::TLS12]
    };
    let mut config = ClientConfig::builder_with_provider(crypto)
        .with_protocol_versions(versions)
        .map_err(|_| "unsupported upstream TLS configuration")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config.resumption = Resumption::in_memory_sessions(8);
    config.enable_early_data = early;
    Ok(config)
}

pub struct DownstreamTls {
    pub tcp: Arc<ServerConfig>,
    pub quic: Option<Arc<quinn::ServerConfig>>,
    pub quic_early: bool,
}

pub fn downstream(
    spec: &TlsSpec,
    base: &Path,
    crypto: Arc<CryptoProvider>,
    h3: bool,
    streams: u32,
    max_connections: usize,
) -> Result<DownstreamTls> {
    let cert =
        File::open(base.join(&spec.cert)).map_err(|_| "cannot open TLS certificate chain")?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(cert))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|_| "invalid TLS certificate PEM")?;
    let key = File::open(base.join(&spec.key)).map_err(|_| "cannot open TLS private key")?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key))
        .map_err(|_| "invalid TLS private key PEM")?
        .ok_or("TLS private key missing")?;
    let tcp = ServerConfig::builder_with_provider(crypto.clone())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| "invalid TCP TLS versions")?
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key.clone_key())
        .map_err(|_| "invalid TLS certificate or key mismatch")?;
    let session_capacity = max_connections.saturating_mul(4).max(512);
    let tcp = configure_server(
        tcp,
        &[b"h2", b"http/1.1"],
        if spec.tcp_early_data { 16 * 1024 } else { 0 },
        session_capacity,
    )?;
    let quic = if h3 {
        let config = ServerConfig::builder_with_provider(crypto)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| "invalid QUIC TLS version")?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|_| "invalid QUIC TLS certificate or key mismatch")?;
        let config = configure_server(
            config,
            &[b"h3"],
            if spec.quic_early_data { u32::MAX } else { 0 },
            session_capacity,
        )?;
        let config = quinn::crypto::rustls::QuicServerConfig::try_from(config)
            .map_err(|_| "invalid QUIC server TLS config")?;
        let mut quic = quinn::ServerConfig::with_crypto(Arc::new(config));
        quic.transport_config(Arc::new(transport(streams, false)));
        quic.migration(false)
            .max_incoming(128)
            .incoming_buffer_size(32 * 1024)
            .incoming_buffer_size_total(1024 * 1024);
        Some(Arc::new(quic))
    } else {
        None
    };
    Ok(DownstreamTls {
        tcp: Arc::new(tcp),
        quic,
        quic_early: spec.quic_early_data,
    })
}

fn configure_server(
    mut tls: ServerConfig,
    alpn: &[&[u8]],
    early_size: u32,
    session_capacity: usize,
) -> Result<ServerConfig> {
    tls.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    tls.send_tls13_tickets = 2;
    tls.max_early_data_size = early_size;
    if early_size == 0 {
        // AWS-LC stateless ticket keys rotate internally every six hours.
        tls.ticketer =
            aws_lc_rs::Ticketer::new().map_err(|_| "cannot initialize TLS ticket rotation")?;
    } else {
        // Rustls only accepts early data with stateful tickets. `take` consumes
        // one PSK atomically, even across the epoch boundary.
        tls.session_storage = Arc::new(RotatingSessions::new(session_capacity));
    }
    Ok(tls)
}

const SESSION_EPOCH_SECS: u64 = 6 * 60 * 60;

struct SessionGenerations {
    epoch: u64,
    capacity: usize,
    current: Arc<ServerSessionMemoryCache>,
    previous: Option<Arc<ServerSessionMemoryCache>>,
}
impl SessionGenerations {
    fn rotate_to(&mut self, epoch: u64) {
        let elapsed = epoch.saturating_sub(self.epoch);
        if elapsed != 0 {
            let older = std::mem::replace(
                &mut self.current,
                ServerSessionMemoryCache::new(self.capacity),
            );
            self.previous = (elapsed == 1).then_some(older);
            self.epoch = epoch;
        }
    }
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        // Ticket identifiers are normally random; on a same-ID overwrite,
        // remove the old copy so taking the new one cannot resurrect it.
        if let Some(previous) = &self.previous {
            previous.take(&key);
        }
        self.current.put(key, value)
    }
    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.current
            .take(key)
            .or_else(|| self.previous.as_ref()?.take(key))
    }
}

struct RotatingSessions {
    start: Instant,
    cache: Mutex<SessionGenerations>,
}
impl fmt::Debug for RotatingSessions {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("RotatingSessions")
    }
}
impl RotatingSessions {
    fn new(capacity: usize) -> Self {
        Self {
            start: Instant::now(),
            cache: Mutex::new(SessionGenerations {
                epoch: 0,
                capacity,
                current: ServerSessionMemoryCache::new(capacity),
                previous: None,
            }),
        }
    }
    fn use_cache<T>(&self, f: impl FnOnce(&mut SessionGenerations) -> T) -> T {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.rotate_to(self.start.elapsed().as_secs() / SESSION_EPOCH_SECS);
        f(&mut cache)
    }
}
impl StoresServerSessions for RotatingSessions {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.use_cache(|c| c.put(key, value))
    }
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        // TLS 1.2 session-ID lookup does not consume the session. The retired
        // generation is deliberately only readable through single-use take().
        self.use_cache(|c| c.current.get(key))
    }
    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.use_cache(|c| c.take(key))
    }
    fn can_cache(&self) -> bool {
        true
    }
}

pub(crate) fn h3_alpn(value: Box<dyn std::any::Any>) -> bool {
    value
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .ok()
        .is_some_and(|h| h.protocol.as_deref() == Some(b"h3"))
}

pub fn transport(streams: u32, client: bool) -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    let idle = quinn::IdleTimeout::try_from(Duration::from_secs(if client { 75 } else { 90 })).ok();
    config
        .max_concurrent_bidi_streams(streams.into())
        .max_concurrent_uni_streams(8u32.into())
        .max_idle_timeout(idle)
        .stream_receive_window((256 * 1024u32).into())
        .receive_window((1024 * 1024u32).into())
        .send_window(1024 * 1024)
        .keep_alive_interval(client.then_some(Duration::from_secs(25)))
        .datagram_receive_buffer_size(None);
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stateful_ticket_rollover_retains_one_generation_for_single_use() {
        let cache = RotatingSessions::new(2);
        let rotate = |epoch| cache.cache.lock().unwrap().rotate_to(epoch);
        cache.put(vec![1], vec![10]);
        cache.put(vec![2], vec![20]);
        rotate(1);
        assert_eq!(cache.get(&[1]), None);
        assert_eq!(cache.take(&[1]), Some(vec![10]));
        assert_eq!(cache.take(&[1]), None);
        cache.put(vec![3], vec![30]);
        assert_eq!(cache.get(&[3]), Some(vec![30]));
        rotate(2);
        assert_eq!(cache.take(&[2]), None);
        assert_eq!(cache.take(&[3]), Some(vec![30]));
        cache.put(vec![4], vec![40]);
        rotate(4);
        assert_eq!(cache.take(&[4]), None);
    }

    #[test]
    fn stateful_ticket_generations_are_bounded_and_do_not_revive_replaced_ids() {
        let cache = RotatingSessions::new(2);
        cache.put(vec![1], vec![10]);
        cache.put(vec![2], vec![20]);
        cache.put(vec![3], vec![30]);
        assert_eq!(cache.take(&[1]), None);
        cache.cache.lock().unwrap().rotate_to(1);
        cache.put(vec![2], vec![21]);
        assert_eq!(cache.take(&[2]), Some(vec![21]));
        assert_eq!(cache.take(&[2]), None);
        assert_eq!(cache.take(&[3]), Some(vec![30]));
    }
}
