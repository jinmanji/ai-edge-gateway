//! Per-provider destination overrides. Neither the URI nor the TLS identity
//! is changed when a socket is dialed through this address book.
use std::{
    collections::{HashSet, VecDeque},
    fs::{self, File},
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::{HeaderValue, Request, StatusCode, Uri, header};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use serde::Deserialize;
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use super::{dns::Dns, tls};
use crate::{ConfigError, Result};

const MAX_LIST_BYTES: usize = 128 * 1024;
const MAX_IPS: usize = 4096;
const DIAL_CANDIDATES: usize = 16;
const DEFAULT_REFRESH: u64 = 86_400;
const RETRY: u64 = 60;
const FETCH_DEADLINE: Duration = Duration::from_secs(20);

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ResolveSpec {
    ipv4: Vec<Ipv4Addr>,
    ipv6: Vec<Ipv6Addr>,
    ipv6_list_file: Option<PathBuf>,
    ipv6_list_url: Option<String>,
    ipv6_refresh_secs: u64,
}

impl Default for ResolveSpec {
    fn default() -> Self {
        Self {
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            ipv6_list_file: None,
            ipv6_list_url: None,
            ipv6_refresh_secs: DEFAULT_REFRESH,
        }
    }
}

pub(crate) struct Overrides {
    ipv4: Vec<Ipv4Addr>,
    ipv6: Vec<Ipv6Addr>,
    remote: Option<Arc<Feed>>,
    cursor: [AtomicUsize; 2],
}

impl Overrides {
    pub(crate) fn build(
        mut spec: ResolveSpec,
        base: &Path,
        old: Option<&Self>,
        dns: Arc<Dns>,
        crypto: Arc<rustls::crypto::CryptoProvider>,
        roots: Arc<rustls::RootCertStore>,
    ) -> Result<Self> {
        if !(60..=604_800).contains(&spec.ipv6_refresh_secs) {
            return Err("ipv6_refresh_secs must be between 60 and 604800".into());
        }
        if spec.ipv4.len() > MAX_IPS || spec.ipv6.len() > MAX_IPS {
            return Err("too many static endpoint IPs".into());
        }
        // Inline addresses are trusted administrator configuration and may
        // intentionally refer to private networks (TLS still verifies the origin).
        if spec.ipv4.iter().any(|a| {
            a.is_unspecified() || a.is_multicast() || a.is_link_local() || a.is_broadcast()
        }) || spec.ipv6.iter().any(|a| {
            a.is_unspecified()
                || a.is_multicast()
                || a.is_unicast_link_local()
                || a.to_ipv4_mapped().is_some()
        }) {
            return Err("invalid unicast IP in endpoint override".into());
        }
        if let Some(path) = spec.ipv6_list_file {
            let path = base.join(path);
            let meta = fs::metadata(&path).map_err(|_| "cannot read ipv6_list_file metadata")?;
            if !meta.is_file() {
                return Err("ipv6_list_file must be a regular file".into());
            }
            let f = File::open(path).map_err(|_| "cannot open ipv6_list_file")?;
            let mut bytes = Vec::new();
            f.take((MAX_LIST_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| "cannot read ipv6_list_file")?;
            spec.ipv6
                .extend(parse_list(&bytes).map_err(ConfigError::from)?);
        }
        dedup(&mut spec.ipv4);
        dedup(&mut spec.ipv6);
        if spec.ipv6.len() > MAX_IPS {
            return Err("too many combined static IPv6 endpoint IPs".into());
        }
        let remote = if let Some(url) = spec.ipv6_list_url.as_deref() {
            let uri = feed_uri(url)?;
            let last_good = old
                .and_then(|o| o.remote.as_deref())
                .filter(|o| o.uri == uri)
                .map_or_else(|| Arc::new(Vec::new()), |o| o.addresses.load_full());
            Some(Arc::new(Feed::new(
                uri,
                spec.ipv6_refresh_secs,
                last_good,
                dns,
                crypto,
                roots,
            )?))
        } else {
            None
        };
        Ok(Self {
            ipv4: spec.ipv4,
            ipv6: spec.ipv6,
            remote,
            cursor: [AtomicUsize::new(0), AtomicUsize::new(0)],
        })
    }

    // None means to query DNS. Some(empty) means a configured remote source
    // is not ready; deliberately do not fall back to that host's broken AAAA.
    pub(crate) fn candidates(&self, port: u16, v6: bool) -> Option<VecDeque<SocketAddr>> {
        if !v6 {
            return (!self.ipv4.is_empty()).then(|| self.rotate(&self.ipv4, port, 0));
        }
        if let Some(remote) = &self.remote {
            let current = remote.addresses.load();
            let ips = if current.is_empty() {
                &self.ipv6
            } else {
                current.as_ref()
            };
            return Some(self.rotate(ips, port, 1));
        }
        (!self.ipv6.is_empty()).then(|| self.rotate(&self.ipv6, port, 1))
    }

    fn rotate<T: Copy + Into<IpAddr>>(
        &self,
        ips: &[T],
        port: u16,
        family: usize,
    ) -> VecDeque<SocketAddr> {
        if ips.is_empty() {
            return VecDeque::new();
        }
        let start = self.cursor[family].fetch_add(1, Ordering::Relaxed) % ips.len();
        ips[start..]
            .iter()
            .chain(&ips[..start])
            .take(DIAL_CANDIDATES)
            .map(|&ip| SocketAddr::new(ip.into(), port))
            .collect()
    }

    pub(crate) fn schedule(
        &self,
        provider: &'static str,
        tasks: &TaskTracker,
        stop: &CancellationToken,
    ) {
        if let Some(feed) = &self.remote {
            feed.schedule(provider, tasks, stop);
        }
    }
}

fn dedup<T: Copy + Eq + std::hash::Hash>(ips: &mut Vec<T>) {
    let mut seen = HashSet::new();
    ips.retain(|ip| seen.insert(*ip));
}

fn feed_uri(raw: &str) -> Result<Uri> {
    fn dns_label(label: &str) -> bool {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }
    let error = "ipv6_list_url requires HTTPS with a DNS hostname, port 443, a path and no credentials, query or fragment";
    if raw.len() > 2048 || raw.contains(['?', '#', '\\']) {
        return Err(error.into());
    }
    let uri: Uri = raw.parse().map_err(|_| error)?;
    let authority = uri.authority().ok_or(error)?;
    let host = authority.host();
    if uri.scheme_str() != Some("https")
        || authority.as_str().contains('@')
        || authority.port().is_some_and(|p| p.as_u16() != 443)
        || host.len() > 253
        || !host.contains('.')
        || host.parse::<IpAddr>().is_ok()
        || !host.split('.').all(dns_label)
        || !uri.path().starts_with('/')
        || uri.path() == "/"
    {
        return Err(error.into());
    }
    Ok(uri)
}

// Feeds are allowed to supply only global unicast IPv6 candidates, not
// internal services, IPv4-mapped IPs or common special-use ranges.
fn public_v6(ip: Ipv6Addr) -> bool {
    let [a, b, ..] = ip.segments();
    a & 0xe000 == 0x2000
        && !(a == 0x2001 && (b < 0x0200 || b == 0x0db8))
        && a != 0x2002
        && !(a == 0x3fff && b < 0x1000)
}

fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V6(a) => public_v6(a),
        IpAddr::V4(a) => !matches!(
            a.octets(),
            [0 | 10 | 127 | 224..=255, ..]
                | [100, 64..=127, ..]
                | [169, 254, ..]
                | [172, 16..=31, ..]
                | [192, 0, 0 | 2, _]
                | [192, 168, ..]
                | [198, 18 | 19, ..]
                | [198, 51, 100, _]
                | [203, 0, 113, _]
        ),
    }
}

fn parse_list(bytes: &[u8]) -> std::result::Result<Vec<Ipv6Addr>, &'static str> {
    if bytes.len() > MAX_LIST_BYTES {
        return Err("IPv6 list exceeds 128 KiB");
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "IPv6 list is not UTF-8")?;
    let mut seen = HashSet::new();
    let mut output = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let ip = line
            .parse()
            .map_err(|_| "expected one IPv6 address per line")?;
        if !public_v6(ip) {
            return Err("IPv6 list contains a non-public address");
        }
        if seen.insert(ip) {
            if output.len() == MAX_IPS {
                return Err("too many IPv6 addresses in list");
            }
            output.push(ip);
        }
    }
    if output.is_empty() {
        return Err("IPv6 list contains no usable addresses");
    }
    Ok(output)
}

struct Feed {
    uri: Uri,
    authority: HeaderValue,
    fqdn: Box<str>,
    name: ServerName<'static>,
    refresh: u64,
    addresses: ArcSwap<Vec<Ipv6Addr>>,
    dns: Arc<Dns>,
    tls: TlsConnector,
    born: Instant,
    next: AtomicU64,
    refreshing: AtomicBool,
}

impl Feed {
    fn new(
        uri: Uri,
        refresh: u64,
        last_good: Arc<Vec<Ipv6Addr>>,
        dns: Arc<Dns>,
        crypto: Arc<rustls::crypto::CryptoProvider>,
        roots: Arc<rustls::RootCertStore>,
    ) -> Result<Self> {
        let authority = uri.authority().ok_or("missing IPv6 list authority")?;
        let host = authority.host();
        let name =
            ServerName::try_from(host.to_owned()).map_err(|_| "invalid IPv6 list TLS hostname")?;
        let fqdn = format!("{host}.").into_boxed_str();
        let authority = HeaderValue::from_str(authority.as_str())
            .map_err(|_| "invalid IPv6 list Host header")?;
        // Separate config/connection from all provider pools, without API credentials.
        let tls = TlsConnector::from(Arc::new(tls::client(
            crypto,
            roots,
            &[b"http/1.1"],
            false,
            false,
        )?));
        Ok(Self {
            uri,
            authority,
            fqdn,
            name,
            refresh,
            addresses: ArcSwap::from(last_good),
            dns,
            tls,
            born: Instant::now(),
            next: AtomicU64::new(0),
            refreshing: AtomicBool::new(false),
        })
    }

    fn schedule(
        self: &Arc<Self>,
        provider: &'static str,
        tasks: &TaskTracker,
        stop: &CancellationToken,
    ) {
        if stop.is_cancelled()
            || self.born.elapsed().as_secs() < self.next.load(Ordering::Relaxed)
            || self.refreshing.swap(true, Ordering::Acquire)
        {
            return;
        }
        if self.born.elapsed().as_secs() < self.next.load(Ordering::Relaxed) {
            self.refreshing.store(false, Ordering::Release);
            return;
        }
        let feed = self.clone();
        let stop = stop.clone();
        tasks.spawn(async move {
            let guard = Refreshing(&feed.refreshing);
            let result = tokio::select! {
                _ = stop.cancelled() => return,
                result = timeout(FETCH_DEADLINE, feed.fetch()) => result.unwrap_or(Err("IPv6 list download timed out")),
            };
            let after = feed.update(provider, result);
            feed.next.store(feed.born.elapsed().as_secs() + after, Ordering::Relaxed);
            drop(guard);
        });
    }

    fn update(
        &self,
        provider: &'static str,
        result: std::result::Result<Vec<Ipv6Addr>, &'static str>,
    ) -> u64 {
        match result {
            Ok(ips) => {
                let count = ips.len();
                self.addresses.store(Arc::new(ips));
                tracing::info!(provider, count, "refreshed endpoint IPv6 list");
                self.refresh
            }
            Err(reason) => {
                tracing::warn!(
                    provider,
                    cached = self.addresses.load().len(),
                    reason,
                    "endpoint IPv6 list refresh failed; keeping previous candidates"
                );
                RETRY
            }
        }
    }

    async fn dial(&self, v6: bool) -> io::Result<TlsStream<TcpStream>> {
        let addresses = self.dns.addresses(&self.fqdn, 443, v6).await;
        for addr in addresses.into_iter().filter(|addr| public_ip(addr.ip())) {
            let connect = async {
                let tcp = TcpStream::connect(addr).await?;
                self.tls.connect(self.name.clone(), tcp).await
            };
            if let Ok(Ok(stream)) = timeout(Duration::from_secs(3), connect).await {
                return Ok(stream);
            }
        }
        Err(io::Error::other(
            "no reachable public address for IPv6 list host",
        ))
    }

    async fn fetch(&self) -> std::result::Result<Vec<Ipv6Addr>, &'static str> {
        let stream = tokio::select! {
            Ok(tls) = self.dial(false) => tls,
            Ok(tls) = self.dial(true) => tls,
            else => return Err("IPv6 list host connection failed"),
        };
        self.read_list(stream).await
    }

    async fn read_list<I>(&self, stream: I) -> std::result::Result<Vec<Ipv6Addr>, &'static str>
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .max_buf_size(8192)
            .max_headers(32)
            .handshake(TokioIo::new(stream))
            .await
            .map_err(|_| "IPv6 list HTTP handshake failed")?;
        let task = AbortOnDrop(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let mut req = Request::new(Empty::<Bytes>::new());
        let path = self
            .uri
            .path_and_query()
            .ok_or("missing IPv6 list path")?
            .clone();
        *req.uri_mut() = path
            .as_str()
            .parse()
            .map_err(|_| "invalid IPv6 list path")?;
        req.headers_mut()
            .insert(header::HOST, self.authority.clone());
        req.headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
        req.headers_mut().insert(
            header::USER_AGENT,
            HeaderValue::from_static("ai-edge-gateway-endpoint-refresh"),
        );
        let response = sender
            .send_request(req)
            .await
            .map_err(|_| "IPv6 list HTTP request failed")?;
        if response.status() != StatusCode::OK {
            return Err("IPv6 list HTTP response was not 200 (redirects disabled)");
        }
        if response.headers().contains_key(header::CONTENT_ENCODING)
            && response.headers()[header::CONTENT_ENCODING].as_bytes() != b"identity"
        {
            return Err("encoded IPv6 list response not supported");
        }
        let mut data = Vec::new();
        let mut body = response.into_body();
        while let Some(frame) = body.frame().await {
            if let Ok(bytes) = frame.map_err(|_| "cannot read IPv6 list body")?.into_data() {
                if bytes.len() > MAX_LIST_BYTES - data.len() {
                    return Err("IPv6 list exceeds 128 KiB");
                }
                data.extend_from_slice(&bytes);
            }
        }
        drop(task);
        parse_list(&data)
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct Refreshing<'a>(&'a AtomicBool);
impl Drop for Refreshing<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Response;
    use http_body_util::Full;
    use hyper::{body::Incoming, service::service_fn};
    use std::convert::Infallible;

    const URL: &str =
        "https://raw.githubusercontent.com/ccbkkb/ipv6-googleapis/refs/heads/main/valid_ips.txt";

    fn build(spec: ResolveSpec, old: Option<&Overrides>) -> Overrides {
        Overrides::build(
            spec,
            Path::new("."),
            old,
            Arc::new(Dns::new(&["127.0.0.1:53".parse().unwrap()]).unwrap()),
            tls::provider(),
            Arc::new(rustls::RootCertStore::empty()),
        )
        .unwrap()
    }

    fn remote_spec() -> ResolveSpec {
        ResolveSpec {
            ipv6_list_url: Some(URL.into()),
            ipv6: vec!["2607:f8b0:4001:805::200e".parse().unwrap()],
            ..ResolveSpec::default()
        }
    }

    #[test]
    fn parses_public_ipv6_text_and_rejects_invalid_or_unbounded_lists() {
        let parsed = parse_list(b" # example\n2404:6800:4007:800::200a\r\n2404:6800:4007:800::200a\n\n 2a00:1450:400d:814::200a # comment\n").unwrap();
        assert_eq!(parsed.len(), 2);
        for bad in [
            "",
            "# comment only",
            "::",
            "::1",
            "::ffff:1.2.3.4",
            "fd00::1",
            "fe80::1%eth0",
            "2001:db8::1",
            "192.0.2.1",
            "<html>error</html>",
        ] {
            assert!(parse_list(bad.as_bytes()).is_err(), "accepted {bad:?}");
        }
        assert!(parse_list(&vec![b' '; MAX_LIST_BYTES + 1]).is_err());
        assert!(feed_uri(URL).is_ok());
        for bad in [
            "http://example.org/list",
            "https://example.org:444/list",
            "https://user@example.org/list",
            "https://example.org/list?q=secret",
            "https://example.org/list#x",
            "https://127.0.0.1/list",
            "https://example.org",
        ] {
            assert!(feed_uri(bad).is_err(), "accepted {bad:?}");
        }
        for bad in ["127.0.0.1", "10.2.3.4", "169.254.169.254", "::1", "fd00::1"] {
            assert!(!public_ip(bad.parse().unwrap()));
        }
    }

    #[test]
    fn rotates_bounded_candidates_and_keeps_last_good_across_failures_and_reload() {
        let o = build(remote_spec(), None);
        assert!(o.candidates(443, false).is_none());
        assert_eq!(
            o.candidates(443, true).unwrap()[0].ip(),
            IpAddr::V6(o.ipv6[0])
        );
        let feed = o.remote.as_ref().unwrap();
        let ips: Vec<_> = (1..=32)
            .map(|i| Ipv6Addr::new(0x2404, 0x6800, 0, 0, 0, 0, 0, i))
            .collect();
        assert_eq!(feed.update("test", Ok(ips.clone())), DEFAULT_REFRESH);
        let a = o.candidates(443, true).unwrap();
        let b = o.candidates(443, true).unwrap();
        assert_eq!(a.len(), DIAL_CANDIDATES);
        assert_eq!(a[1], b[0]);
        assert_eq!(feed.update("test", Err("invalid response")), RETRY);
        assert_eq!(*feed.addresses.load_full(), ips);
        let new = build(remote_spec(), Some(&o));
        assert_eq!(*new.remote.unwrap().addresses.load_full(), ips);
        let mut different = remote_spec();
        different.ipv6_list_url = Some("https://example.org/other.txt".into());
        different.ipv6.clear();
        let reset = build(different, Some(&o));
        assert!(reset.candidates(443, true).unwrap().is_empty()); // No fallback AAAA.
    }

    #[tokio::test]
    async fn fetcher_uses_separate_public_request_and_rejects_redirects_and_large_bodies() {
        let book = build(remote_spec(), None);
        let feed = book.remote.unwrap();
        let exchange = async |status, data: Bytes| {
            let (client, server) = tokio::io::duplex(8192);
            let server = tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(server),
                        service_fn(|request: Request<Incoming>| {
                            assert_eq!(request.method(), "GET");
                            assert_eq!(
                                request.headers()[header::HOST],
                                "raw.githubusercontent.com"
                            );
                            assert!(!request.headers().contains_key(header::AUTHORIZATION));
                            assert!(!request.headers().contains_key("x-goog-api-key"));
                            assert_eq!(
                                request.uri().path(),
                                "/ccbkkb/ipv6-googleapis/refs/heads/main/valid_ips.txt"
                            );
                            let mut response = Response::new(Full::new(data.clone()));
                            *response.status_mut() = status;
                            if status == StatusCode::TEMPORARY_REDIRECT {
                                response.headers_mut().insert(
                                    header::LOCATION,
                                    HeaderValue::from_static("http://127.0.0.1/"),
                                );
                            }
                            async { Ok::<_, Infallible>(response) }
                        }),
                    )
                    .await;
            });
            let result = timeout(Duration::from_secs(2), feed.read_list(client))
                .await
                .unwrap();
            server.await.unwrap();
            result
        };
        let data = Bytes::from_static(b"2404:6800:4007:800::200a\n");
        assert_eq!(
            exchange(StatusCode::OK, data.clone()).await.unwrap().len(),
            1
        );
        assert!(
            exchange(StatusCode::TEMPORARY_REDIRECT, data)
                .await
                .is_err()
        );
        assert!(
            exchange(StatusCode::OK, Bytes::from(vec![0; MAX_LIST_BYTES + 1]))
                .await
                .is_err()
        );
    }
}
