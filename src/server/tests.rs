use std::{
    convert::Infallible,
    fs,
    future::{pending, poll_fn},
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering::Relaxed},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Version, header};
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Body, Frame, Incoming},
    client::conn::{http1 as client_h1, http2 as client_h2},
    server::conn::{http1, http2},
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use quinn::Endpoint;
use rustls::{RootCertStore, pki_types::ServerName};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Notify, mpsc},
    task::{JoinHandle, JoinSet},
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::{Running, bind_udp, shutdown, start};
use crate::{
    config::{Provider, Snapshot, TlsSpec},
    net::tls,
    pool::Origin,
    proxy::body::{self, Fault, H3Body, ProxyBody},
};

const KEY_A: &str = "local-test-user-11111111111111";
const KEY_B: &str = "local-test-user-22222222222222";
const KEY_C: &str = "local-test-user-33333333333333";
const KEY_D: &str = "local-test-user-44444444444444";
const AUTH_CONFIG: &str = r#"
[routes.openai]
mode = "managed"
[routes.claude]
mode = "managed"
host = "claude.gateway.test"
[routes.gemini]
mode = "managed"
[egress.second]
mode = "v4_only"
local_v4 = "127.0.0.2"
freebind = true
[upstreams.open_account1]
provider = "openai"
egress = "loop"
key = "mock-openai-A"
[upstreams.open_account2]
provider = "openai"
egress = "loop"
key = "mock-openai-B"
[upstreams.open_account1_second]
provider = "openai"
egress = "second"
key = "mock-openai-A"
[upstreams.anthropic]
provider = "claude"
egress = "loop"
key = "mock-anthropic"
[upstreams.google]
provider = "gemini"
egress = "loop"
key = "mock+google=/"
[users.a]
key = "local-test-user-11111111111111"
[users.a.grants]
openai = { upstream = "open_account1", methods = ["GET"], path_prefixes = ["/v1/models"] }
claude = { upstream = "anthropic", methods = ["POST"], path_prefixes = ["/v1/messages"] }
gemini = { upstream = "google" }
[users.b]
key = "local-test-user-22222222222222"
[users.b.grants]
openai = { upstream = "open_account1" }
[users.c]
key = "local-test-user-33333333333333"
[users.c.grants]
openai = { upstream = "open_account2" }
[users.d]
key = "local-test-user-44444444444444"
[users.d.grants]
openai = { upstream = "open_account1_second" }
"#;

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "aieg-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Task(JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Debug)]
struct Seen {
    path_query: String,
    version: Version,
    headers: HeaderMap,
    id: usize,
    peer: SocketAddr,
    early_transport: bool,
    tls_name: Option<String>,
    authority: Option<String>,
}

#[derive(Clone)]
struct EarlyTransport;

#[derive(Clone)]
struct TlsName(String);

struct Mock {
    heads: mpsc::UnboundedSender<Seen>,
    id: AtomicUsize,
    released: Arc<Notify>,
    cancelled: Arc<Notify>,
    upload_bytes: Arc<AtomicUsize>,
    quic_peer: std::sync::Mutex<Option<quinn::Connection>>,
}

struct MockOut {
    rx: mpsc::UnboundedReceiver<Seen>,
    mock: Arc<Mock>,
    addr: SocketAddr,
    _task: Task,
    quic: Option<(Endpoint, rustls::ServerConfig)>,
}
impl MockOut {
    async fn seen(&mut self) -> Seen {
        timeout(Duration::from_secs(3), self.rx.recv())
            .await
            .unwrap()
            .unwrap()
    }
    async fn cancelled(&self) {
        timeout(Duration::from_secs(3), self.mock.cancelled.notified())
            .await
            .unwrap();
    }
}

struct Fixture {
    _files: Temp,
    roots: Arc<RootCertStore>,
    spec: TlsSpec,
}
impl Fixture {
    fn new() -> Self {
        Self::with_sans(vec!["localhost".to_owned()])
    }
    fn with_sans(names: Vec<String>) -> Self {
        let dir = Temp::new();
        let cert = rcgen::generate_simple_self_signed(names).unwrap();
        fs::write(dir.0.join("cert.pem"), cert.cert.pem()).unwrap();
        fs::write(dir.0.join("key.pem"), cert.signing_key.serialize_pem()).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        Self {
            _files: dir,
            roots: Arc::new(roots),
            spec: TlsSpec {
                cert: "cert.pem".into(),
                key: "key.pem".into(),
                tcp_early_data: true,
                quic_early_data: true,
            },
        }
    }
    fn path(&self) -> &Path {
        &self._files.0
    }
    fn run(
        &self,
        upstream: SocketAddr,
        secure: bool,
        h3: bool,
        limits: &str,
        routes: &str,
    ) -> Running {
        self.run_with_listen(upstream, secure, h3, limits, routes, "")
    }
    fn run_with_listen(
        &self,
        upstream: SocketAddr,
        secure: bool,
        h3: bool,
        limits: &str,
        routes: &str,
        listen: &str,
    ) -> Running {
        self.run_origins(
            Provider::ALL.map(|_| Origin::mock(upstream)),
            secure,
            h3,
            limits,
            routes,
            listen,
        )
    }
    fn run_origins(
        &self,
        origins: [Origin; 3],
        secure: bool,
        h3: bool,
        limits: &str,
        routes: &str,
        listen: &str,
    ) -> Running {
        let text = format!(
            r#"
dns_servers = ["127.0.0.1:53"]
byok_egress = "loop"
[listen]
bind = "127.0.0.1:0"
management = "127.0.0.1:0"
h3 = {h3}
quic_retry = false
{listen}
[egress.loop]
mode = "v4_only"
local_v4 = "127.0.0.1"
[limits]
shutdown_drain_timeout_secs = 3
{limits}
{routes}
"#
        );
        let text = if secure {
            text + "\n[tls]\ncert = 'cert.pem'\nkey = 'key.pem'\n"
        } else {
            text
        };
        let snapshot =
            Arc::new(Snapshot::for_test(&text, self.path(), origins, self.roots.clone()).unwrap());
        // TCP and UDP have separate ephemeral port allocators. A TCP port picked
        // by the kernel occasionally happens to be in use on UDP already.
        for _ in 0..8 {
            match start(snapshot.clone()) {
                Ok(running) => return running,
                Err(e)
                    if h3
                        && e.0.starts_with("cannot bind public QUIC")
                        && e.0.contains("Address already in use") =>
                {
                    continue;
                }
                Err(e) => panic!("local gateway fixture: {e}"),
            }
        }
        panic!("cannot find a free local TCP+UDP test port");
    }
    fn tcp_client(&self, alpn: &'static [u8]) -> TlsConnector {
        TlsConnector::from(Arc::new(
            tls::client(tls::provider(), self.roots.clone(), &[alpn], false, false).unwrap(),
        ))
    }
    fn h3_client(&self) -> Endpoint {
        let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let tls = tls::client(tls::provider(), self.roots.clone(), &[b"h3"], true, true).unwrap();
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
        )));
        client
    }
    async fn mock_tcp(&self, h2: bool) -> MockOut {
        let config =
            tls::downstream(&self.spec, self.path(), tls::provider(), false, 32, 256).unwrap();
        let mut config = (*config.tcp).clone();
        config.alpn_protocols = if h2 {
            vec![b"h2".to_vec()]
        } else {
            vec![b"http/1.1".to_vec()]
        };
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (mock, rx) = mock();
        let shared = mock.clone();
        let task = Task(tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    _ = children.join_next(), if !children.is_empty() => {}
                    r = listener.accept() => {
                        let Ok((tcp, peer)) = r else { break; };
                        tcp.set_nodelay(true).unwrap();
                        let acceptor = acceptor.clone();
                        let mock = shared.clone();
                        children.spawn(async move {
                            let Ok(tls) = acceptor.accept(tcp).await else { return; };
                            let id = mock.id.fetch_add(1, Relaxed);
                            let name = tls.get_ref().1.server_name().map(|name| TlsName(name.to_owned()));
                            let svc = service_fn(move |mut r: Request<Incoming>| {
                                if let Some(name) = &name { r.extensions_mut().insert(name.clone()); }
                                handle_mock(r.map(|b| b.map_err(|_| Fault::Downstream).boxed_unsync()), peer, id, mock.clone())
                            });
                            if h2 {
                                let _ = http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(tls), svc).await;
                            } else {
                                let conn = http1::Builder::new().serve_connection(TokioIo::new(tls), svc);
                                #[cfg(feature = "websocket")]
                                let conn = conn.with_upgrades();
                                let _ = conn.await;
                            }
                        });
                    }
                }
            }
        }));
        MockOut {
            rx,
            mock,
            addr,
            _task: task,
            quic: None,
        }
    }
    fn mock_quic(&self) -> MockOut {
        let tcp =
            tls::downstream(&self.spec, self.path(), tls::provider(), false, 32, 256).unwrap();
        let mut base = (*tcp.tcp).clone();
        base.alpn_protocols = vec![b"h3".to_vec()];
        let endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(mock_tls_quic(&base, true)),
            bind_udp("127.0.0.1:0".parse().unwrap()).unwrap(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let shared_endpoint = endpoint.clone();
        let addr = endpoint.local_addr().unwrap();
        let (mock, rx) = mock();
        let shared = mock.clone();
        let task = Task(tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    _ = children.join_next(), if !children.is_empty() => {}
                    i = endpoint.accept() => {
                        let Some(i) = i else { break; };
                        let mock = shared.clone();
                        children.spawn(async move {
                            let Ok(conn) = i.await else { return; };
                            let id = mock.id.fetch_add(1, Relaxed);
                            let peer = conn.remote_address();
                            *mock.quic_peer.lock().unwrap() = Some(conn.clone());
                            let Ok(mut server) = h3::server::builder().send_grease(false).build(h3_quinn::Connection::new(conn)).await else { return; };
                            let mut handlers = JoinSet::new();
                            loop {
                                tokio::select! {
                                    _ = handlers.join_next(), if !handlers.is_empty() => {}
                                    r = poll_fn(|cx| server.poll_accept_request_stream(cx)) => {
                                        let Ok(Some(stream)) = r else { break; };
                                        let stopped = stream.stopped();
                                        let resolver = server.create_resolver(h3::frame::FrameStream::new(h3::stream::BufRecvStream::new(stream)));
                                        let mock = mock.clone();
                                        handlers.spawn(async move {
                                            tokio::select! {
                                                biased;
                                                _ = stopped => {}
                                                _ = async move {
                                                    let Ok((mut r, stream)) = resolver.resolve_request().await else { return; };
                                                    // The mock deliberately waits for the QUIC
                                                    // handshake before polling H3 stream accept.
                                                    if stream.transport().is_0rtt() {
                                                        r.extensions_mut().insert(EarlyTransport);
                                                    }
                                                    let (mut send, recv) = stream.split();
                                                    let r = r.map(|_| H3Body::new(recv, None).boxed_unsync());
                                                    let Ok(response) = handle_mock(r, peer, id, mock).await;
                                                    let (parts, mut body) = response.into_parts();
                                                    if send.send_response(Response::from_parts(parts, ())).await.is_err() { return; }
                                                    while let Some(Ok(f)) = body.frame().await {
                                                        if let Ok(data) = f.into_data() && send.send_data(data).await.is_err() { return; }
                                                    }
                                                    let _ = send.finish().await;
                                                } => {}
                                            }
                                        });
                                    }
                                }
                            }
                        });
                    }
                }
            }
        }));
        MockOut {
            rx,
            mock,
            addr,
            _task: task,
            quic: Some((shared_endpoint, base)),
        }
    }
}

fn mock_tls_quic(base: &rustls::ServerConfig, early: bool) -> quinn::ServerConfig {
    let mut cfg = base.clone();
    cfg.max_early_data_size = if early { u32::MAX } else { 0 };
    quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(cfg).unwrap(),
    ))
}

fn mock() -> (Arc<Mock>, mpsc::UnboundedReceiver<Seen>) {
    let (heads, rx) = mpsc::unbounded_channel();
    (
        Arc::new(Mock {
            heads,
            id: AtomicUsize::new(0),
            released: Arc::new(Notify::new()),
            cancelled: Arc::new(Notify::new()),
            upload_bytes: Arc::new(AtomicUsize::new(0)),
            quic_peer: std::sync::Mutex::new(None),
        }),
        rx,
    )
}

async fn handle_mock(
    mut req: Request<ProxyBody>,
    peer: SocketAddr,
    id: usize,
    mock: Arc<Mock>,
) -> Result<Response<ProxyBody>, Infallible> {
    let url = req
        .uri()
        .path_and_query()
        .map_or("", |p| p.as_str())
        .to_owned();
    let path = req.uri().path().to_owned();
    let _ = mock.heads.send(Seen {
        path_query: url,
        headers: req.headers().clone(),
        version: req.version(),
        id,
        peer,
        early_transport: req.extensions().get::<EarlyTransport>().is_some(),
        tls_name: req
            .extensions()
            .get::<TlsName>()
            .map(|value| value.0.clone()),
        authority: req.uri().authority().map(|value| value.as_str().to_owned()),
    });
    if path.ends_with("/wait") {
        let _watch = NotifyDrop(mock.cancelled.clone());
        pending::<()>().await;
    }
    if path.ends_with("/stream") {
        let events = EventBody {
            first: true,
            last: false,
            gate: Box::pin(async move {
                mock.released.notified().await;
            }),
        };
        let mut r = Response::new(events.boxed_unsync());
        r.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream; charset=utf-8"),
        );
        r.headers_mut()
            .insert(header::ALT_SVC, HeaderValue::from_static("h3=\":12345\""));
        return Ok(r);
    }
    if path.ends_with("/upload") {
        while let Some(frame) = req.body_mut().frame().await {
            let Ok(f) = frame else {
                return Ok(body::text(StatusCode::BAD_REQUEST, "broken upload"));
            };
            if let Ok(data) = f.into_data() {
                mock.upload_bytes.fetch_add(data.len(), Relaxed);
            }
        }
    }
    #[cfg(feature = "websocket")]
    if path.ends_with("/realtime") {
        let ws = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            if let Ok(ws) = ws.await {
                let (mut r, mut w) = tokio::io::split(TokioIo::new(ws));
                let _ = tokio::io::copy(&mut r, &mut w).await;
            }
        });
        return Ok(Response::builder()
            .status(101)
            .header("upgrade", "websocket")
            .header("connection", "upgrade")
            .header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
            .header("sec-websocket-protocol", "realtime")
            .body(body::empty())
            .unwrap());
    }
    Ok(body::text(StatusCode::OK, "mock-ok"))
}

struct NotifyDrop(Arc<Notify>);
impl Drop for NotifyDrop {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

struct EventBody {
    first: bool,
    last: bool,
    gate: Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
}
impl Body for EventBody {
    type Data = Bytes;
    type Error = Fault;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Fault>>> {
        if self.first {
            self.first = false;
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(
                b"data: first\n\n",
            )))));
        }
        if self.last {
            return Poll::Ready(None);
        }
        std::task::ready!(self.gate.as_mut().poll(cx));
        self.last = true;
        Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"data: last\n\n")))))
    }
}

fn req(path: &str) -> Request<ProxyBody> {
    Request::builder()
        .uri(path)
        .header(header::HOST, "localhost")
        .header(header::AUTHORIZATION, "Bearer mock-byok")
        .body(body::empty())
        .unwrap()
}

async fn client1(addr: SocketAddr) -> (client_h1::SendRequest<ProxyBody>, Task) {
    let tcp = TcpStream::connect(addr).await.unwrap();
    tcp.set_nodelay(true).unwrap();
    let (sender, driver) = client_h1::handshake(TokioIo::new(tcp)).await.unwrap();
    (
        sender,
        Task(tokio::spawn(async move {
            let _ = driver.await;
        })),
    )
}
async fn body_eq(mut response: Response<Incoming>, expect: StatusCode) {
    assert_eq!(response.status(), expect);
    let mut found = Bytes::new();
    while let Some(f) = response.body_mut().frame().await {
        if let Ok(bytes) = f.unwrap().into_data() {
            found = bytes;
        }
    }
    if expect == StatusCode::OK {
        assert_eq!(found, "mock-ok");
    }
}

#[tokio::test]
async fn h1_to_h2_managed_authorization_preservation_and_isolation() {
    let f = Fixture::new();
    let mut mock = f.mock_tcp(true).await;
    let running = f.run(mock.addr, false, false, "", AUTH_CONFIG);
    let (mut cli, _driver) = client1(running.public_addr).await;
    let mut ids = Vec::new();
    for (k, upstream) in [
        (KEY_A, "Bearer mock-openai-A"),
        (KEY_B, "Bearer mock-openai-A"),
        (KEY_C, "Bearer mock-openai-B"),
        (KEY_D, "Bearer mock-openai-A"),
        (KEY_A, "Bearer mock-openai-A"),
    ] {
        let mut r = req("/openai/v1/models?x=%2f&stale=false");
        r.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {k}")).unwrap(),
        );
        r.headers_mut().insert(
            "openai-project",
            HeaderValue::from_static("my-mock-project"),
        );
        body_eq(cli.send_request(r).await.unwrap(), StatusCode::OK).await;
        let s = mock.seen().await;
        assert_eq!(s.headers[header::AUTHORIZATION], upstream);
        assert_eq!(s.headers["openai-project"], "my-mock-project");
        assert_eq!(s.path_query, "/v1/models?x=%2f&stale=false");
        assert_eq!(s.version, Version::HTTP_2);
        assert_eq!(
            s.peer.ip().to_string(),
            if k == KEY_D { "127.0.0.2" } else { "127.0.0.1" }
        );
        ids.push(s.id);
    }
    assert_eq!(ids[0], ids[1]);
    assert_eq!(ids[0], ids[4]);
    assert_ne!(ids[0], ids[2]);
    assert_ne!(ids[0], ids[3]);
    assert_ne!(ids[2], ids[3]);
    let claude = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("host", "CLAUDE.gateway.test")
        .header("x-api-key", KEY_A)
        .header("anthropic-version", "2023-06-01")
        .header("anthropic-beta", "test-beta")
        .body(
            Full::new(Bytes::from_static(b"{}"))
                .map_err(|e| match e {})
                .boxed_unsync(),
        )
        .unwrap();
    body_eq(cli.send_request(claude).await.unwrap(), StatusCode::OK).await;
    let seen = mock.seen().await;
    assert_eq!(seen.path_query, "/v1/messages");
    assert_eq!(seen.headers["x-api-key"], "mock-anthropic");
    assert_eq!(seen.headers["anthropic-version"], "2023-06-01");
    assert_eq!(seen.headers["anthropic-beta"], "test-beta");
    let gemini = Request::builder()
        .uri(format!(
            "/gemini/v1beta/models:generateContent?alt=sse&&%6Bey={KEY_A}&more=%2f&"
        ))
        .header("host", "localhost")
        .body(body::empty())
        .unwrap();
    body_eq(cli.send_request(gemini).await.unwrap(), StatusCode::OK).await;
    assert_eq!(
        mock.seen().await.path_query,
        "/v1beta/models:generateContent?alt=sse&&key=mock%2Bgoogle%3D%2F&more=%2f&"
    );
    let gemini = Request::builder()
        .uri("/gemini/v1beta/models")
        .header("host", "localhost")
        .header("x-goog-api-key", KEY_A)
        .body(body::empty())
        .unwrap();
    body_eq(cli.send_request(gemini).await.unwrap(), StatusCode::OK).await;
    assert_eq!(mock.seen().await.headers["x-goog-api-key"], "mock+google=/");
    let gemini = Request::builder()
        .uri("/gemini/v1beta/openai/models")
        .header("host", "localhost")
        .header("x-gateway-key", KEY_A)
        .body(body::empty())
        .unwrap();
    body_eq(cli.send_request(gemini).await.unwrap(), StatusCode::OK).await;
    let seen = mock.seen().await;
    assert_eq!(seen.headers[header::AUTHORIZATION], "Bearer mock+google=/");
    assert!(!seen.headers.contains_key("x-gateway-key"));
    let rejected = Request::builder()
        .uri("/claude/v1/messages")
        .header("host", "localhost")
        .header("x-api-key", KEY_B)
        .body(body::empty())
        .unwrap();
    body_eq(
        cli.send_request(rejected).await.unwrap(),
        StatusCode::UNAUTHORIZED,
    )
    .await;
    for path in [
        "/openai/v1/models-extra",
        "/openai/v1/models/%2E%2E/responses",
        "/openai/v1/models/../responses",
    ] {
        let mut r = req(path);
        r.headers_mut()
            .insert("authorization", format!("Bearer {KEY_A}").parse().unwrap());
        body_eq(cli.send_request(r).await.unwrap(), StatusCode::FORBIDDEN).await;
    }
    let mut post = req("/openai/v1/responses");
    *post.method_mut() = Method::POST;
    post.headers_mut()
        .insert("early-data", HeaderValue::from_static("1"));
    body_eq(cli.send_request(post).await.unwrap(), StatusCode::TOO_EARLY).await;
    assert!(mock.rx.try_recv().is_err());
    assert!(shutdown(&running.app).await);
}

#[tokio::test]
async fn h2c_and_tls_h2_to_h1_with_h3_probe_fallback() {
    let f = Fixture::new();
    let mut mock = f.mock_tcp(false).await;
    for secure in [false, true] {
        let running = f.run(
            mock.addr,
            secure,
            secure,
            "h3_probe_timeout_ms=80",
            "[routes.openai]\nprefer_h3=true\n",
        );
        let tcp = TcpStream::connect(running.public_addr).await.unwrap();
        let (mut sender, driver) = if secure {
            let tls = f
                .tcp_client(b"h2")
                .connect(ServerName::try_from("localhost").unwrap(), tcp)
                .await
                .unwrap();
            let (s, d) = client_h2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .unwrap();
            (
                s,
                Task(tokio::spawn(async move {
                    let _ = d.await;
                })),
            )
        } else {
            let (s, d) = client_h2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
                .await
                .unwrap();
            (
                s,
                Task(tokio::spawn(async move {
                    let _ = d.await;
                })),
            )
        };
        for _ in 0..2 {
            let mut r = req(if secure {
                "https://localhost/openai/v1/models"
            } else {
                "http://localhost/openai/v1/models"
            });
            *r.version_mut() = Version::HTTP_2;
            let out = sender.send_request(r).await.unwrap();
            assert_eq!(out.version(), Version::HTTP_2);
            assert_eq!(out.headers().contains_key(header::ALT_SVC), secure);
            body_eq(out, StatusCode::OK).await;
            let s = mock.seen().await;
            assert_eq!(s.version, Version::HTTP_11);
            assert_eq!(s.headers[header::HOST], mock.addr.to_string());
        }
        let snapshot = running.app.config.load();
        assert_eq!(
            snapshot
                .metrics
                .values()
                .map(|s| s.h3_fallbacks.load(Relaxed))
                .sum::<u64>(),
            2
        );
        drop(driver);
        assert!(shutdown(&running.app).await);
    }
}

#[tokio::test]
async fn first_sse_chunk_without_waiting_and_regular_graceful_drain() {
    let f = Fixture::new();
    let mut mock = f.mock_tcp(true).await;
    let running = f.run(mock.addr, false, false, "", "");
    let (mut cli, _driver) = client1(running.public_addr).await;
    let mut res = timeout(
        Duration::from_secs(2),
        cli.send_request(req("/openai/v1/stream")),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(res.headers()["x-accel-buffering"], "no");
    assert!(!res.headers().contains_key(header::ALT_SVC));
    let first = timeout(Duration::from_secs(2), res.body_mut().frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first.into_data().unwrap(), "data: first\n\n");
    mock.seen().await;
    let app = running.app.clone();
    let drain = tokio::spawn(async move { shutdown(&app).await });
    running.app.stop.cancelled().await;
    assert!(!drain.is_finished());
    mock.mock.released.notify_one();
    let last = res
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(last, "data: last\n\n");
    assert!(res.body_mut().frame().await.is_none());
    assert!(drain.await.unwrap());
}

#[tokio::test]
async fn deadlines_and_disconnect_cancel_upstream_before_headers() {
    let f = Fixture::new();
    let mut mock = f.mock_tcp(true).await;
    let running = f.run(
        mock.addr,
        false,
        false,
        "response_header_timeout_secs=1\nstream_idle_timeout_secs=1",
        "",
    );
    let (mut cli, conn) = client1(running.public_addr).await;
    let wait = cli.send_request(req("/openai/v1/wait"));
    tokio::pin!(wait);
    tokio::select! { _ = mock.seen() => {}, _ = &mut wait => panic!("unexpected response before disconnect") }
    drop(conn);
    mock.cancelled().await;
    let (mut cli, _conn) = client1(running.public_addr).await;
    let response = timeout(
        Duration::from_secs(3),
        cli.send_request(req("/openai/v1/wait")),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    mock.seen().await;
    mock.cancelled().await;
    let mut response = cli.send_request(req("/openai/v1/stream")).await.unwrap();
    assert!(response.body_mut().frame().await.unwrap().is_ok());
    assert!(
        timeout(Duration::from_secs(3), response.body_mut().frame())
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(shutdown(&running.app).await);
}

#[tokio::test]
async fn both_h3_legs_stream_and_cancel_without_closing_connection() {
    let f = Fixture::new();
    let mut mock = f.mock_quic();
    let running = f.run(
        mock.addr,
        true,
        true,
        "h3_probe_timeout_ms=800",
        "[routes.openai]\nprefer_h3=true\n",
    );
    let endpoint = f.h3_client();
    let quic = endpoint
        .connect(running.public_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut driver, mut client) = h3::client::new(h3_quinn::Connection::new(quic))
        .await
        .unwrap();
    let _driver = Task(tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    }));
    let make = |path: &str| {
        Request::builder()
            .uri(format!("https://localhost/openai/v1/{path}"))
            .header("authorization", "Bearer mock-byok")
            .body(())
            .unwrap()
    };
    let mut stream = client.send_request(make("wait")).await.unwrap();
    stream.finish().await.unwrap();
    let first = mock.seen().await;
    assert_eq!(first.version, Version::HTTP_3);
    stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
    mock.cancelled().await;
    let mut stream = client.send_request(make("stream")).await.unwrap();
    stream.finish().await.unwrap();
    let resp = timeout(Duration::from_secs(3), stream.recv_response())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["x-accel-buffering"], "no");
    assert_eq!(
        resp.headers()[header::ALT_SVC],
        format!("h3=\":{}\"; ma=86400", running.public_addr.port())
    );
    assert_eq!(mock.seen().await.id, first.id);
    let mut first = stream.recv_data().await.unwrap().unwrap();
    use bytes::Buf;
    assert_eq!(first.copy_to_bytes(first.remaining()), "data: first\n\n");
    let app = running.app.clone();
    let drain = tokio::spawn(async move { shutdown(&app).await });
    running.app.stop.cancelled().await;
    assert!(!drain.is_finished());
    mock.mock.released.notify_one();
    let mut last = stream.recv_data().await.unwrap().unwrap();
    assert_eq!(last.copy_to_bytes(last.remaining()), "data: last\n\n");
    assert!(stream.recv_data().await.unwrap().is_none());
    assert!(drain.await.unwrap());
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn h1_websocket_upgrade_is_opaque_and_keeps_authentication() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let f = Fixture::new();
    let mut mock = f.mock_tcp(false).await;
    let running = f.run(mock.addr, false, false, "", "");
    let mut tcp = TcpStream::connect(running.public_addr).await.unwrap();
    let head = b"GET /openai/v1/realtime HTTP/1.1\r\nHost: localhost\r\nConnection: upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: realtime\r\nAuthorization: Bearer dummy-realtime\r\n\r\n";
    tcp.write_all(head).await.unwrap();
    let response = timeout(Duration::from_secs(3), async {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") && bytes.len() < 8192 {
            bytes.push(tcp.read_u8().await.unwrap());
        }
        String::from_utf8(bytes).unwrap()
    })
    .await
    .unwrap();
    assert!(response.starts_with("HTTP/1.1 101 "), "{response}");
    assert!(response.contains("sec-websocket-protocol: realtime"));
    let capture = mock.seen().await;
    assert_eq!(
        capture.headers[header::AUTHORIZATION],
        "Bearer dummy-realtime"
    );
    assert_eq!(capture.path_query, "/v1/realtime");
    let arbitrary = b"opaque ws bytes";
    tcp.write_all(arbitrary).await.unwrap();
    let mut replay = [0; 15];
    timeout(Duration::from_secs(3), tcp.read_exact(&mut replay))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&replay, arbitrary);
    assert_eq!(running.app.global.in_flight.load(Relaxed), 1);
    drop(tcp);
    assert!(shutdown(&running.app).await);
}

fn byok_request(path: &str, auth: &'static str) -> Request<ProxyBody> {
    let mut request = req(path);
    request
        .headers_mut()
        .insert(header::AUTHORIZATION, HeaderValue::from_static(auth));
    request
}

#[tokio::test]
async fn byok_evicts_lru_instead_of_rejecting_a_new_key() {
    const A: &str = "Bearer mock-account-a";
    const B: &str = "Bearer mock-account-b";
    const C: &str = "Bearer mock-account-c";
    let f = Fixture::new();
    let mut mock = f.mock_tcp(true).await;
    let running = f.run(mock.addr, false, false, "byok_pool_capacity=2", "");
    let (mut cli, _driver) = client1(running.public_addr).await;
    let mut ids = Vec::new();
    for key in [A, B, A, C, A, B] {
        let response = cli
            .send_request(byok_request("/openai/v1/models", key))
            .await
            .unwrap();
        body_eq(response, StatusCode::OK).await;
        let seen = mock.seen().await;
        assert_eq!(seen.headers[header::AUTHORIZATION], key);
        ids.push(seen.id);
    }
    let [a, b, a_hit, c, a_kept, b_redial] = ids[..] else {
        unreachable!()
    };
    assert_eq!(a, a_hit);
    assert_eq!(a, a_kept);
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(b, c);
    assert!(![a, b, c].contains(&b_redial));
    assert!(shutdown(&running.app).await);
}

#[tokio::test]
async fn byok_at_capacity_rejects_only_while_all_pools_have_active_requests() {
    const A: &str = "Bearer mock-account-a";
    const B: &str = "Bearer mock-account-b";
    const C: &str = "Bearer mock-account-c";
    let f = Fixture::new();
    let mut mock = f.mock_tcp(true).await;
    let running = f.run(mock.addr, false, false, "byok_pool_capacity=2", "");
    let (mut cli_a, _driver_a) = client1(running.public_addr).await;
    let (mut cli_b, driver_b) = client1(running.public_addr).await;
    let (mut cli_c, _driver_c) = client1(running.public_addr).await;
    let a = cli_a
        .send_request(byok_request("/openai/v1/stream", A))
        .await
        .unwrap();
    assert_eq!(a.status(), StatusCode::OK);
    let a_seen = mock.seen().await;
    let b = cli_b.send_request(byok_request("/openai/v1/wait", B));
    tokio::pin!(b);
    let b_seen = tokio::select! {
        seen = mock.seen() => seen,
        got = &mut b => panic!("unexpected response from waiting upstream: {got:?}"),
    };
    let rejected = cli_c
        .send_request(byok_request("/openai/v1/models", C))
        .await
        .unwrap();
    body_eq(rejected, StatusCode::SERVICE_UNAVAILABLE).await;
    assert!(mock.rx.try_recv().is_err());
    drop(driver_b);
    mock.cancelled().await;
    let c = cli_c
        .send_request(byok_request("/openai/v1/models", C))
        .await
        .unwrap();
    body_eq(c, StatusCode::OK).await;
    let c_seen = mock.seen().await;
    assert_ne!(a_seen.id, b_seen.id);
    assert!(![a_seen.id, b_seen.id].contains(&c_seen.id));
    assert_eq!(c_seen.headers[header::AUTHORIZATION], C);
    drop(a);
    assert!(shutdown(&running.app).await);
}

#[tokio::test]
async fn request_upload_is_forwarded_before_the_client_finishes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let f = Fixture::new();
    let mock = f.mock_tcp(true).await;
    let running = f.run(
        mock.addr,
        false,
        false,
        "response_header_timeout_secs=1\nstream_idle_timeout_secs=1",
        "",
    );
    let mut tcp = TcpStream::connect(running.public_addr).await.unwrap();
    tcp.write_all(b"POST /openai/v1/upload HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer mock-byok\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n").await.unwrap();
    timeout(Duration::from_secs(2), async {
        while mock.mock.upload_bytes.load(Relaxed) != 4 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    for n in 1..=3 {
        sleep(Duration::from_millis(400)).await;
        tcp.write_all(b"5\r\nhello\r\n").await.unwrap();
        timeout(Duration::from_secs(2), async {
            while mock.mock.upload_bytes.load(Relaxed) != 4 + 5 * n {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
    tcp.write_all(b"0\r\n\r\n").await.unwrap();
    let mut prefix = [0; 12];
    timeout(Duration::from_secs(2), tcp.read_exact(&mut prefix))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&prefix, b"HTTP/1.1 200");
    drop(tcp);
    assert!(shutdown(&running.app).await);
}

#[tokio::test]
async fn upstream_quic_resumption_attempts_early_and_retries_only_explicit_rejection() {
    let f = Fixture::new();
    let mut mock = f.mock_quic();
    let running = f.run(
        mock.addr,
        false,
        false,
        "h3_probe_timeout_ms=1000",
        "[routes.openai]\nprefer_h3=true\n",
    );
    let (mut client, _driver) = client1(running.public_addr).await;
    let stats = running
        .app
        .config
        .load()
        .metrics
        .iter()
        .find(|((p, _), _)| *p == Provider::Openai)
        .unwrap()
        .1
        .clone();
    for leg in 0..3 {
        if leg == 2 {
            let (ep, cfg) = mock.quic.as_ref().unwrap();
            ep.set_server_config(Some(mock_tls_quic(cfg, false)));
        }
        body_eq(
            client.send_request(req("/openai/v1/models")).await.unwrap(),
            StatusCode::OK,
        )
        .await;
        let incoming = mock.seen().await;
        assert_eq!(incoming.version, Version::HTTP_3);
        assert_eq!(incoming.headers.contains_key("early-data"), leg == 1);
        if leg < 2 {
            sleep(Duration::from_millis(30)).await;
            mock.mock
                .quic_peer
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .close(0u32.into(), b"");
            sleep(Duration::from_millis(70)).await;
        }
    }
    assert_eq!(stats.h3_early_accepted.load(Relaxed), 1);
    assert_eq!(stats.h3_early_rejected.load(Relaxed), 1);
    assert_eq!(stats.h3_fallbacks.load(Relaxed), 0);
    assert!(mock.rx.try_recv().is_err());
    assert!(shutdown(&running.app).await);
}

#[tokio::test]
async fn downstream_quic_early_data_policy_and_tls_resumption() {
    let f = Fixture::new();
    let mut mock = f.mock_tcp(true).await;
    let running = f.run(mock.addr, true, true, "", "");
    let endpoint = f.h3_client();
    let make = |method: Method| {
        Request::builder()
            .method(method)
            .uri("https://localhost/openai/v1/models")
            .header("authorization", "Bearer mock-byok")
            .body(())
            .unwrap()
    };
    let connect = || endpoint.connect(running.public_addr, "localhost").unwrap();
    let seed = connect().await.unwrap();
    let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(seed.clone()))
        .await
        .unwrap();
    let _seed_driver = Task(tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    }));
    let mut req = send.send_request(make(Method::GET)).await.unwrap();
    req.finish().await.unwrap();
    assert_eq!(req.recv_response().await.unwrap().status(), StatusCode::OK);
    while req.recv_data().await.unwrap().is_some() {}
    mock.seen().await;
    sleep(Duration::from_millis(50)).await;
    seed.close(0u32.into(), b"");
    let (early, accepted) = connect().into_0rtt().expect("resumption ticket with 0-RTT");
    let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(early))
        .await
        .unwrap();
    let _early_driver = Task(tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    }));
    let mut req = send.send_request(make(Method::POST)).await.unwrap();
    req.finish().await.unwrap();
    assert!(accepted.await);
    assert_eq!(
        req.recv_response().await.unwrap().status(),
        StatusCode::TOO_EARLY
    );
    assert!(mock.rx.try_recv().is_err());
    let mut req = send.send_request(make(Method::POST)).await.unwrap();
    req.finish().await.unwrap();
    assert_eq!(req.recv_response().await.unwrap().status(), StatusCode::OK);
    mock.seen().await;
    while req.recv_data().await.unwrap().is_some() {}
    assert!(shutdown(&running.app).await);
}

#[tokio::test]
async fn tcp_tls_accepts_early_bytes_but_dispatches_only_after_handshake() {
    use std::io::{Read, Write};
    let f = Fixture::new();
    let mut mock = f.mock_tcp(true).await;
    let running = f.run(mock.addr, true, false, "", "");
    let addr = running.public_addr;
    let cfg = Arc::new(
        tls::client(
            tls::provider(),
            f.roots.clone(),
            &[b"http/1.1"],
            false,
            true,
        )
        .unwrap(),
    );
    tokio::task::spawn_blocking(move || {
        const POST: &[u8] = b"POST /openai/v1/models HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer mock-byok\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        for send_early in [false, true] {
            let mut session = rustls::ClientConnection::new(cfg.clone(), ServerName::try_from("localhost").unwrap()).unwrap();
            let mut tcp = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            tcp.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
            if send_early {
                session.early_data().expect("resumable TCP TLS ticket").write_all(POST).unwrap();
                session.complete_io(&mut tcp).unwrap();
                assert!(session.is_early_data_accepted());
            }
            let mut stream = rustls::StreamOwned::new(session, tcp);
            if !send_early { stream.write_all(POST).unwrap(); }
            let mut prefix = [0; 12];
            stream.read_exact(&mut prefix).unwrap();
            assert_eq!(&prefix, b"HTTP/1.1 200");
            let mut rest = Vec::new();
            let _ = stream.read_to_end(&mut rest);
            assert!(rest.ends_with(b"mock-ok"));
        }
    }).await.unwrap();
    for _ in 0..2 {
        let seen = mock.seen().await;
        assert!(!seen.headers.contains_key("early-data"));
    }
    assert!(shutdown(&running.app).await);
}

type H3Client = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type H3ClientStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

async fn client3(endpoint: &Endpoint, addr: SocketAddr) -> (H3Client, Task) {
    let quic = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(quic))
        .await
        .unwrap();
    (
        send,
        Task(tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        })),
    )
}

async fn get3(client: &mut H3Client, path: &str, len_zero: bool) -> H3ClientStream {
    let mut request = req(&format!("https://localhost{path}")).map(|_| ());
    if len_zero {
        request
            .headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    }
    let mut stream = client.send_request(request).await.unwrap();
    stream.finish().await.unwrap();
    stream
}

async fn drain3(stream: &mut H3ClientStream, status: StatusCode) {
    timeout(Duration::from_secs(3), async {
        assert_eq!(stream.recv_response().await.unwrap().status(), status);
        while stream.recv_data().await.unwrap().is_some() {}
    })
    .await
    .unwrap();
}

fn close_mock_quic(mock: &MockOut) {
    mock.mock.quic_peer.lock().unwrap().as_ref().unwrap().close(
        quinn::VarInt::from_u64(h3::error::Code::H3_NO_ERROR.value()).unwrap(),
        b"",
    );
}

#[tokio::test]
async fn bodyless_h3_get_can_resume_upstream_quic_with_early_data() {
    let f = Fixture::new();
    let mut mock = f.mock_quic();
    let running = f.run(
        mock.addr,
        true,
        true,
        "h3_probe_timeout_ms=1000",
        "[routes.openai]\nprefer_h3=true\n",
    );
    let endpoint = f.h3_client();
    let (mut cli, _driver) = client3(&endpoint, running.public_addr).await;
    let stats = running
        .app
        .config
        .load()
        .metrics
        .iter()
        .find(|((p, _), _)| *p == Provider::Openai)
        .unwrap()
        .1
        .clone();
    for (attempt, len_zero) in [false, false, true].into_iter().enumerate() {
        let mut stream = get3(&mut cli, "/openai/v1/models", len_zero).await;
        drain3(&mut stream, StatusCode::OK).await;
        let seen = mock.seen().await;
        assert_eq!(seen.version, Version::HTTP_3);
        assert_eq!(seen.headers.contains_key("early-data"), attempt > 0);
        assert_eq!(
            seen.early_transport,
            attempt > 0,
            "must observe actual QUIC 0-RTT, even after handshake completion"
        );
        if attempt < 2 {
            // Give the locality-only QUIC client time to process the session
            // ticket and the subsequent connection close before the next dial.
            sleep(Duration::from_millis(35)).await;
            close_mock_quic(&mock);
            sleep(Duration::from_millis(70)).await;
        }
    }
    assert_eq!(stats.h3_early_accepted.load(Relaxed), 2);
    assert_eq!(stats.h3_fallbacks.load(Relaxed), 0);
    assert!(shutdown(&running.app).await);
}

#[tokio::test]
async fn h3_to_h1_bodyless_request_does_not_add_chunked_or_forward_framing_errors() {
    let f = Fixture::new();
    let mut mock = f.mock_tcp(false).await;
    let running = f.run(mock.addr, true, true, "", "");
    let endpoint = f.h3_client();
    let (mut cli, _driver) = client3(&endpoint, running.public_addr).await;
    for len_zero in [false, true] {
        let mut response = get3(&mut cli, "/openai/v1/models", len_zero).await;
        drain3(&mut response, StatusCode::OK).await;
        let seen = mock.seen().await;
        assert_eq!(seen.version, Version::HTTP_11);
        assert!(!seen.headers.contains_key(header::TRANSFER_ENCODING));
    }
    let bad = Request::builder()
        .uri("https://localhost/openai/v1/upload")
        .method(Method::POST)
        .header(header::AUTHORIZATION, "Bearer mock-byok")
        .header(header::CONTENT_LENGTH, "0")
        .body(())
        .unwrap();
    let mut stream = cli.send_request(bad).await.unwrap();
    stream
        .send_data(Bytes::from_static(b"not zero"))
        .await
        .unwrap();
    stream.finish().await.unwrap();
    drain3(&mut stream, StatusCode::BAD_REQUEST).await;
    assert!(mock.rx.try_recv().is_err());
    assert!(shutdown(&running.app).await);
}

#[tokio::test]
async fn established_h3_close_fails_only_that_request_and_redials_without_cooldown() {
    let f = Fixture::new();
    let mut mock = f.mock_quic();
    let running = f.run(
        mock.addr,
        false,
        false,
        "h3_probe_timeout_ms=1000\nupstream_0rtt=false",
        "[routes.openai]\nprefer_h3=true\n",
    );
    let (mut client, _driver) = client1(running.public_addr).await;
    body_eq(
        client.send_request(req("/openai/v1/models")).await.unwrap(),
        StatusCode::OK,
    )
    .await;
    let first = mock.seen().await;
    let pending = client.send_request(req("/openai/v1/wait"));
    tokio::pin!(pending);
    tokio::select! {
        waiting = mock.seen() => assert_eq!(waiting.id, first.id),
        _ = &mut pending => panic!("request returned before upstream close"),
    }
    close_mock_quic(&mock);
    body_eq(
        timeout(Duration::from_secs(3), pending)
            .await
            .unwrap()
            .unwrap(),
        StatusCode::BAD_GATEWAY,
    )
    .await;
    assert!(
        mock.rx.try_recv().is_err(),
        "no retry of an already-sent request"
    );
    body_eq(
        client.send_request(req("/openai/v1/models")).await.unwrap(),
        StatusCode::OK,
    )
    .await;
    let after = mock.seen().await;
    assert_eq!(after.version, Version::HTTP_3);
    assert_ne!(first.id, after.id);
    assert_eq!(
        running
            .app
            .config
            .load()
            .metrics
            .values()
            .map(|s| s.h3_fallbacks.load(Relaxed))
            .sum::<u64>(),
        0
    );
    assert!(shutdown(&running.app).await);
}

#[tokio::test]
async fn idle_h2_releases_connection_lease_but_active_sse_does_not_idle() {
    let f = Fixture::new();
    let mut mock = f.mock_tcp(true).await;
    let running = f.run_with_listen(
        mock.addr,
        false,
        false,
        "",
        "",
        "idle_connection_timeout_secs=1\nmax_connections=1",
    );
    let tcp = TcpStream::connect(running.public_addr).await.unwrap();
    let (mut client, drive) = client_h2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
        .await
        .unwrap();
    let driver = Task(tokio::spawn(async move {
        let _ = drive.await;
    }));
    let path = "http://localhost/openai/v1/stream";
    let mut response = client.send_request(req(path)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        "data: first\n\n"
    );
    mock.seen().await;
    sleep(Duration::from_millis(1250)).await;
    assert!(!driver.0.is_finished());
    assert_eq!(running.app.global.connections.load(Relaxed), 1);
    mock.mock.released.notify_one();
    assert_eq!(
        response
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        "data: last\n\n"
    );
    // HTTP/2 can carry END_STREAM in an empty final DATA frame.
    while let Some(frame) = response.body_mut().frame().await {
        let data = frame.unwrap().into_data().unwrap();
        assert!(data.is_empty());
    }
    timeout(Duration::from_secs(3), async {
        while running.app.global.connections.load(Relaxed) != 0 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("idle H2 must release the sole permit");
    let (mut next, _driver) = client1(running.public_addr).await;
    body_eq(
        next.send_request(req("/openai/v1/models")).await.unwrap(),
        StatusCode::OK,
    )
    .await;
    assert!(shutdown(&running.app).await);
}

#[tokio::test]
async fn custom_ip_dials_override_on_tcp_and_quic_without_changing_gemini_tls_identity() {
    let official = Provider::Gemini.host();
    let f = Fixture::with_sans(vec![official.to_owned()]);
    // No configured DNS server will answer the Gemini name in this fixture.
    // The mock certificate is trusted only for Gemini, never for the literal IP.
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        let h3 = version == Version::HTTP_3;
        let mut mock = if h3 {
            f.mock_quic()
        } else {
            f.mock_tcp(version == Version::HTTP_2).await
        };
        let origins = Provider::ALL.map(|p| Origin::official(p).with_mock_port(mock.addr.port()));
        let routes = format!(
            "[routes.gemini]\nprefer_h3={h3}\n[routes.gemini.resolve]\nipv4=['127.0.0.1']\n"
        );
        let running = f.run_origins(
            origins,
            false,
            false,
            "h3_probe_timeout_ms=1000",
            &routes,
            "",
        );
        let (mut send, _driver) = client1(running.public_addr).await;
        let req = Request::builder()
            .uri("/gemini/v1beta/models?alt=json")
            .header(header::HOST, "localhost")
            .header("x-goog-api-key", "mock-byok")
            .body(body::empty())
            .unwrap();
        let response = timeout(Duration::from_secs(3), send.send_request(req))
            .await
            .unwrap()
            .unwrap();
        body_eq(response, StatusCode::OK).await;
        let seen = mock.seen().await;
        assert_eq!(seen.path_query, "/v1beta/models?alt=json");
        assert_eq!(seen.headers["x-goog-api-key"], "mock-byok");
        assert_eq!(seen.version, version);
        if version != Version::HTTP_11 {
            assert_eq!(seen.authority.as_deref(), Some(official));
            assert!(!seen.headers.contains_key(header::HOST));
        }
        if h3 {
            let hello = mock
                .mock
                .quic_peer
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .handshake_data()
                .unwrap();
            let hello = hello
                .downcast::<quinn::crypto::rustls::HandshakeData>()
                .unwrap();
            assert_eq!(hello.server_name.as_deref(), Some(official));
        } else {
            if version == Version::HTTP_11 {
                assert_eq!(seen.headers[header::HOST], official);
            }
            assert_eq!(seen.tls_name.as_deref(), Some(official));
        }
        assert!(shutdown(&running.app).await);
    }
}

#[tokio::test]
async fn gemini_connect_uses_exact_ipv6_sni_and_does_not_attempt_quic() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, copy_bidirectional};

    let official = Provider::Gemini.host();
    let fixture = Fixture::with_sans(vec![official.to_owned()]);
    let mut upstream = fixture.mock_tcp(false).await;
    let destination = upstream.addr;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let task = Task(tokio::spawn(async move {
        let (mut downstream, _) = listener.accept().await.unwrap();
        let expected = format!(
            "CONNECT [::1]:{} HTTP/1.1\r\nHost: [::1]:{}\r\n\r\n",
            destination.port(),
            destination.port()
        );
        let mut buf = vec![0; expected.len()];
        downstream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, expected.as_bytes());
        let mut upstream = TcpStream::connect(destination).await.unwrap();
        downstream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .unwrap();
        let _ = copy_bidirectional(&mut downstream, &mut upstream).await;
    }));
    let routes = format!(
        r#"
[egress.tunnel]
mode = "v6_only"
local_v6 = "::"
allow_wildcard = true
http_proxy = "http://{proxy}"
[routes.gemini]
byok_egress = "tunnel"
prefer_h3 = true
[routes.gemini.resolve]
ipv6 = ["::1"]
"#
    );
    let origins = Provider::ALL.map(|p| Origin::official(p).with_mock_port(destination.port()));
    let running = fixture.run_origins(origins, false, false, "", &routes, "");
    let (mut client, _driver) = client1(running.public_addr).await;
    let request = Request::builder()
        .uri("/gemini/v1beta/models")
        .header(header::HOST, "localhost")
        .header("x-goog-api-key", "mock-byok")
        .body(body::empty())
        .unwrap();
    let res = timeout(Duration::from_secs(3), client.send_request(request))
        .await
        .unwrap()
        .unwrap();
    body_eq(res, StatusCode::OK).await;
    let seen = upstream.seen().await;
    assert_eq!(seen.headers[header::HOST], official);
    assert_eq!(seen.tls_name.as_deref(), Some(official));
    assert_eq!(seen.headers["x-goog-api-key"], "mock-byok");
    assert_eq!(
        running
            .app
            .config
            .load()
            .metrics
            .values()
            .map(|stats| stats.h3_fallbacks.load(Relaxed))
            .sum::<u64>(),
        0
    );
    assert!(shutdown(&running.app).await);
    drop(task);
}
