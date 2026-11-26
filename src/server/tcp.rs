use std::{
    convert::Infallible,
    io,
    pin::Pin,
    sync::{Arc, atomic::Ordering::Relaxed},
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::{Request, StatusCode, Version};
use http_body_util::BodyExt;
use hyper::{
    body::{Body, Frame, Incoming, SizeHint},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto,
};
use socket2::{SockRef, TcpKeepalive};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{Notify, watch},
    time::{Instant, sleep, sleep_until, timeout},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use zeroize::Zeroizing;

use super::{App, ConnectionLease};
use crate::{
    config::Listen,
    proxy::{
        body::{self, Fault, ProxyBody},
        handler::{self, ContextInfo},
    },
};

pub async fn accept(listener: TcpListener, app: Arc<App>) {
    let limits = app.config.load().listen.clone();
    while !app.stop.is_cancelled() {
        let result = tokio::select! { biased; _ = app.stop.cancelled() => break, result = listener.accept() => result };
        let Ok((tcp, _)) = result else {
            // Bounded backoff for EMFILE etc.; no per-connection logging.
            tokio::select! { _ = app.stop.cancelled() => break, _ = sleep(Duration::from_millis(50)) => {} }
            continue;
        };
        let Some(lease) = app.connection() else {
            app.global.rejected_connections.fetch_add(1, Relaxed);
            continue;
        };
        if tcp.set_nodelay(true).is_err()
            || SockRef::from(&tcp)
                .set_tcp_keepalive(&TcpKeepalive::new().with_time(Duration::from_secs(60)))
                .is_err()
        {
            continue;
        }
        app.tasks
            .spawn(connect(tcp, app.clone(), lease, limits.clone()));
    }
}

#[derive(Clone, Copy)]
enum Protocol {
    Auto,
    H1,
    H2,
}

async fn connect(tcp: TcpStream, app: Arc<App>, lease: ConnectionLease, limits: Listen) {
    let tls = app.config.load().tls.as_ref().map(|p| p.tcp.clone());
    let handshake = Duration::from_secs(limits.header_timeout_secs);
    if let Some(tls) = tls {
        let acceptor = TlsAcceptor::from(tls);
        let result = tokio::select! {
            biased; _ = app.stop.cancelled() => return,
            result = timeout(handshake, acceptor.accept(tcp)) => result,
        };
        let Ok(Ok(mut stream)) = result else {
            return;
        };
        let proto = if stream.get_ref().1.alpn_protocol() == Some(b"h2") {
            Protocol::H2
        } else {
            Protocol::H1
        };
        // tokio-rustls waits for the full handshake. Rustls buffers accepted
        // early bytes separately; optionally prepend those <=16 KiB bytes.
        // No TCP request is dispatched before the handshake succeeds.
        let mut queued = Zeroizing::new(Vec::new());
        if let Some(mut early) = stream.get_mut().1.early_data()
            && io::Read::read_to_end(&mut early, &mut queued).is_err()
        {
            return;
        }
        serve(
            AfterHandshake {
                stream,
                queued,
                read: 0,
            },
            app,
            lease,
            limits,
            proto,
        )
        .await;
    } else {
        serve(tcp, app, lease, limits, Protocol::Auto).await;
    }
}

async fn serve<I: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    io: I,
    app: Arc<App>,
    lease: ConnectionLease,
    limits: Listen,
    proto: Protocol,
) {
    let lease = Arc::new(lease);
    let ctx = ContextInfo {
        secure: !matches!(proto, Protocol::Auto),
        early: false,
        #[cfg(feature = "websocket")]
        connection: Some(lease.clone()),
    };
    let first = Arc::new(Notify::new());
    let activity = (!matches!(proto, Protocol::H1)).then(|| Arc::new(H2Activity::new()));
    let svc = service_fn({
        let app = app.clone();
        let first = first.clone();
        let activity = activity.clone();
        move |r: Request<Incoming>| {
            first.notify_one();
            // Lease the stream before Hyper spawns/polls its service future.
            let h2 = r.version() == Version::HTTP_2;
            let stream = activity.as_ref().filter(|_| h2).and_then(H2Activity::start);
            let app = app.clone();
            let ctx = ctx.clone();
            async move {
                let response = if h2 && stream.is_none() {
                    body::text(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "HTTP/2 connection is closing\n",
                    )
                } else {
                    handler::handle(
                        app,
                        r.map(|b| b.map_err(|_| Fault::Downstream).boxed_unsync()),
                        ctx,
                    )
                    .await
                };
                Ok::<_, Infallible>(response.map(|body| {
                    match stream {
                        Some(stream) if !body.is_end_stream() => ActiveBody {
                            inner: body,
                            _stream: stream,
                        }
                        .boxed_unsync(),
                        _ => body,
                    }
                }))
            }
        }
    });
    let io = TokioIo::new(io);
    let header_timeout = Duration::from_secs(limits.header_timeout_secs);
    let idle_timeout = Duration::from_secs(limits.idle_connection_timeout_secs);
    macro_rules! drive {
        ($conn:expr) => {{
            let conn = $conn;
            tokio::pin!(conn);
            tokio::select! {
                biased;
                _ = app.stop.cancelled() => { conn.as_mut().graceful_shutdown(); let _ = conn.await; }
                _ = &mut conn => {}
                r = timeout(header_timeout, first.notified()) => {
                    if r.is_ok() {
                        tokio::select! {
                            biased;
                            _ = app.stop.cancelled() => { conn.as_mut().graceful_shutdown(); let _ = conn.await; }
                            _ = &mut conn => {}
                            _ = wait_h2_idle(activity.as_deref(), idle_timeout) => {
                                conn.as_mut().graceful_shutdown();
                                // An idle peer can ignore the GOAWAY ping. Do
                                // not let it hold the connection permit forever.
                                let _ = timeout(header_timeout.min(Duration::from_secs(5)), conn).await;
                            }
                        }
                    }
                }
            }
        }};
    }
    match proto {
        Protocol::H1 => {
            let mut builder = http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .half_close(false)
                .max_headers(128)
                .max_buf_size(limits.max_header_bytes as usize)
                .header_read_timeout(header_timeout);
            let conn = builder.serve_connection(io, svc);
            #[cfg(feature = "websocket")]
            let conn = conn.with_upgrades();
            drive!(conn);
        }
        Protocol::H2 | Protocol::Auto => {
            let mut builder = auto::Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .half_close(false)
                .max_headers(128)
                .max_buf_size(limits.max_header_bytes as usize)
                .header_read_timeout(header_timeout);
            builder
                .http2()
                .timer(TokioTimer::new())
                .max_concurrent_streams(limits.streams_per_connection)
                .max_header_list_size(limits.max_header_bytes)
                .initial_stream_window_size(128 * 1024)
                .initial_connection_window_size(1024 * 1024)
                .max_send_buf_size(128 * 1024)
                .keep_alive_interval(Duration::from_secs(30))
                .keep_alive_timeout(Duration::from_secs(10));
            if matches!(proto, Protocol::H2) {
                let builder = builder.http2_only();
                drive!(builder.serve_connection(io, svc));
            } else {
                #[cfg(feature = "websocket")]
                drive!(builder.serve_connection_with_upgrades(io, svc));
                #[cfg(not(feature = "websocket"))]
                drive!(builder.serve_connection(io, svc));
            }
        }
    }
    drop(lease);
}

#[derive(Clone, Copy)]
struct H2State {
    active: usize,
    idle_since: Option<Instant>,
    closing: bool,
}

struct H2Activity {
    state: watch::Sender<H2State>,
}
impl H2Activity {
    fn new() -> Self {
        Self {
            state: watch::Sender::new(H2State {
                active: 0,
                idle_since: None,
                closing: false,
            }),
        }
    }
    fn start(self: &Arc<Self>) -> Option<H2Stream> {
        let mut admitted = false;
        self.state.send_if_modified(|s| {
            if s.closing {
                return false;
            }
            admitted = true;
            s.active += 1;
            // Only an idle-to-active transition needs to wake the driver.
            s.idle_since.take().is_some()
        });
        admitted.then(|| H2Stream(self.clone()))
    }
}

struct H2Stream(Arc<H2Activity>);
impl Drop for H2Stream {
    fn drop(&mut self) {
        self.0.state.send_if_modified(|s| {
            s.active -= 1;
            if s.active == 0 {
                s.idle_since = Some(Instant::now());
                true
            } else {
                false
            }
        });
    }
}

async fn wait_h2_idle(activity: Option<&H2Activity>, idle: Duration) {
    let Some(activity) = activity else {
        return std::future::pending().await;
    };
    let mut state = activity.state.subscribe();
    loop {
        let since = state.borrow_and_update().idle_since;
        if let Some(since) = since {
            tokio::select! {
                _ = state.changed() => {}
                _ = sleep_until(since + idle) => {
                    // Check again under the same guard as stream admission.
                    if activity.state.send_if_modified(|s| {
                        if s.idle_since != Some(since) || s.active != 0 { return false; }
                        s.closing = true;
                        true
                    }) { return; }
                }
            }
        } else {
            let _ = state.changed().await;
        }
    }
}

struct ActiveBody {
    inner: ProxyBody,
    _stream: H2Stream,
}
impl Body for ActiveBody {
    type Data = Bytes;
    type Error = Fault;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Fault>>> {
        Pin::new(&mut self.get_mut().inner).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

struct AfterHandshake {
    stream: TlsStream<TcpStream>,
    queued: Zeroizing<Vec<u8>>,
    read: usize,
}
impl AsyncRead for AfterHandshake {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let s = self.get_mut();
        if s.read < s.queued.len() {
            let n = buf.remaining().min(s.queued.len() - s.read);
            buf.put_slice(&s.queued[s.read..s.read + n]);
            s.queued[s.read..s.read + n].fill(0);
            s.read += n;
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut s.stream).poll_read(cx, buf)
        }
    }
}
impl AsyncWrite for AfterHandshake {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}
