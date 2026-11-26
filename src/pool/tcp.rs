use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use http::Uri;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::{
    client::legacy::{
        Client,
        connect::{Connected, Connection},
    },
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};
use tower_service::Service;

use super::Origin;
use crate::{
    net::egress::Egress,
    proxy::body::{Fault, ProxyBody},
};

pub type ClientPool = Client<Connector, ProxyBody>;

pub fn client(
    egress: Arc<Egress>,
    tls: [Option<Arc<rustls::ClientConfig>>; 2],
    origin: Origin,
    timeout: Duration,
    max_headers: u32,
    websocket: bool,
) -> ClientPool {
    Client::builder(TokioExecutor::new())
        .pool_timer(TokioTimer::new())
        .timer(TokioTimer::new())
        .pool_idle_timeout(Duration::from_secs(50))
        .pool_max_idle_per_host(if websocket { 0 } else { 2 })
        .retry_canceled_requests(false)
        .http1_max_buf_size(max_headers as usize)
        .http1_max_headers(128)
        .http2_max_header_list_size(max_headers)
        .http2_initial_stream_window_size(128 * 1024)
        .http2_initial_connection_window_size(1024 * 1024)
        .http2_max_send_buf_size(128 * 1024)
        .http2_keep_alive_interval(Duration::from_secs(25))
        .http2_keep_alive_timeout(Duration::from_secs(10))
        .http2_keep_alive_while_idle(true)
        .set_host(false)
        .build(Connector {
            egress,
            tls: tls.map(|t| t.map(TlsConnector::from)),
            origin,
            timeout,
        })
}

#[derive(Clone)]
pub struct Connector {
    egress: Arc<Egress>,
    tls: [Option<TlsConnector>; 2],
    origin: Origin,
    timeout: Duration,
}

impl Service<Uri> for Connector {
    type Response = UpstreamIo;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<UpstreamIo>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let connector = self.clone();
        Box::pin(async move {
            if uri.scheme_str() != Some("https")
                || uri.authority() != Some(&connector.origin.authority)
            {
                return Err(io::Error::other("unexpected upstream authority"));
            }
            let shared = &connector;
            let socket = connector
                .egress
                .race(
                    &connector.origin.dns,
                    connector.origin.port,
                    connector.timeout,
                    |addr| async move {
                        let tcp = shared.egress.tcp(addr).await?;
                        let tls = shared.tls[usize::from(addr.is_ipv6())]
                            .as_ref()
                            .ok_or_else(|| io::Error::other("TLS family disabled"))?;
                        tls.connect(shared.origin.server_name.clone(), tcp).await
                    },
                )
                .await?;
            Ok(UpstreamIo(TokioIo::new(socket)))
        })
    }
}

pub struct UpstreamIo(TokioIo<TlsStream<TcpStream>>);
impl Connection for UpstreamIo {
    fn connected(&self) -> Connected {
        let result = Connected::new();
        if self.0.inner().get_ref().1.alpn_protocol() == Some(b"h2") {
            result.negotiated_h2()
        } else {
            result
        }
    }
}
impl Read for UpstreamIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}
impl Write for UpstreamIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

pub(super) fn classify(err: hyper_util::client::legacy::Error) -> Fault {
    let connecting = err.is_connect();
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&err);
    while let Some(e) = source {
        if let Some(fault) = e.downcast_ref::<Fault>() {
            return *fault;
        }
        if connecting
            && e.downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::TimedOut)
        {
            return Fault::ConnectDeadline;
        }
        source = e.source();
    }
    if connecting {
        Fault::Connect
    } else {
        Fault::Response
    }
}
