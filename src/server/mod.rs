mod h3;
mod manage;
mod tcp;

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use http::HeaderValue;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore},
    time::timeout,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    ConfigError, Result,
    config::Snapshot,
    metrics::{ConnectionCount, Global},
};

pub struct App {
    pub config: ArcSwap<Snapshot>,
    pub global: Arc<Global>,
    pub requests: Arc<Semaphore>,
    connections: Arc<Semaphore>,
    pub stop: CancellationToken,
    pub tasks: TaskTracker,
    pub alt_svc: Option<HeaderValue>,
}

pub struct Running {
    pub app: Arc<App>,
    pub public_addr: SocketAddr,
    pub management_addr: SocketAddr,
}

pub struct ConnectionLease {
    _permit: OwnedSemaphorePermit,
    _count: ConnectionCount,
}
impl App {
    fn connection(&self) -> Option<ConnectionLease> {
        let permit = self.connections.clone().try_acquire_owned().ok()?;
        Some(ConnectionLease {
            _permit: permit,
            _count: ConnectionCount::new(self.global.clone()),
        })
    }
}

pub fn start(config: Arc<Snapshot>) -> Result<Running> {
    let public = bind_tcp(config.listen.bind).map_err(|e| {
        ConfigError(format!(
            "cannot bind public TCP {}: {e}",
            config.listen.bind
        ))
    })?;
    let management = bind_tcp(config.listen.management).map_err(|e| {
        ConfigError(format!(
            "cannot bind management TCP {}: {e}",
            config.listen.management
        ))
    })?;
    let public_addr = public
        .local_addr()
        .map_err(|_| "cannot obtain public socket address")?;
    let management_addr = management
        .local_addr()
        .map_err(|_| "cannot obtain management socket address")?;
    let mut alt_svc = None;
    let mut endpoint = None;
    if config.listen.h3 {
        let quic = config
            .tls
            .as_ref()
            .and_then(|t| t.quic.as_ref())
            .ok_or("missing QUIC listener configuration")?;
        let udp = bind_udp(public_addr)
            .map_err(|e| ConfigError(format!("cannot bind public QUIC {public_addr}: {e}")))?;
        endpoint = Some(
            quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some((**quic).clone()),
                udp,
                Arc::new(quinn::TokioRuntime),
            )
            .map_err(|e| ConfigError(format!("cannot start QUIC endpoint: {e}")))?,
        );
        alt_svc = Some(
            HeaderValue::from_str(&format!("h3=\":{}\"; ma=86400", public_addr.port()))
                .map_err(|_| "cannot encode Alt-Svc")?,
        );
    }
    let app = Arc::new(App {
        requests: Arc::new(Semaphore::new(config.listen.max_in_flight)),
        connections: Arc::new(Semaphore::new(config.listen.max_connections)),
        config: ArcSwap::from(config),
        global: Arc::new(Global::default()),
        stop: CancellationToken::new(),
        tasks: TaskTracker::new(),
        alt_svc,
    });
    app.tasks.spawn(tcp::accept(public, app.clone()));
    app.tasks.spawn(manage::serve(management, app.clone()));
    if let Some(endpoint) = endpoint {
        app.tasks.spawn(h3::accept(endpoint, app.clone()));
    }
    Ok(Running {
        app,
        public_addr,
        management_addr,
    })
}

pub async fn shutdown(app: &App) -> bool {
    let duration = Duration::from_secs(app.config.load().limits.shutdown_drain_timeout_secs);
    app.stop.cancel();
    app.tasks.close();
    timeout(duration, app.tasks.wait()).await.is_ok()
}

fn bind_socket(addr: SocketAddr, udp: bool) -> io::Result<Socket> {
    let sock = Socket::new(
        Domain::for_address(addr),
        if udp { Type::DGRAM } else { Type::STREAM },
        Some(if udp { Protocol::UDP } else { Protocol::TCP }),
    )?;
    if addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }
    if !udp {
        sock.set_reuse_address(true)?;
    }
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    Ok(sock)
}
fn bind_tcp(addr: SocketAddr) -> io::Result<TcpListener> {
    let s = bind_socket(addr, false)?;
    s.listen(512)?;
    TcpListener::from_std(s.into())
}
fn bind_udp(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    Ok(bind_socket(addr, true)?.into())
}

#[cfg(test)]
mod tests;
