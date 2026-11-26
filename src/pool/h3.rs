use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use arc_swap::ArcSwapOption;
use bytes::Bytes;
use h3::{ConnectionState, error::Code};
use http::{Request, Response, Version, header};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use quinn::{ClientConfig, Connection, Endpoint, ZeroRttAccepted};
use tokio::{sync::Mutex, task::JoinHandle, time::timeout_at};

use super::Origin;
use crate::{
    config::Limits,
    metrics::Stats,
    net::{egress::Egress, tls},
    proxy::{
        body::{ClientRecv, Fault, H3Body, ProxyBody},
        headers,
    },
};

pub enum Outcome {
    Response(Response<ProxyBody>),
    Fallback(Request<ProxyBody>),
}

type H3Stream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type H3Send = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type Upload = Pin<Box<dyn Future<Output = Result<(), Fault>> + Send>>;

pub struct Pool {
    endpoints: [Option<Endpoint>; 2],
    config: [Option<ClientConfig>; 2],
    egress: Arc<Egress>,
    origin: Origin,
    header_limit: u32,
    probe: Duration,
    cooldown: Duration,
    epoch: Instant,
    blocked_until_ms: AtomicU64,
    session: ArcSwapOption<Session>,
    dial_lock: Mutex<()>,
    stats: Arc<Stats>,
}

struct Session {
    quic: Connection,
    sender: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver: JoinHandle<()>,
}
impl Session {
    fn is_live(&self) -> bool {
        !self.sender.is_closing() && self.quic.close_reason().is_none()
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.quic.close(
            quinn::VarInt::from_u64(Code::H3_NO_ERROR.value()).expect("valid H3 code"),
            b"",
        );
        self.driver.abort();
    }
}

enum Handshake {
    Confirmed(Connection),
    Early(Connection, ZeroRttAccepted),
}
enum EarlyFailure {
    Rejected,
    Probe,
    Fatal,
}

impl Pool {
    pub fn new(
        endpoints: [Option<Endpoint>; 2],
        config: [Option<ClientConfig>; 2],
        egress: Arc<Egress>,
        origin: Origin,
        header_limit: u32,
        limits: &Limits,
        stats: Arc<Stats>,
    ) -> Self {
        Self {
            endpoints,
            config,
            egress,
            origin,
            header_limit,
            probe: Duration::from_millis(limits.h3_probe_timeout_ms)
                .min(Duration::from_secs(limits.connect_timeout_secs)),
            cooldown: Duration::from_secs(limits.h3_cooldown_secs),
            epoch: Instant::now(),
            blocked_until_ms: AtomicU64::new(0),
            session: ArcSwapOption::empty(),
            dial_lock: Mutex::new(()),
            stats,
        }
    }

    fn cached(&self) -> Option<Arc<Session>> {
        let current = self.session.load();
        let session = current.as_ref()?;
        if session.is_live() {
            Some(session.clone())
        } else {
            self.invalidate(session);
            None
        }
    }
    fn invalidate(&self, session: &Arc<Session>) {
        // An older stream can fail after another task has installed a new
        // connection. Never clear the replacement, or cool down a live origin.
        self.session.compare_and_swap(Arc::as_ptr(session), None);
    }
    fn invalidate_if_closed(&self, session: &Arc<Session>) {
        if !session.is_live() {
            self.invalidate(session);
        }
    }
    fn ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }
    fn blocked(&self) -> bool {
        self.ms() < self.blocked_until_ms.load(Relaxed)
    }
    fn block(&self) {
        self.blocked_until_ms
            .store(self.ms() + self.cooldown.as_millis() as u64, Relaxed);
    }
    pub fn reap_idle(&self) {
        if let Ok(_lock) = self.dial_lock.try_lock()
            && self
                .session
                .load()
                .as_ref()
                .is_some_and(|s| Arc::strong_count(s) == 1)
        {
            self.session.store(None);
        }
    }

    async fn dial(&self, deadline: tokio::time::Instant, early: bool) -> io::Result<Handshake> {
        self.egress
            .race(
                &self.origin.dns,
                self.origin.port,
                deadline.saturating_duration_since(tokio::time::Instant::now()),
                |addr| async move {
                    let family = usize::from(addr.is_ipv6());
                    let endpoint = self.endpoints[family]
                        .as_ref()
                        .ok_or_else(|| io::Error::other("QUIC family disabled"))?;
                    let config = self.config[family]
                        .as_ref()
                        .ok_or_else(|| io::Error::other("QUIC TLS family disabled"))?;
                    let connecting = endpoint
                        .connect_with(
                            config.clone(),
                            addr,
                            self.origin.server_name.to_str().as_ref(),
                        )
                        .map_err(|_| io::Error::other("QUIC setup failed"))?;
                    let connecting = if early {
                        match connecting.into_0rtt() {
                            Ok((conn, accepted)) => return Ok(Handshake::Early(conn, accepted)),
                            Err(connecting) => connecting,
                        }
                    } else {
                        connecting
                    };
                    let connection = connecting
                        .await
                        .map_err(|_| io::Error::other("QUIC handshake failed"))?;
                    if !connection.handshake_data().is_some_and(tls::h3_alpn) {
                        return Err(io::Error::other("QUIC ALPN is not h3"));
                    }
                    Ok(Handshake::Confirmed(connection))
                },
            )
            .await
    }

    async fn start(&self, quic: Connection) -> Result<Arc<Session>, Fault> {
        let (mut driver, sender) = h3::client::builder()
            .send_grease(false)
            .max_field_section_size(self.header_limit.into())
            .build(h3_quinn::Connection::new(quic.clone()))
            .await
            .map_err(|_| Fault::Connect)?;
        let driver = tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });
        Ok(Arc::new(Session {
            quic,
            sender,
            driver,
        }))
    }

    async fn try_early(
        &self,
        mut head: Request<()>,
        quic: Connection,
        mut accepted: ZeroRttAccepted,
        deadline: tokio::time::Instant,
    ) -> Result<(Arc<Session>, H3Stream), EarlyFailure> {
        *head.version_mut() = Version::HTTP_3;
        head.headers_mut().remove(header::HOST);
        head.headers_mut()
            .insert("early-data", http::HeaderValue::from_static("1"));
        let mut tried_request = false;
        let early = async {
            let session = self.start(quic.clone()).await?;
            tried_request = true;
            let attempt = async {
                let mut stream = session
                    .sender
                    .clone()
                    .send_request(head)
                    .await
                    .map_err(|_| Fault::Response)?;
                stream.finish().await.map_err(|_| Fault::Response)?;
                Ok::<_, Fault>(stream)
            }
            .await;
            // Keep the QUIC session alive until we know whether the early-data
            // epoch was accepted; dropping it here would make a clean rejection
            // look like an ambiguous communication failure.
            Ok::<_, Fault>((session, attempt))
        };
        let ready = |sent: Result<(Arc<Session>, Result<H3Stream, Fault>), Fault>| {
            let (s, attempt) = sent.map_err(|_| EarlyFailure::Probe)?;
            Ok((s, attempt.map_err(|_| EarlyFailure::Fatal)?))
        };
        let result = timeout_at(deadline, async {
            tokio::pin!(early);
            let rejected = || {
                if quic.close_reason().is_none() {
                    EarlyFailure::Rejected
                } else {
                    EarlyFailure::Fatal
                }
            };
            tokio::select! {
                biased;
                a = &mut accepted => {
                    if !a { return Err(rejected()); }
                    if !quic.handshake_data().is_some_and(tls::h3_alpn) { return Err(EarlyFailure::Fatal); }
                    ready(early.await)
                }
                sent = &mut early => {
                    if !accepted.await { return Err(rejected()); }
                    if !quic.handshake_data().is_some_and(tls::h3_alpn) { return Err(EarlyFailure::Fatal); }
                    ready(sent)
                }
            }
        })
        .await;
        match result {
            Ok(Ok(ok)) => Ok(ok),
            Ok(Err(err)) => {
                quic.close(0u32.into(), b"");
                Err(err)
            }
            Err(_) => {
                quic.close(0u32.into(), b"");
                Err(if tried_request {
                    EarlyFailure::Fatal
                } else {
                    EarlyFailure::Probe
                })
            }
        }
    }

    pub async fn request(
        &self,
        req: Request<ProxyBody>,
        can_early: bool,
    ) -> Result<Outcome, Fault> {
        if let Some(session) = self.cached() {
            return self.forward(session, req).await;
        }
        if self.blocked() {
            return Ok(Outcome::Fallback(req));
        }
        let deadline = tokio::time::Instant::now() + self.probe;
        let Ok(lock) = timeout_at(deadline, self.dial_lock.lock()).await else {
            return Ok(Outcome::Fallback(req));
        };
        if let Some(session) = self.cached() {
            drop(lock);
            return self.forward(session, req).await;
        }
        if self.blocked() {
            return Ok(Outcome::Fallback(req));
        }
        let mut budget_end = deadline;
        let quic = match self
            .dial(deadline, can_early && req.body().is_end_stream())
            .await
        {
            Ok(Handshake::Confirmed(quic)) => quic,
            Ok(Handshake::Early(conn, accepted)) => {
                let mut head = Request::new(());
                *head.method_mut() = req.method().clone();
                *head.uri_mut() = req.uri().clone();
                *head.headers_mut() = req.headers().clone();
                match self.try_early(head, conn, accepted, deadline).await {
                    Ok((session, stream)) => {
                        self.stats.h3_early_accepted.fetch_add(1, Relaxed);
                        self.session.store(Some(session.clone()));
                        drop(lock);
                        let (_, recv) = stream.split();
                        return self.receive(session, recv, None).await;
                    }
                    Err(EarlyFailure::Rejected) => {
                        self.stats.h3_early_rejected.fetch_add(1, Relaxed);
                        // H3 critical streams from the failed early-data epoch cannot
                        // safely be reused. Redial and send once under 1-RTT protection.
                        budget_end = tokio::time::Instant::now() + self.probe;
                        match self.dial(budget_end, false).await {
                            Ok(Handshake::Confirmed(quic)) => quic,
                            _ => {
                                self.block();
                                return Ok(Outcome::Fallback(req));
                            }
                        }
                    }
                    Err(EarlyFailure::Probe) => {
                        self.block();
                        return Ok(Outcome::Fallback(req));
                    }
                    Err(EarlyFailure::Fatal) => return Err(Fault::Connect),
                }
            }
            Err(_) => {
                self.block();
                return Ok(Outcome::Fallback(req));
            }
        };
        let Ok(Ok(session)) = timeout_at(budget_end, self.start(quic)).await else {
            self.block();
            return Ok(Outcome::Fallback(req));
        };
        self.session.store(Some(session.clone()));
        drop(lock);
        self.forward(session, req).await
    }

    async fn forward(
        &self,
        session: Arc<Session>,
        req: Request<ProxyBody>,
    ) -> Result<Outcome, Fault> {
        if !session.is_live() {
            self.invalidate(&session);
            return Ok(Outcome::Fallback(req));
        }
        let (mut head, body) = req.into_parts();
        head.version = Version::HTTP_3;
        head.headers.remove(header::HOST);
        // After the send attempt, never fall back: transmission may already
        // have created a billable upstream inference.
        let stream = match session
            .sender
            .clone()
            .send_request(Request::from_parts(head, ()))
            .await
        {
            Ok(stream) => stream,
            Err(_) => {
                self.invalidate_if_closed(&session);
                return Err(Fault::Response);
            }
        };
        let (send, recv) = stream.split();
        let mut send = SendGuard(Some(send));
        let upload = if body.is_end_stream() {
            if let Err(fault) = send.finish().await {
                self.invalidate_if_closed(&session);
                return Err(fault);
            }
            None
        } else {
            let future: Upload = Box::pin(send.upload(body));
            Some(future)
        };
        self.receive(session, recv, upload).await
    }

    async fn receive(
        &self,
        session: Arc<Session>,
        recv: ClientRecv,
        mut upload: Option<Upload>,
    ) -> Result<Outcome, Fault> {
        let mut recv = RecvGuard(Some(recv));
        let result = {
            let read_headers = async {
                // Ignore interim responses without waiting for the upload to finish.
                for _ in 0..8 {
                    let resp = recv
                        .0
                        .as_mut()
                        .ok_or(Fault::Response)?
                        .recv_response()
                        .await
                        .map_err(|_| Fault::Response)?;
                    if !resp.status().is_informational() {
                        return Ok(resp);
                    }
                }
                Err(Fault::Response)
            };
            tokio::pin!(read_headers);
            if let Some(pump) = upload.as_mut() {
                tokio::select! {
                    r = &mut read_headers => r,
                    p = pump => {
                        upload = None;
                        match p { Ok(()) => read_headers.await, Err(fault) => Err(fault) }
                    }
                }
            } else {
                read_headers.await
            }
        };
        let r = match result {
            Ok(r) => r,
            Err(err) => {
                self.invalidate_if_closed(&session);
                return Err(err);
            }
        };
        let remaining = headers::content_length(r.headers()).map_err(|_| Fault::Framing)?;
        let recv = recv.0.take().ok_or(Fault::Response)?;
        Ok(Outcome::Response(r.map(|_| {
            Duplex {
                upload,
                recv: H3Body::new(recv, remaining),
                _session: session,
            }
            .boxed_unsync()
        })))
    }
}

struct SendGuard(Option<H3Send>);
impl SendGuard {
    async fn finish(&mut self) -> Result<(), Fault> {
        let stream = self.0.as_mut().ok_or(Fault::Response)?;
        stream.finish().await.map_err(|_| Fault::Response)?;
        self.0.take();
        Ok(())
    }
    async fn upload(mut self, mut body: ProxyBody) -> Result<(), Fault> {
        let stream = self.0.as_mut().ok_or(Fault::Response)?;
        while let Some(frame) = body.frame().await {
            match frame?.into_data() {
                Ok(data) if !data.is_empty() => {
                    stream.send_data(data).await.map_err(|_| Fault::Response)?
                }
                Err(other) => {
                    if let Ok(t) = other.into_trailers() {
                        stream.send_trailers(t).await.map_err(|_| Fault::Response)?;
                    }
                }
                _ => {}
            }
        }
        self.finish().await
    }
}
impl Drop for SendGuard {
    fn drop(&mut self) {
        if let Some(stream) = &mut self.0 {
            stream.stop_stream(Code::H3_REQUEST_CANCELLED);
        }
    }
}
struct RecvGuard(Option<ClientRecv>);
impl Drop for RecvGuard {
    fn drop(&mut self) {
        if let Some(stream) = &mut self.0 {
            stream.stop_sending(Code::H3_REQUEST_CANCELLED);
        }
    }
}

struct Duplex {
    upload: Option<Upload>,
    recv: H3Body<ClientRecv>,
    _session: Arc<Session>,
}
impl Body for Duplex {
    type Data = Bytes;
    type Error = Fault;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Fault>>> {
        let s = self.get_mut();
        if let Some(upload) = &mut s.upload
            && let Poll::Ready(r) = upload.as_mut().poll(cx)
        {
            s.upload = None;
            if let Err(err) = r {
                return Poll::Ready(Some(Err(err)));
            }
        }
        Pin::new(&mut s.recv).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.recv.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.recv.size_hint()
    }
}
