use std::{
    pin::Pin,
    sync::{Arc, atomic::Ordering::Relaxed},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::{HeaderValue, Method, Request, Response, StatusCode, header};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use tokio::sync::OwnedSemaphorePermit;

use super::{
    body::{self, Fault, ProxyBody},
    headers, router, timing,
};
use crate::{metrics::Global, pool::Pool, server::App};

#[derive(Clone, Default)]
pub struct ContextInfo {
    pub secure: bool,
    pub early: bool,
    #[cfg(feature = "websocket")]
    pub connection: Option<Arc<crate::server::ConnectionLease>>,
}

pub async fn handle(
    app: Arc<App>,
    req: Request<ProxyBody>,
    ctx: ContextInfo,
) -> Response<ProxyBody> {
    let version = req.version();
    let secure = ctx.secure;
    let mut response = proxy(&app, req, ctx).await;
    // Hyper's H1 encoder accepts only versions 1.0/1.1 (never a raw H3
    // response version). The downstream transport owns wire framing.
    *response.version_mut() = version;
    advertise(&app, secure, response.headers_mut());
    response
}

async fn proxy(app: &App, mut req: Request<ProxyBody>, ctx: ContextInfo) -> Response<ProxyBody> {
    let Ok(permit) = app.requests.clone().try_acquire_owned() else {
        app.global.rejected_requests.fetch_add(1, Relaxed);
        return body::text(
            StatusCode::SERVICE_UNAVAILABLE,
            "too many active requests\n",
        );
    };
    let mut work = Work::new(permit, app.global.clone());
    let snapshot = app.config.load();
    let max = snapshot.listen.max_header_bytes as usize;
    if headers::request_size(req.method(), req.uri(), req.headers()) > max {
        return body::text(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "headers exceed gateway limit\n",
        );
    }
    let websocket = headers::has_token(req.headers(), header::UPGRADE, "websocket");
    let any_upgrade = req.headers().contains_key(header::UPGRADE);
    let client_early =
        match headers::single(req.headers(), http::HeaderName::from_static("early-data")) {
            Ok(None) => false,
            Ok(Some(v)) if v.as_bytes() == b"1" => true,
            _ => return body::text(StatusCode::BAD_REQUEST, "invalid early-data indication\n"),
        };
    let early = ctx.early || client_early;
    let safe = replay_safe(req.method()) && !any_upgrade;
    if early && !safe && !snapshot.limits.allow_0rtt_non_idempotent {
        return body::text(StatusCode::TOO_EARLY, "retry after the TLS handshake\n");
    }
    if any_upgrade && (!websocket || !snapshot.limits.websocket || !cfg!(feature = "websocket")) {
        return body::text(
            StatusCode::UPGRADE_REQUIRED,
            "only HTTP/1.1 WebSocket upgrade is supported\n",
        );
    }
    #[cfg(feature = "websocket")]
    let ws = if websocket {
        match super::websocket::validate(&req) {
            Ok(ws) => Some(ws),
            Err(r) => return *r,
        }
    } else {
        None
    };
    let input_length = headers::content_length(req.headers());
    if input_length.is_err()
        || (input_length.ok().flatten().is_some()
            && req.headers().contains_key(header::TRANSFER_ENCODING))
    {
        return body::text(StatusCode::BAD_REQUEST, "ambiguous body framing\n");
    }
    if headers::remove_hop(req.headers_mut()).is_err() {
        return body::text(StatusCode::BAD_REQUEST, "invalid connection header\n");
    }
    headers::remove_forwarding(req.headers_mut());
    if early {
        req.headers_mut()
            .insert("early-data", HeaderValue::from_static("1"));
    }
    let head = req.method() == Method::HEAD;
    let (mut parts, upload) = req.into_parts();
    let routed = match router::route(
        &snapshot,
        &parts.method,
        parts.version,
        &parts.uri,
        &mut parts.headers,
        websocket,
    )
    .await
    {
        Ok(routed) => routed,
        Err(router::Rejection(status, msg)) => {
            app.global.rejected_requests.fetch_add(1, Relaxed);
            return body::text(status, msg);
        }
    };
    let header_timeout = Duration::from_secs(snapshot.limits.response_header_timeout_secs);
    let idle = Duration::from_secs(snapshot.limits.stream_idle_timeout_secs);
    let early_upstream = snapshot.limits.upstream_0rtt && safe;
    drop(snapshot);
    work.begin(routed.pool.clone());
    parts.uri = routed.target;
    #[cfg(feature = "websocket")]
    let upgrade = ws.map(|ws| super::websocket::take(ws, &mut parts));
    parts.extensions.clear();
    let (upload, upload_clock) = timing::monitor(body::timed(upload, idle, max));
    let upstream = Request::from_parts(parts, upload);
    let sent = Instant::now();
    #[cfg(feature = "websocket")]
    if let Some(upgrade) = upgrade {
        let mut upstream = upstream;
        upgrade.set_headers(&mut upstream);
        let res = timing::response(
            upload_clock,
            header_timeout,
            idle,
            routed.pool.upgrade(upstream),
        )
        .await;
        return match res {
            Ok(response) if response.status() == StatusCode::SWITCHING_PROTOCOLS => {
                match upgrade.tunnel(response, ctx.connection, max) {
                    Ok((response, tunnel)) => {
                        work.ttfb(sent);
                        work.complete = true;
                        // The tunnel (not just its 101 headers) owns the limit permits.
                        app.tasks.spawn(async move {
                            let _work = work;
                            tunnel.run().await;
                        });
                        response
                    }
                    Err(fault) => fail(work, fault),
                }
            }
            Ok(response) => finish(
                response.map(|b| b.map_err(|_| Fault::Response).boxed_unsync()),
                work,
                sent,
                idle,
                max,
                head,
            ),
            Err(fault) => fail(work, fault),
        };
    }
    match timing::response(
        upload_clock,
        header_timeout,
        idle,
        routed.pool.request(upstream, early_upstream),
    )
    .await
    {
        Ok(response) => finish(response, work, sent, idle, max, head),
        Err(fault) => fail(work, fault),
    }
}

pub fn replay_safe(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn fail(mut work: Work, fault: Fault) -> Response<ProxyBody> {
    work.error();
    work.complete = true;
    match fault {
        Fault::ConnectDeadline | Fault::HeaderDeadline | Fault::StreamIdle => {
            body::text(StatusCode::GATEWAY_TIMEOUT, "upstream deadline exceeded\n")
        }
        _ => body::text(StatusCode::BAD_GATEWAY, "upstream request failed\n"),
    }
}

fn advertise(app: &App, secure: bool, headers: &mut http::HeaderMap) {
    headers.remove(header::ALT_SVC);
    if secure && let Some(value) = &app.alt_svc {
        headers.insert(header::ALT_SVC, value.clone());
    }
}

fn finish(
    mut response: Response<ProxyBody>,
    mut work: Work,
    sent: Instant,
    idle: Duration,
    max: usize,
    head: bool,
) -> Response<ProxyBody> {
    work.ttfb(sent);
    if response.status().is_informational()
        || headers::remove_hop(response.headers_mut()).is_err()
        || headers::header_size(response.headers()) > max
        || headers::content_length(response.headers()).is_err()
    {
        return fail(work, Fault::Framing);
    }
    if response.status().is_client_error() || response.status().is_server_error() {
        work.error();
    }
    let sse = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/event-stream"))
        });
    if sse
        || (!response.headers().contains_key(header::CONTENT_LENGTH)
            && response.body().size_hint().exact().is_none())
    {
        response
            .headers_mut()
            .insert("x-accel-buffering", HeaderValue::from_static("no"));
    }
    let no_body = head
        || matches!(
            response.status(),
            StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED | StatusCode::RESET_CONTENT
        );
    if response.status() == StatusCode::NO_CONTENT {
        response.headers_mut().remove(header::CONTENT_LENGTH);
    }
    response.map(|b| {
        if no_body || b.is_end_stream() {
            work.complete = true;
            drop(work);
            body::empty()
        } else {
            Tracked {
                inner: body::timed(b, idle, max),
                work,
            }
            .boxed_unsync()
        }
    })
}

struct Work {
    _permit: OwnedSemaphorePermit,
    global: Arc<Global>,
    pool: Option<Arc<Pool>>,
    complete: bool,
    error: bool,
}
impl Work {
    fn new(permit: OwnedSemaphorePermit, global: Arc<Global>) -> Self {
        global.in_flight.fetch_add(1, Relaxed);
        Self {
            _permit: permit,
            global,
            pool: None,
            complete: false,
            error: false,
        }
    }
    fn begin(&mut self, pool: Arc<Pool>) {
        pool.stats.requests.fetch_add(1, Relaxed);
        self.pool = Some(pool);
    }
    fn ttfb(&self, start: Instant) {
        if let Some(p) = &self.pool {
            p.stats.ttfb(start.elapsed());
        }
    }
    fn error(&mut self) {
        if !self.error {
            self.error = true;
            if let Some(p) = &self.pool {
                p.stats.errors.fetch_add(1, Relaxed);
            }
        }
    }
}
impl Drop for Work {
    fn drop(&mut self) {
        self.global.in_flight.fetch_sub(1, Relaxed);
        if !self.complete
            && let Some(p) = &self.pool
        {
            p.stats.cancelled.fetch_add(1, Relaxed);
        }
    }
}
struct Tracked {
    inner: ProxyBody,
    work: Work,
}
impl Drop for Tracked {
    fn drop(&mut self) {
        self.work.complete |= self.inner.is_end_stream();
    }
}
impl Body for Tracked {
    type Data = Bytes;
    type Error = Fault;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Fault>>> {
        let s = self.get_mut();
        let frame = Pin::new(&mut s.inner).poll_frame(cx);
        match &frame {
            Poll::Ready(None) => s.work.complete = true,
            Poll::Ready(Some(Err(_))) => {
                s.work.complete = true;
                s.work.error();
                if let Some(p) = &s.work.pool {
                    p.stats.stream_errors.fetch_add(1, Relaxed);
                }
            }
            _ => {}
        }
        frame
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
