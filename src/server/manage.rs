use std::{
    convert::Infallible,
    fmt::Write,
    sync::{Arc, atomic::Ordering::Relaxed},
    time::Duration,
};

use bytes::Bytes;
use http::{HeaderValue, Method, Request, Response, StatusCode, header};
use http_body_util::Full;
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::{
    net::TcpListener,
    sync::Semaphore,
    time::{sleep, timeout},
};

use super::App;

pub async fn serve(listener: TcpListener, app: Arc<App>) {
    let limit = Arc::new(Semaphore::new(8));
    loop {
        let result = tokio::select! { biased; _ = app.stop.cancelled() => break, r = listener.accept() => r };
        let Ok((tcp, _)) = result else {
            sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            continue;
        };
        let app = app.clone();
        app.tasks.clone().spawn(async move {
            let _permit = permit;
            let svc = service_fn(move |r| {
                let response = response(&app, r);
                async move { Ok::<_, Infallible>(response) }
            });
            let mut builder = http1::Builder::new();
            builder
                .keep_alive(false)
                .max_headers(32)
                .max_buf_size(8192)
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(2));
            let _ = timeout(
                Duration::from_secs(4),
                builder.serve_connection(TokioIo::new(tcp), svc),
            )
            .await;
        });
    }
}

fn response(app: &App, request: Request<Incoming>) -> Response<Full<Bytes>> {
    let local_host = crate::proxy::headers::single(request.headers(), header::HOST)
        .ok()
        .flatten()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<http::uri::Authority>().ok())
        .is_some_and(|a| {
            a.host().eq_ignore_ascii_case("localhost")
                || a.host()
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
    let (status, bytes, content_type) = if !local_host {
        (
            StatusCode::BAD_REQUEST,
            Bytes::from_static(b"loopback Host required\n"),
            "text/plain",
        )
    } else if request.method() != Method::GET && request.method() != Method::HEAD {
        (
            StatusCode::METHOD_NOT_ALLOWED,
            Bytes::from_static(b"only GET/HEAD\n"),
            "text/plain",
        )
    } else {
        match request.uri().path() {
            "/healthz" if !app.stop.is_cancelled() => {
                (StatusCode::OK, Bytes::from_static(b"ok\n"), "text/plain")
            }
            "/healthz" => (
                StatusCode::SERVICE_UNAVAILABLE,
                Bytes::from_static(b"draining\n"),
                "text/plain",
            ),
            "/metrics" => (
                StatusCode::OK,
                Bytes::from(metrics(app)),
                "text/plain; version=0.0.4; charset=utf-8",
            ),
            _ => (
                StatusCode::NOT_FOUND,
                Bytes::from_static(b"not found\n"),
                "text/plain",
            ),
        }
    };
    let mut response = Response::new(Full::new(bytes));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn metrics(app: &App) -> String {
    let mut s = String::with_capacity(4096);
    let g = &app.global;
    for (field, value) in [
        ("active_connections", g.connections.load(Relaxed)),
        ("active_requests", g.in_flight.load(Relaxed)),
        (
            "rejected_connections_total",
            g.rejected_connections.load(Relaxed),
        ),
        ("rejected_requests_total", g.rejected_requests.load(Relaxed)),
    ] {
        let _ = writeln!(s, "aieg_{field} {value}");
    }
    let _ = writeln!(s, "# TYPE aieg_upstream_ttfb_seconds histogram");
    let config = app.config.load();
    for ((p, egress), stats) in &config.metrics {
        stats.render(&mut s, p.name(), egress);
    }
    s
}
