use std::{
    future::poll_fn,
    sync::{Arc, atomic::Ordering::Relaxed},
    time::Duration,
};

use bytes::Bytes;
use h3::{error::Code, frame::FrameStream, server::RequestResolver, stream::BufRecvStream};
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use quinn::{Connecting, Endpoint};
use tokio::{task::JoinSet, time::timeout};

use super::{App, ConnectionLease};
use crate::{
    config::Listen,
    net::tls,
    proxy::{
        body::{self, H3Body},
        handler::{self, ContextInfo},
        headers,
    },
};

type Resolver = RequestResolver<h3_quinn::Connection, Bytes>;
type SendStream = h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;

pub async fn accept(endpoint: Endpoint, app: Arc<App>) {
    let limits = app.config.load().listen.clone();
    loop {
        let incoming = tokio::select! { biased; _ = app.stop.cancelled() => break, i = endpoint.accept() => i };
        let Some(incoming) = incoming else {
            break;
        };
        if limits.quic_retry && !incoming.remote_address_validated() && incoming.may_retry() {
            let _ = incoming.retry();
            continue;
        }
        let Some(lease) = app.connection() else {
            app.global.rejected_connections.fetch_add(1, Relaxed);
            incoming.refuse();
            continue;
        };
        let settings = app
            .config
            .load()
            .tls
            .as_ref()
            .and_then(|t| t.quic.clone().map(|q| (q, t.quic_early)));
        let Some((cfg, early)) = settings else {
            incoming.refuse();
            continue;
        };
        let Ok(connecting) = incoming.accept_with(cfg) else {
            continue;
        };
        app.tasks.spawn(connection(
            connecting,
            app.clone(),
            lease,
            limits.clone(),
            early,
        ));
    }
    // Existing QUIC connections retain the endpoint driver while draining.
}

async fn connection(
    mut connecting: Connecting,
    app: Arc<App>,
    _lease: ConnectionLease,
    limits: Listen,
    early: bool,
) {
    let header_time = Duration::from_secs(limits.header_timeout_secs);
    let protocol = tokio::select! {
        biased; _ = app.stop.cancelled() => return,
        r = timeout(header_time, connecting.handshake_data()) => r.ok().and_then(Result::ok).is_some_and(tls::h3_alpn),
    };
    if !protocol {
        return;
    }
    let result = if early {
        match connecting.into_0rtt() {
            Ok((connection, confirmed)) => Some((connection, Some(confirmed))),
            Err(connecting) => fully_connected(connecting, &app, header_time).await,
        }
    } else {
        fully_connected(connecting, &app, header_time).await
    };
    let Some((quic, confirm)) = result else {
        return;
    };
    let mut confirm = Box::pin(async {
        if let Some(confirm) = confirm {
            timeout(header_time, confirm).await.is_ok()
        } else {
            true
        }
    });
    let mut confirming = true;
    let mut build = h3::server::builder();
    build
        .max_field_section_size(limits.max_header_bytes.into())
        .send_grease(false);
    let connected = tokio::select! {
        biased; _ = app.stop.cancelled() => return,
        r = timeout(header_time, build.build(h3_quinn::Connection::new(quic.clone()))) => r,
    };
    let Ok(Ok(mut h3)) = connected else {
        return;
    };
    let mut children = JoinSet::new();
    let mut draining = false;
    loop {
        if draining && children.is_empty() {
            break;
        }
        tokio::select! {
            biased;
            _ = app.stop.cancelled(), if !draining => {
                draining = true;
                let _ = timeout(header_time, h3.shutdown(0)).await;
            }
            valid = &mut confirm, if confirming => {
                confirming = false;
                if !valid || quic.close_reason().is_some() { break; }
            }
            _ = children.join_next(), if !children.is_empty() => {}
            _ = quic.closed() => break,
            next = poll_fn(|cx| h3.poll_accept_request_stream(cx)) => {
                let Ok(Some(stream)) = next else {
                    if draining { while children.join_next().await.is_some() {} }
                    break;
                };
                let peer_stop = stream.stopped();
                let resolver = h3.create_resolver(FrameStream::new(BufRecvStream::new(stream)));
                let app = app.clone();
                children.spawn(async move {
                    tokio::pin!(peer_stop);
                    tokio::select! { biased;
                        _ = &mut peer_stop => {}
                        sent = serve(resolver, app, draining, header_time) => {
                            // Quinn finish queues the FIN; closing the whole H3
                            // connection before it is acknowledged can truncate a
                            // response during an otherwise successful drain.
                            if sent { let _ = timeout(header_time, &mut peer_stop).await; }
                        }
                    }
                });
            }
        }
    }
    // JoinSet aborts outstanding handlers on abrupt connection closure.
}

async fn fully_connected(
    connecting: Connecting,
    app: &App,
    wait: Duration,
) -> Option<(quinn::Connection, Option<quinn::ZeroRttAccepted>)> {
    tokio::select! { biased;
        _ = app.stop.cancelled() => None,
        r = timeout(wait, connecting) => r.ok()?.ok().map(|quic| (quic, None)),
    }
}

async fn serve(resolver: Resolver, app: Arc<App>, draining: bool, header_time: Duration) -> bool {
    let Ok(Ok((request, stream))) = timeout(header_time, resolver.resolve_request()).await else {
        return false;
    };
    // Query the transport after decoding HEADERS, when the stream's data
    // provenance is known; handshake status at scheduling time is not enough.
    let early = stream.transport().is_0rtt();
    let idle = Duration::from_secs(app.config.load().limits.stream_idle_timeout_secs);
    let (send, mut recv) = stream.split();
    let mut send = SendGuard(Some(send));
    if draining {
        recv.stop_sending(Code::H3_REQUEST_REJECTED);
        if let Some(s) = &mut send.0 {
            s.stop_stream(Code::H3_REQUEST_REJECTED);
        }
        send.0 = None;
        return false;
    }
    let response = match headers::content_length(request.headers()) {
        Ok(length)
            if !request
                .headers()
                .contains_key(http::header::TRANSFER_ENCODING) =>
        {
            let (mut parts, _) = request.into_parts();
            let body = timeout(header_time, H3Body::new(recv, length).into_request_body()).await;
            match body {
                Ok(Ok(body)) => {
                    if length == Some(0) && !hyper::body::Body::is_end_stream(&body) {
                        // A length-zero stream may carry trailers. Leave the
                        // receiving protocol free to choose its wire framing.
                        parts.headers.remove(http::header::CONTENT_LENGTH);
                    }
                    handler::handle(
                        app,
                        Request::from_parts(parts, body),
                        ContextInfo {
                            secure: true,
                            early,
                            ..ContextInfo::default()
                        },
                    )
                    .await
                }
                Ok(Err(_)) => body::text(StatusCode::BAD_REQUEST, "invalid HTTP/3 body framing\n"),
                Err(_) => body::text(
                    StatusCode::REQUEST_TIMEOUT,
                    "HTTP/3 request did not finish\n",
                ),
            }
        }
        _ => {
            recv.stop_sending(Code::H3_MESSAGE_ERROR);
            body::text(StatusCode::BAD_REQUEST, "invalid HTTP/3 body framing\n")
        }
    };
    let (parts, mut body) = response.into_parts();
    let Some(s) = &mut send.0 else {
        return false;
    };
    if !timeout(idle, s.send_response(Response::from_parts(parts, ())))
        .await
        .is_ok_and(|r| r.is_ok())
    {
        return false;
    }
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else {
            return false;
        };
        let result = match frame.into_data() {
            Ok(data) if data.is_empty() => continue,
            Ok(data) => timeout(idle, s.send_data(data)).await,
            Err(frame) => match frame.into_trailers() {
                Ok(t) => timeout(idle, s.send_trailers(t)).await,
                Err(_) => continue,
            },
        };
        if !result.is_ok_and(|r| r.is_ok()) {
            return false;
        }
    }
    if timeout(idle, s.finish()).await.is_ok_and(|r| r.is_ok()) {
        send.0 = None;
        true
    } else {
        false
    }
}

struct SendGuard(Option<SendStream>);
impl Drop for SendGuard {
    fn drop(&mut self) {
        if let Some(s) = &mut self.0 {
            s.stop_stream(Code::H3_REQUEST_CANCELLED);
        }
    }
}

#[cfg(test)]
mod tests {
    use h3::proto::frame::{Frame, FrameError};

    #[test]
    fn bounded_encoded_frame_rejects_length_without_buffering_payload() {
        // A HEADERS prefix declaring slightly over 256 KiB, but no payload.
        // A cap must reject immediately; asking for more bytes defeats it.
        let mut prefix: &[u8] = &[0x01, 0x80, 0x04, 0x00, 0x01];
        assert!(matches!(
            Frame::decode(&mut prefix),
            Err(FrameError::InvalidFrameValue)
        ));
        let mut streamed: &[u8] = &[0x00, 0x80, 0x04, 0x00, 0x01];
        assert!(matches!(Frame::decode(&mut streamed), Ok(Frame::Data(_))));
    }
}
