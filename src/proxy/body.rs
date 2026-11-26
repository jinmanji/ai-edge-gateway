use std::{
    fmt,
    future::{Future, poll_fn},
    pin::Pin,
    task::{Context, Poll, ready},
    time::Duration,
};

use bytes::{Buf, Bytes};
use h3::error::Code;
use http::{HeaderMap, Response, StatusCode, header};
use http_body_util::{BodyExt, Empty, Full, combinators::UnsyncBoxBody};
use hyper::body::{Body, Frame, SizeHint};
use tokio::time::{Sleep, sleep};

use super::headers;

pub type ProxyBody = UnsyncBoxBody<Bytes, Fault>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    Downstream,
    Response,
    Connect,
    ConnectDeadline,
    HeaderDeadline,
    StreamIdle,
    Framing,
}

impl fmt::Display for Fault {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(match self {
            Self::Downstream => "downstream stream closed",
            Self::Response => "upstream stream failed",
            Self::Connect => "upstream connect failed",
            Self::ConnectDeadline => "upstream connect deadline exceeded",
            Self::HeaderDeadline => "upstream response-header deadline exceeded",
            Self::StreamIdle => "stream idle deadline exceeded",
            Self::Framing => "invalid HTTP framing",
        })
    }
}
impl std::error::Error for Fault {}

pub fn empty() -> ProxyBody {
    Empty::<Bytes>::new().map_err(|e| match e {}).boxed_unsync()
}
pub fn text(status: StatusCode, body: &'static str) -> Response<ProxyBody> {
    let mut r = Response::new(
        Full::new(Bytes::from_static(body.as_bytes()))
            .map_err(|e| match e {})
            .boxed_unsync(),
    );
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    r
}

pub fn timed(body: ProxyBody, idle: Duration, trailer_limit: usize) -> ProxyBody {
    if body.is_end_stream() {
        return body;
    }
    Idle {
        body,
        idle,
        sleep: None,
        trailer_limit,
        failed: false,
    }
    .boxed_unsync()
}

struct Idle {
    body: ProxyBody,
    idle: Duration,
    sleep: Option<Pin<Box<Sleep>>>,
    trailer_limit: usize,
    failed: bool,
}

impl Body for Idle {
    type Data = Bytes;
    type Error = Fault;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Fault>>> {
        let s = self.get_mut();
        if s.failed {
            return Poll::Ready(None);
        }
        match Pin::new(&mut s.body).poll_frame(cx) {
            Poll::Ready(value) => {
                // Count idle time only while the consumer is asking for a frame,
                // not while a slow downstream is applying backpressure.
                s.sleep = None;
                if let Some(Ok(mut frame)) = value {
                    if let Some(headers) = frame.trailers_mut()
                        && headers::trailers(headers, s.trailer_limit).is_err()
                    {
                        s.failed = true;
                        s.body = empty();
                        return Poll::Ready(Some(Err(Fault::Framing)));
                    }
                    Poll::Ready(Some(Ok(frame)))
                } else {
                    Poll::Ready(value)
                }
            }
            Poll::Pending => {
                let timer = s.sleep.get_or_insert_with(|| Box::pin(sleep(s.idle)));
                if timer.as_mut().poll(cx).is_ready() {
                    s.failed = true;
                    s.body = empty();
                    Poll::Ready(Some(Err(Fault::StreamIdle)))
                } else {
                    Poll::Pending
                }
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.failed || self.body.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

pub type ClientRecv = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;
pub type ServerRecv = h3::server::RequestStream<h3_quinn::RecvStream, Bytes>;

pub trait H3Recv: Send + Unpin + 'static {
    fn data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, Fault>>;
    fn trailers(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<HeaderMap>, Fault>>;
    fn cancel(&mut self);
}

macro_rules! recv_impl {
    ($type:ty, $error:expr) => {
        impl H3Recv for $type {
            fn data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, Fault>> {
                let chunk = ready!(self.poll_recv_data(cx)).map_err(|_| $error)?;
                // h3's DATA adapter returns a Bytes chunk (via opaque Buf); its
                // copy_to_bytes is a slice/refcount operation, not a body copy.
                Poll::Ready(Ok(chunk.map(|mut b| b.copy_to_bytes(b.remaining()))))
            }
            fn trailers(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<HeaderMap>, Fault>> {
                self.poll_recv_trailers(cx).map_err(|_| $error)
            }
            fn cancel(&mut self) {
                self.stop_sending(Code::H3_REQUEST_CANCELLED);
            }
        }
    };
}
recv_impl!(ClientRecv, Fault::Response);
recv_impl!(ServerRecv, Fault::Downstream);

pub struct H3Body<R: H3Recv> {
    recv: R,
    remaining: Option<u64>,
    at_trailers: bool,
    prefetched: Option<Frame<Bytes>>,
    done: bool,
}

impl<R: H3Recv> H3Body<R> {
    pub fn new(recv: R, remaining: Option<u64>) -> Self {
        Self {
            recv,
            remaining,
            at_trailers: false,
            prefetched: None,
            done: false,
        }
    }
    /// Check whether a downstream H3 request is actually bodyless. An
    /// advertised zero length still needs validation against DATA and FIN.
    /// With no length, peek once without waiting for a streaming upload.
    pub async fn into_request_body(mut self) -> Result<ProxyBody, Fault> {
        let frame = match self.remaining {
            Some(0) => self.frame().await,
            Some(_) => return Ok(self.boxed_unsync()),
            None => match poll_fn(|cx| Poll::Ready(Pin::new(&mut self).poll_frame(cx))).await {
                Poll::Ready(frame) => frame,
                Poll::Pending => return Ok(self.boxed_unsync()),
            },
        };
        match frame {
            None => Ok(empty()),
            Some(Ok(first)) => {
                self.prefetched = Some(first);
                Ok(self.boxed_unsync())
            }
            Some(Err(fault)) => Err(fault),
        }
    }
    fn fail(&mut self, fault: Fault) -> Poll<Option<Result<Frame<Bytes>, Fault>>> {
        self.recv.cancel();
        self.done = true;
        Poll::Ready(Some(Err(fault)))
    }
}
impl<R: H3Recv> Drop for H3Body<R> {
    fn drop(&mut self) {
        if !self.done {
            self.recv.cancel();
        }
    }
}

impl<R: H3Recv> Body for H3Body<R> {
    type Data = Bytes;
    type Error = Fault;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Fault>>> {
        let s = self.get_mut();
        if let Some(frame) = s.prefetched.take() {
            return Poll::Ready(Some(Ok(frame)));
        }
        if s.done {
            return Poll::Ready(None);
        }
        if !s.at_trailers {
            match ready!(s.recv.data(cx)) {
                Ok(Some(chunk)) => {
                    if let Some(n) = &mut s.remaining {
                        if (chunk.len() as u64) > *n {
                            return s.fail(Fault::Framing);
                        }
                        *n -= chunk.len() as u64;
                    }
                    return Poll::Ready(Some(Ok(Frame::data(chunk))));
                }
                Ok(None) if s.remaining.is_some_and(|n| n != 0) => return s.fail(Fault::Framing),
                Ok(None) => s.at_trailers = true,
                Err(fault) => return s.fail(fault),
            }
        }
        let trailers = match ready!(s.recv.trailers(cx)) {
            Ok(h) => h,
            Err(fault) => return s.fail(fault),
        };
        s.done = true;
        Poll::Ready(trailers.map(|h| Ok(Frame::trailers(h))))
    }
    fn is_end_stream(&self) -> bool {
        self.done && self.prefetched.is_none()
    }
    fn size_hint(&self) -> SizeHint {
        // Do not claim EOF from Content-Length alone: a trailing HEADERS block
        // may follow, and the peer's FIN must validate framing.
        if self.is_end_stream() {
            SizeHint::with_exact(0)
        } else {
            SizeHint::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering::Relaxed},
    };

    use super::*;

    struct Recv {
        data: VecDeque<Bytes>,
        trailers: Option<HeaderMap>,
        stalls: bool,
        cancelled: Arc<AtomicUsize>,
    }
    impl Recv {
        fn new(data: &'static [&'static str]) -> Self {
            Self {
                data: data
                    .iter()
                    .map(|s| Bytes::from_static(s.as_bytes()))
                    .collect(),
                trailers: None,
                stalls: false,
                cancelled: Default::default(),
            }
        }
    }
    impl H3Recv for Recv {
        fn data(&mut self, _: &mut Context<'_>) -> Poll<Result<Option<Bytes>, Fault>> {
            if self.stalls {
                Poll::Pending
            } else {
                Poll::Ready(Ok(self.data.pop_front()))
            }
        }
        fn trailers(&mut self, _: &mut Context<'_>) -> Poll<Result<Option<HeaderMap>, Fault>> {
            Poll::Ready(Ok(self.trailers.take()))
        }
        fn cancel(&mut self) {
            self.cancelled.fetch_add(1, Relaxed);
        }
    }

    #[tokio::test]
    async fn h3_empty_fast_path_requires_fin_and_keeps_prefetched_data_or_trailers() {
        for length in [None, Some(0)] {
            let recv = Recv::new(&[]);
            let cancelled = recv.cancelled.clone();
            let mut body = H3Body::new(recv, length).into_request_body().await.unwrap();
            assert!(body.is_end_stream());
            assert_eq!(body.size_hint().exact(), Some(0));
            assert!(body.frame().await.is_none());
            assert_eq!(cancelled.load(Relaxed), 0);
        }
        let mut body = H3Body::new(Recv::new(&["first", "second"]), None)
            .into_request_body()
            .await
            .unwrap();
        assert!(!body.is_end_stream());
        for expect in ["first", "second"] {
            assert_eq!(
                body.frame().await.unwrap().unwrap().into_data().unwrap(),
                expect
            );
        }
        assert!(body.frame().await.is_none());
        let mut recv = Recv::new(&[]);
        let mut trailer = HeaderMap::new();
        trailer.insert("x-test-trailer", http::HeaderValue::from_static("present"));
        recv.trailers = Some(trailer);
        let mut body = H3Body::new(recv, Some(0))
            .into_request_body()
            .await
            .unwrap();
        assert!(!body.is_end_stream());
        assert_eq!(
            body.frame()
                .await
                .unwrap()
                .unwrap()
                .into_trailers()
                .unwrap()["x-test-trailer"],
            "present"
        );
        assert!(body.is_end_stream());
    }

    #[tokio::test]
    async fn h3_fast_path_rejects_bad_length_and_keeps_drop_cancellation() {
        let recv = Recv::new(&["unexpected"]);
        let cancelled = recv.cancelled.clone();
        assert!(matches!(
            H3Body::new(recv, Some(0)).into_request_body().await,
            Err(Fault::Framing)
        ));
        assert_eq!(cancelled.load(Relaxed), 1);

        let mut recv = Recv::new(&[]);
        recv.stalls = true;
        let cancelled = recv.cancelled.clone();
        let body = H3Body::new(recv, None).into_request_body().await.unwrap();
        assert!(!body.is_end_stream());
        drop(body);
        assert_eq!(cancelled.load(Relaxed), 1);
    }
}
