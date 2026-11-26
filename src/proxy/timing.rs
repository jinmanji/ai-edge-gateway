use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{
            AtomicU8, AtomicU64,
            Ordering::{Acquire, Relaxed, Release},
        },
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use tokio::{
    sync::Notify,
    time::{Instant, sleep_until, timeout},
};

use super::body::{Fault, ProxyBody};

const QUEUED: u8 = 0;
const UPLOADING: u8 = 1;
const UPLOADED: u8 = 2;

pub struct Clock {
    stage: AtomicU8,
    start: Instant,
    last_ms: AtomicU64,
    change: Notify,
}

impl Clock {
    fn update(&self, stage: u8) {
        self.last_ms
            .store(self.start.elapsed().as_millis() as u64, Relaxed);
        if self.stage.swap(stage, Release) != stage {
            self.change.notify_one();
        }
    }
    async fn expire(&self, header: Duration, idle: Duration) -> Fault {
        loop {
            let notify = self.change.notified();
            let stage = self.stage.load(Acquire);
            let last = Duration::from_millis(self.last_ms.load(Relaxed));
            let duration = if stage == UPLOADING { idle } else { header };
            let deadline = self.start + last + duration;
            if Instant::now() >= deadline {
                // Avoid expiring from an old observation as upload progress or
                // EOF races this task on a different runtime worker.
                if self.stage.load(Acquire) != stage
                    || self.last_ms.load(Relaxed) != last.as_millis() as u64
                {
                    continue;
                }
                return if stage == UPLOADING {
                    Fault::StreamIdle
                } else {
                    Fault::HeaderDeadline
                };
            }
            tokio::select! { _ = notify => {}, _ = sleep_until(deadline) => {} }
        }
    }
}

pub fn monitor(body: ProxyBody) -> (ProxyBody, Option<Arc<Clock>>) {
    if body.is_end_stream() {
        return (body, None);
    }
    let clock = Arc::new(Clock {
        stage: AtomicU8::new(QUEUED),
        start: Instant::now(),
        last_ms: AtomicU64::new(0),
        change: Notify::new(),
    });
    (
        Upload {
            inner: body,
            clock: clock.clone(),
            started: false,
            eof: false,
        }
        .boxed_unsync(),
        Some(clock),
    )
}

/// Connection establishment has its own deadline inside the connector. While
/// a streaming upload is progressing, don't consume the model's header budget.
/// The initial dispatch/queue (or a bodyless request) also has a bounded wait.
pub async fn response<T>(
    clock: Option<Arc<Clock>>,
    header: Duration,
    idle: Duration,
    operation: impl Future<Output = Result<T, Fault>>,
) -> Result<T, Fault> {
    if let Some(clock) = clock {
        tokio::select! { biased; result = operation => result, fault = clock.expire(header, idle) => Err(fault) }
    } else {
        timeout(header, operation)
            .await
            .map_err(|_| Fault::HeaderDeadline)?
    }
}

struct Upload {
    inner: ProxyBody,
    clock: Arc<Clock>,
    started: bool,
    eof: bool,
}
impl Upload {
    fn complete(&mut self) {
        if !self.eof {
            self.eof = true;
            self.clock.update(UPLOADED);
        }
    }
}
impl Drop for Upload {
    fn drop(&mut self) {
        self.complete();
    }
}
impl Body for Upload {
    type Data = Bytes;
    type Error = Fault;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Fault>>> {
        let s = self.get_mut();
        if !s.started {
            s.started = true;
            s.clock.update(UPLOADING);
        }
        let frame = Pin::new(&mut s.inner).poll_frame(cx);
        if let Poll::Ready(result) = &frame {
            if result
                .as_ref()
                .is_none_or(|f| f.as_ref().is_err() || f.as_ref().is_ok_and(|f| f.is_trailers()))
                || s.inner.is_end_stream()
            {
                s.complete();
            } else if !s.eof {
                s.clock
                    .last_ms
                    .store(s.clock.start.elapsed().as_millis() as u64, Relaxed);
            }
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
