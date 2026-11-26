use std::{
    fmt::Write,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    time::Duration,
};

// Non-cumulative, allocation-free on the request path. Prometheus exposition
// converts to cumulative buckets and reports explicit approximate quantiles.
const BOUNDS: [u64; 20] = [
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000,
    120_000, 180_000, 600_000,
];

#[derive(Default)]
pub struct Stats {
    pub requests: AtomicU64,
    pub errors: AtomicU64,
    pub cancelled: AtomicU64,
    pub stream_errors: AtomicU64,
    pub h3_fallbacks: AtomicU64,
    pub h3_early_accepted: AtomicU64,
    pub h3_early_rejected: AtomicU64,
    ttfb_count: [AtomicU64; BOUNDS.len() + 1],
    ttfb_sum_ms: AtomicU64,
}

impl Stats {
    pub fn ttfb(&self, elapsed: Duration) {
        let ms = elapsed.as_millis().min(u64::MAX as u128) as u64;
        let i = BOUNDS.partition_point(|&bound| bound < ms);
        self.ttfb_count[i].fetch_add(1, Relaxed);
        self.ttfb_sum_ms.fetch_add(ms, Relaxed);
    }
    pub fn render(&self, out: &mut String, provider: &str, egress: &str) {
        // Provider and egress labels were validated against a safe ASCII alphabet.
        let labels = format!("provider=\"{provider}\",egress=\"{egress}\"");
        let n = self.requests.load(Relaxed);
        let e = self.errors.load(Relaxed);
        for (field, value) in [
            ("requests_total", n),
            ("request_errors_total", e),
            ("cancelled_total", self.cancelled.load(Relaxed)),
            ("stream_errors_total", self.stream_errors.load(Relaxed)),
            ("h3_fallbacks_total", self.h3_fallbacks.load(Relaxed)),
            (
                "h3_early_accepted_total",
                self.h3_early_accepted.load(Relaxed),
            ),
            (
                "h3_early_rejected_total",
                self.h3_early_rejected.load(Relaxed),
            ),
        ] {
            let _ = writeln!(out, "aieg_{field}{{{labels}}} {value}");
        }
        let error_ratio = if n == 0 { 0.0 } else { e as f64 / n as f64 };
        let _ = writeln!(out, "aieg_request_error_ratio{{{labels}}} {error_ratio}");
        let counts = self.ttfb_count.each_ref().map(|c| c.load(Relaxed));
        let total: u64 = counts.iter().sum();
        let mut sum = 0;
        for (i, n) in counts.iter().enumerate() {
            sum += n;
            let le = BOUNDS
                .get(i)
                .map_or("+Inf".into(), |b| (*b as f64 / 1000.0).to_string());
            let _ = writeln!(
                out,
                "aieg_upstream_ttfb_seconds_bucket{{{labels},le=\"{le}\"}} {sum}"
            );
        }
        let _ = writeln!(out, "aieg_upstream_ttfb_seconds_count{{{labels}}} {total}");
        let _ = writeln!(
            out,
            "aieg_upstream_ttfb_seconds_sum{{{labels}}} {}",
            self.ttfb_sum_ms.load(Relaxed) as f64 / 1000.0
        );
        if total != 0 {
            for p in [50u64, 99] {
                let mut seen = 0;
                let i = counts
                    .iter()
                    .position(|n| {
                        seen += n;
                        seen >= total.saturating_mul(p).div_ceil(100)
                    })
                    .unwrap_or(BOUNDS.len());
                let bound = BOUNDS
                    .get(i)
                    .map_or("+Inf".into(), |ms| (*ms as f64 / 1000.0).to_string());
                let _ = writeln!(
                    out,
                    "aieg_upstream_ttfb_estimate_seconds{{{labels},quantile=\"{}\"}} {bound}",
                    p as f64 / 100.0
                );
            }
        }
    }
}

#[derive(Default)]
pub struct Global {
    pub connections: AtomicU64,
    pub rejected_connections: AtomicU64,
    pub in_flight: AtomicU64,
    pub rejected_requests: AtomicU64,
}

pub struct ConnectionCount(pub Arc<Global>);
impl ConnectionCount {
    pub fn new(global: Arc<Global>) -> Self {
        global.connections.fetch_add(1, Relaxed);
        Self(global)
    }
}
impl Drop for ConnectionCount {
    fn drop(&mut self) {
        self.0.connections.fetch_sub(1, Relaxed);
    }
}
