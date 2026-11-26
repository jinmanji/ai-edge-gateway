Based on h3-quinn 0.0.10 from crates.io (MIT). The local changes expose Quinn's
stream early-data tag and STOP_SENDING future. Receive polling uses Quinn's
cancel-safe read_chunk directly, so a pending read cannot prevent STOP_SENDING
or cause an unwrap panic. The rest is the upstream adapter. Revisit this patch
when updating h3/h3-quinn.

The adapter uses Quinn's inherent read/write methods, so it also leaves Quinn's
`futures-io` feature and default runtime/crypto features disabled. The gateway
selects `runtime-tokio` and `rustls-aws-lc-rs` explicitly.
