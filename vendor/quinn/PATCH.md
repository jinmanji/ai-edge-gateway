Quinn 0.11.12 (MIT OR Apache-2.0). Use the protocol's per-stream 0-RTT data
marker rather than `is_handshaking()` at accept time. Preserve the marker in
the receive handle on reads, before transport state can be freed on EOF.
Revisit this patch when updating Quinn.
