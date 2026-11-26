quinn-proto 0.11.19 (MIT OR Apache-2.0). Preserve the early-data provenance
of authenticated QUIC STREAM payloads per receive stream. This is independent
of when the application polls its request queue. Keep the wasm-specific ring
edge optional, controlled by the existing explicit `ring` crypto feature.
Revisit this patch when updating quinn-proto.
