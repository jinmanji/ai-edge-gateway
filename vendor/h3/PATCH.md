Based on h3 0.0.8 from crates.io (MIT). The frame decoder rejects non-DATA
payloads larger than 256 KiB from the frame prefix instead of accumulating an
unbounded encoded header, settings, or extension block. DATA frame contents
are still streamed. The request stream also skips zero-length DATA rather than
mistaking it for EOF. The decoded field-section limit is enforced separately.
Revisit both local changes when updating h3.

A FIN in the middle of a nonempty DATA frame is reported as `UnexpectedEnd`,
including when no DATA payload bytes arrived; it must not look like empty EOF.
