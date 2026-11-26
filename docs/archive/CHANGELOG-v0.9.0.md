# Khaymali v0.9.0 — Multi-Flow FakeTLS-Mux (`ktunnel`) Release Notes

## Implemented Features in v0.9.0

1. **Userspace Multi-Flow FakeTLS-Mux Protocol (`src/ktunnel.rs`, `ktunnel://HOST:PORT`):**
   - Stripes encrypted traffic round-robin across `8` parallel TCP subflows with active-flow fallback (`MUX_FLOW_COUNT = 8`), preventing single-flow head-of-line stalls and DPI per-flow throttling.
   - Wraps every record in a 9-byte TLS 1.3 Application Data + Mux header (`17 03 03 | record_len | stream_id | mux_flags | pad_len`) with keyed `HMAC-SHA256` stream masking.
   - Integrated into `Transport` (`KtunnelTransport`, `AutoTransport`), `TransportRegistry` (`CarrierKind::Ktunnel`), `Exit` (`--ktunnel-listen ADDR`), `Entry` / `Bridge` (`--exit ktunnel://HOST:PORT`), Prometheus metrics (`ktunnel_sessions_active`, `ktunnel_flows_active`), and Control API.

2. **Hardened Linux Kernel TCP-Mux + FakeTLS & `ktun_cc` (`experimental/ktunnel/`):**
   - Integrated `k_tcpmux.c`, `ktun_cc.c` (loss-tolerant 7/8 `ssthresh` congestion control), `ktun_handshake.c` (`TCP_REPAIR` sequence sync daemon), and `Makefile`.
   - Hardened `ktun_handshake.c` (compiled cleanly with `gcc -O2 -Wall -Wextra -Werror`) with strict `argc` checks, bounds-checked `fds[]` indexing, full syscall error handling, and clean signal teardown.
   - Upgraded `k_tcpmux.c` with optional 32-hex `obfs_secret` keyed rolling keystream masking and strict `record_len`/`inner_len` bounds verification.

3. **Security Gate #20 (`tests/neg_security.rs`):**
   - Added `neg_20_ktunnel_multiflow_faketls_roundtrip_and_tamper_rejection` verifying 8-flow striped transfer and unauthorized key rejection.
