# Khaymali v0.10.0 — Complete Release Notes

## New Capabilities Integrated in v0.10.0

1. **Live XOR-Parity Forward Error Correction (FEC) on UDP Carrier (`src/udp_transport.rs`):**
   - Added `FLAG_FEC` (`1 << 4`) emitting 1 authenticated XOR-parity packet per 4 data packets (`FEC_GROUP_SIZE = 4`).
   - Reconstructs any single lost packet in a 4-packet group in **0-RTT** without waiting for ARQ retransmission, exported via `khaymali_udp_fec_recovered_total`.

2. **Automatic Multi-Transport Fallback Cascade (`auto://HOST:PORT`, `src/transport.rs`):**
   - `auto://HOST:PORT` automatically probes and falls back across `udp://` (UDP + XOR-FEC + ARQ) -> `ktunnel://` (8-flow FakeTLS-Mux) -> `tcp+camo` (TLS 1.3 Camo) -> `tcp` when UDP is blocked or throttled.

3. **Reverse-Dial Connection Mode (`--reverse-entry` on Exit / `--listen-exit` on Entry):**
   - Allows Exit to initiate outbound transport connections to Entry (`--reverse-entry <ENTRY_IP:PORT>`), enabling 2-node traversal behind strict NAT/firewalls without a 3rd Bridge host.

4. **Kernel-Level Transparent Port Forwarding Preserving Real Client Source IP (`mode=kernel` in `src/forward.rs` & `src/l3.rs`):**
   - Added `KernelTransparentForwarder` using dedicated `iptables` `KHAYMALI_PREROUTING` / `KHAYMALI_MANGLE` chains + policy routing over TUN (`khaymali0`) so backend services see the exact original client IPv4 address without SNAT masquerading.

5. **Ergonomic Join Code URI, Comma-Separated Forwards & Live Forward Control (`src/main.rs`, `src/control.rs`, `install.sh`):**
   - Added `khaymali join-code` / `khaymali parse-join <khaymali://v1?...>` single-string pairing.
   - Added comma-separated port shorthand (`--forward 443,2052,8443@proxy=v2`), live `khaymali forward add|ls|rm`, `khaymali status`, `khaymali up|down`, and `--from-source` / `--local` / `--mirror` installer flags.
