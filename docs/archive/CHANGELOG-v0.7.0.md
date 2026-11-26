# Khaymali v0.7.0 — Complete Release Notes

## Implemented Subsystems & Architectural Upgrades

1. **Turbo-Tunnel Live Session Engine (`src/session_resume.rs`, wired into `src/mux.rs` & `src/exit.rs`):**
   - Decoupled TCP/Stream session state and destination socket ownership (`SessionOwner`, `SessionRegistry`) from volatile underlying carriers.
   - Implemented `ResumeFrame` wire framing (`AttachReq`, `AttachAck`, `SeqData`, `SeqAck`, `SeqFin`) over `CMD_RESUME = 10` inside encrypted `Noise_IK` links.
   - Bound session resumption to authenticated peer Noise static keys via `HMAC-SHA256` proofs (`compute_resume_proof`) with `ReplayLedger` and monotonic `ResumeEpoch` generation leases.
   - Added bounded per-session (`512 KiB`) and global (`64 MiB`) unacknowledged ring buffers (`ResumeDataPlane`) with duplicate suppression, out-of-order reassembly, and seamless replay on carrier failover without resetting destination TCP sockets.

2. **Modular Transport Engine & Carrier Extensions (`src/transport_engine.rs`):**
   - Added `TransportRegistry` supporting `tcp`, `tcp+camo`, `udp+arq`, `quic-stream` (RFC 9000 framing + 64-bit connection ID), `kcp-fec` (XOR parity shard recovery), and `ws-h2` (RFC 6455 masked binary framing).
   - Added `TransportBenchmark` measuring `RTT`, `Jitter`, `Loss per-mille`, and `Goodput`, paired with `HysteresisSelector` (15% margin + cooldown) to eliminate path flapping.

3. **Independent Layer-3 Networking Subsystem (`src/l3.rs`):**
   - Added `TunConfig`, `GreEncap` (RFC 2784), `IpipEncap` (RFC 2003), `WireGuardAdapter` (cryptographically separated from Noise_IK), `PmtuTracker` (`1280..1420` clamping), and longest-prefix-match `RoutePolicy` with anti-SSRF enforcement.

4. **Fleet & Service Governance (`src/fleet.rs`):**
   - Added `NodeRegistry` (health heartbeats & capacity tracking), `ServiceIdentity` / `ServiceRegistry`, and `SignedConfig` (`HMAC-SHA256` signature + monotonic revision anti-rollback + expiry verification).

5. **Audited `experimental/ktunnel` Research Module:**
   - Removed static XOR header masking, added strict header magic/bounds/AEAD tag validation (`ktun_proto.h`, `k_tcpmux.c`), and documented strict ciphertext-only boundaries.

6. **CLI, Control Plane, Prometheus Metrics & Negative Security Gates:**
   - Added `khaymali transports` and `khaymali verify-config` CLI commands (`src/main.rs`).
   - Added `sessions.status`, `transports.list`, and `l3.status` Control API RPCs (`src/control.rs`) and metrics (`src/stats.rs`).
   - Added negative & integration test gates #15–#17 in `tests/neg_security.rs`.
