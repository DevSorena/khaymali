# Khaymali v0.8.0 — Complete Release Notes

## Implemented Features in v0.8.0

1. **HAProxy PROXY Protocol v2 Support in L4 Port Forwarding (`src/forward.rs`, `src/control.rs`):**
   - Added `proxy=v2` option to `--forward` rules (e.g., `--forward "443@name=VLESS,target=127.0.0.1:8443,proxy=v2"`).
   - Encodes standards-compliant binary HAProxy PROXY Protocol v2 headers (`encode_proxy_v2_header`) for both IPv4 (`0x11`/`0x12`) and IPv6 (`0x21`/`0x22`) over TCP and UDP forwards, passing the real client source IP and port through the encrypted Noise tunnel to backend panels (`3x-ui`, `Marzban`, `Xray`, `Nginx`).

2. **Native Linux `/dev/net/tun` Layer-3 VPN Subsystem & `khaymali tun` CLI (`src/l3.rs`, `src/exit.rs`, `src/main.rs`):**
   - Added `LinuxTunDevice` (`IFF_TUN | IFF_NO_PI`) with zero external crate dependencies (`Cargo.lock` compatible) plus safe `ip link` / `ip addr` / `ip route` configuration.
   - Added `khaymali tun` CLI subcommand (`--tun`, `--cidr`, `--peer-ip`, `--mode tun|gre|ipip`, `--route`, `--mtu`) and `--tun` / `--tun-cidr` support on `khaymali exit` (request type `[4]`), bridging raw IPv4/IPv6 packets with `PMTU` clamping (`1280..1420`) and anti-SSRF route enforcement.

3. **End-to-End Entry-to-Exit Turbo-Tunnel Live Session Resume (`src/mux.rs`, `src/entry.rs`):**
   - Added `MuxCarrier::open_resumable_stream`, `MuxCarrier::attach_session`, and `ResumableMuxStream` on the Entry side, wired into `MuxPool` and `handle_socks` (`--session-resume` enabled by default when `--mux` is active; opt-out via `--no-session-resume`).
   - Added background `MuxPool` reattachment supervisor in `src/entry.rs` that automatically detects detached `SessionOwner` streams upon carrier death/rekeying, dials/picks a healthy carrier, increments `ResumeEpoch`, verifies `HMAC-SHA256` proof, and replays unacknowledged frames without resetting client TCP streams.

4. **Expanded Negative & Integration Security Gates (`tests/neg_security.rs`):**
   - Added `neg_18_proxy_protocol_v2_wire_verification` and `neg_19_end_to_end_mux_carrier_session_resume_across_carrier_kill`.
