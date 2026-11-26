# Ecosystem Architecture Matrix & Extraction Plan (`docs/ECOSYSTEM_MATRIX.md`)

Khaymali does NOT blindly copy protocols or bloat its core. Instead, each major open-source project is studied for specific architectural primitives and mapped strictly to Khaymali's phased, evidence-gated roadmap.

## 1. Primary Tunnel & Manager References
| Project | Architectural Strength Extracted | Khaymali Implementation / Phase |
|---|---|---|
| **BackPack** | Interactive dark/crimson TUI dashboard, Check Code, L4 Port Forwarding (quotas, rate limits, failover, live per-user table), route metrics | `src/forward.rs`, `scripts/khaymali-tui`, `scripts/khaymali-web`, `src/health.rs` (v0.5.0) |
| **C-Tunnel** | Multi-tunnel management, path & MTU probing across multiple foreign Exits | `scripts/khaymali-doctor` (PMTU step probe + per-Exit scan), multi-Exit `Exits` pool |
| **Paqet Tunnel Manager** | One-line deployment ergonomics and clean node lifecycle scripts (evaluated separately from its raw-socket engine) | `install.sh` (verified archive + optional `--tune`/`--verify-attestation`), `khaymali-tui` + `khaymali-manager` |

## 2. Global Ecosystem Study Matrix
| Category | Projects Studied | Specific Concept Relevant to Khaymali | Phase / Gate |
|---|---|---|---|
| **Modern Multi-Protocol Cores** | `sing-box`, `Xray-core`, `Mihomo`, `Brook`, `Shadowsocks-rust` | Strict `Transport` trait separation, inbound/outbound routing hygiene, low-RSS Rust data path | Phase 2A (`src/transport.rs`), Phase 4 (XHTTP/CDN if IP-block confirmed) |
| **QUIC & Lossy Paths** | `Hysteria 2`, `TUIC`, `NaiveProxy` | QUIC datagrams, custom congestion control, HTTP/2 & HTTP/3 stack behavior | Phase 4 (Strictly optional — NOT default in Iran/China due to UDP/QUIC SNI blocking) |
| **Reverse & Specialized Tunnels** | `rathole`, `frp`, `GOST`, `Chisel`, `NPS`, `udp2raw`, `kcptun`, `Phantun` | Reverse-dial NAT traversal (`Bridge`), bounded link pooling, multi-layer relay chaining | Core 3-node architecture (`Entry ◄── Bridge ──► Exit`), Phase 4 Chain Mode |
| **VPN, Kernel & Research** | `WireGuard`, `AmneziaWG`, `dae` (eBPF), `Cloak`, `Mieru`, `Iodine`, `Tailscale`, `ZeroTier` | Minimal cryptographic surface (`Noise_IK`), clean static key pinning, extensible framing, emergency fallback concepts | Core `Noise_IK` + Phase 3 Signed Exit Manifest (`Ed25519` offline root) |

## 3. Discipline Rule
No secondary transport (`QUIC`, `XHTTP/CDN`, `ShadowTLS v3/BoringSSL`, `Raw/KCP`) is merged into Khaymali's primary Data Plane until:
1. All 14 mandatory negative/security tests in `tests/neg_security.rs` pass under `cargo test --release --locked`.
2. Real-link `khaymali-doctor probe` JSON baselines prove the exact impairment class on the target network.
3. `scripts/check_baseline_regression.py` confirms zero `p99`, `RSS`, or `goodput` regression.
