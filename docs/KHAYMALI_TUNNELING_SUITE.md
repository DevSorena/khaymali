# Khaymali v0.22.0 — Pure Tunneling Suite

Khaymali v0.22.0 is a **pure, standalone Rust tunneling system** with **zero web panel overhead** and **zero external crate bloat** (`--locked` builds). Every carrier, wrap, engine manager, live swap coordinator, cluster mesh/LB, diagnostic doctor, and harsh-network Micro-NLP lives natively inside a single `khaymali` binary.

## 1. Native Multi-Carrier Transports (End-to-End Noise_IK)

| Scheme | Module | Description |
| --- | --- | --- |
| `HOST:PORT` / `tcp://` | `transport.rs` / `camo.rs` | Plain TCP or FakeTLS 1.3 Camouflage + Decoy Fallback |
| `udp://HOST:PORT` | `udp_transport.rs` | Authenticated Reliable UDP ARQ + Adaptive XOR-Parity 0-RTT FEC |
| `ktunnel://HOST:PORT` | `ktunnel.rs` | Multi-Flow FakeTLS-Mux (8 parallel striped TCP subflows) |
| `ws://HOST:PORT` | `ws_transport.rs` | RFC 6455 Binary WebSocket + HMAC-SHA256 `X-Khaymali-Auth` |
| `wss://HOST:PORT` | `ws_transport.rs` | RFC 6455 WebSocket inside TLS 1.3 Camo + Decoy Fallback |
| `ssh://[user@]host[:port]/remote_port` | `ssh_carrier.rs` | SSH carrier with `TCP_NODELAY` session-exec nudge |
| `spoof://10.20.0.2:443` | `spoof_carrier.rs` | IP-Spoofing raw-socket pipe (`RawSpoofEngine`) + WireGuard (MTU 1280) |
| `auto://HOST:PORT` | `transport.rs` | Automatic cascade: UDP+FEC -> Ktunnel -> WSS -> Camo/TCP |

## 2. Tunneling Engines, Wraps, Cluster Mesh & Micro-NLP

* **GRE Wraps & MTU (`l3_wraps.rs`)**: `direct`, `wss`, `6to4`, `4in6`, Path MTU Keeper with MSS clamping, `/30` pair allocator.
* **Spoof Carrier (`spoof_carrier.rs`)**: Native IPv4 raw-socket engine (`socket2` + `IP_HDRINCL`, RFC 1071 checksums), WireGuard X25519 keygen (RFC 7748), `spf1_` / `SPOOF1:` bundles, idempotent `forward.nft`, `SpoofTester`.
* **FRP & Backhaul Engines (`engines.rs`, `setup_bundle.rs`)**: Transactional setup (`UnitSwitchTx`), `hsh1_`/`bh1_`/`gh1_` bundles, FRP (`tcp`/`kcp`/`quic`/`websocket`), Backhaul (`tcp`/`tcpmux`/`ws`/`wss`/`wsmux`/`wssmux`/`udp` + UDP companion + live `connection_pool`), Auto Pool on port clash.
* **Xray REALITY & SSH Port-Forward (`xray_engine.rs`, `sshfwd.rs`)**: UUID v4 + X25519 REALITY keygen, 5 anti-censorship presets (`reality-vision`, `reality-grpc`, `reality-xhttp`, `ws-tls`, `kcp-noise`), Iran `dokodemo-door` bridge JSON, `vless://` URIs, locked `authorized_keys` SSH forwarding.
* **Live Carrier Swap (`carrier_swap.rs`)**: 4-phase coordinated Iran <-> Foreign swap (`foreign -> local -> verify -> automatic revert`).
* **Cluster Hub Mesh & Load Balancer (`cluster_mesh.rs`, `cluster_lb.rs`, `node_cluster.rs`)**: Signed HTTP/1.1 `/_hc` mesh (`X-Khaymali-Ts/Nonce/Sig`, stealth `404`), AES-256-GCM secret adoption, 5-mode TCP/nft Load Balancer (`failover`, `balance`, `sticky`, `latency`, `least`), weighted DNS rotation, node framing & RTT fleet probing.
* **Harsh-Network Micro-NLP (`harsh_nlp.rs`, wired live into `recovery.rs` & `control.rs`)**: Fixed-weight telemetry + log classifier for 6 regimes (`clean`, `congested`, `lossy_burst`, `mtu_blackhole`, `dpi_reset`, `severe_throttling`), Shadow default, automatic rollback on regression, 180s lockout, live RPC (`khaymali harsh-nlp status | mode shadow|active`).

## 3. Quick Usage Examples

```bash
# Kernel BBR/FQ tuning & tunnel doctor:
khaymali ops doctor
sudo khaymali ops tune --apply

# Multi-carrier Exit & Entry:
khaymali exit --listen 0.0.0.0:443 --udp-listen 0.0.0.0:444 --wss-listen 0.0.0.0:8443 \
  --key <EXIT_PRIV> --allow <ENTRY_PUB> --camo-secret <SEC> --camo-fallback <DECOY:443>

khaymali entry --key <ENTRY_PRIV> --exit-pub <EXIT_PUB> \
  --exit wss://<EXIT_IP>:8443 --exit udp://<EXIT_IP>:444 \
  --camo-secret <SEC> --camo-sni www.cloudflare.com --socks 127.0.0.1:1080 --pool 8

# Live Harsh-Network Micro-NLP inspection & control:
khaymali harsh-nlp status
khaymali harsh-nlp mode active

# FRP / Backhaul / Xray / Spoof / GRE / Cluster CLI:
khaymali setup iran --engine backhaul --transport tcpmux --local-pub <IRAN_IP> --ctrl-port 3080 --ports 443,8443 --plan
khaymali xray gen --preset reality-vision --side foreign --port 8443 --remote <FOREIGN_IP>
khaymali spoof gen --role local --local-ip <IRAN_IP> --peer-ip <FOREIGN_IP> --spoof-ips 1.1.1.1,8.8.8.8 --forward 443
khaymali carrier wrap 6to4 --iface gre-tunnel --local-inner 10.11.10.1 --peer-inner 10.11.10.2 --local-v4 <IRAN_IP> --remote-v4 <FOREIGN_IP>

# 200 & 300 concurrent-user harsh-network netem A/B stress test:
sudo bash scripts/stress_harsh_300_ab.sh target/release/khaymali /tmp/khaymali-ab
```
