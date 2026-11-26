# Khaymali v0.5.0 – Final Hardened & Adaptive Release Notes

## Summary of Fixes & Subsystems Implemented

### 1. Core Stability & Test Fixes
- **Bridge READY v2 Panic (`src/link.rs`):** Fixed plaintext slice length (`&out[BRIDGE_READY_V2.len()..n]`).
- **Bridge Connection Ordering & Spin-Loop (`src/bridge.rs`):** Authenticates with Entry before dialing Exit; aligned 16 KiB bidirectional copy buffers (`copy_bidirectional_with_sizes`); zero-byte immediate relay closure now penalizes Exit health (`FailureKind::Reset`) and preserves jittered backoff.
- **KANI TinyNetNlp (`src/kani_nlp.rs`):** Upgraded to margin perceptron (`TRAIN_MARGIN = 512`) and weighted current `extra_log` features 2x over historical `event_window` tokens so `tdd_sequence_and_online_adaptation` passes cleanly alongside all Persian/English symptom tests.
- **Health & Circuit Breaker (`src/health.rs`):** Removed bare TCP SYN/close active probes (eliminating DPI scanner patterns, false circuit closes behind L7 firewalls, and RTT/CUSUM pollution); prevented all-open Exit stampede; `probe_loop` now advances passive hysteresis ticks only.

### 2. Adaptive Recovery & Packet-Pattern Engine (`src/recovery.rs`, wired live into Data Plane)
- Added `AdaptiveRuntime` and `TransportEvent` telemetry sliding window wired into `entry.rs`, `bridge.rs`, `link.rs`, `forward.rs`, and `control.rs`.
- Classifies Early Reset, Handshake Timeout, Mid-Stream Stall, PMTU/Large-Frame Loss, Intermittent Loss, and Queueing Congestion with 2-observation hysteresis and cooldowns.
- Applies bounded, safe Data Plane controls automatically:
  - Dynamic chunk downsizing (`14 KiB -> 4 KiB -> 1200 B`) on PMTU/large-frame stalls, with gradual step-up recovery after 20 healthy events.
  - Microsecond transmit pacing under loss bursts (`0..2500 us`).
  - Dynamic concurrency capping under queueing congestion.
  - ±25% jittered reconnect backoff to break robotic DPI timing patterns.
- Exposed read-only via `status` and `recovery.status` Control API RPCs and Prometheus metrics.

### 3. Bottleneck Elimination & Reliability
- **Frame Alignment (`src/link.rs`, `src/camo.rs`, `src/bridge.rs`):** Aligned `CHUNK = 14 KiB` (14354 B on wire with header+tag) inside single Camo records (`DATA_CHUNK = 15360`) and 16 KiB Bridge/Channel-Binding buffers, eliminating fixed `(15000 + 1402)` double-splitting and reducing TCP-over-TCP HoL blocking.
- **Lock-Free-Wakeup `LinkPool` & On-Demand Burst Dialing (`src/entry.rs`):** Replaced `Arc<Mutex<mpsc::Receiver<Link>>>` with `LinkPool` (`StdMutex<VecDeque<Link>>` + pinned `Notify`), fixing negative `LINKS_READY` races and adding bounded on-demand burst dialing in Direct mode to eliminate tail-latency spikes under 50–300 concurrent clients.
- **Application-Level Pool Keepalive (`src/link.rs`, `src/entry.rs`, `src/exit.rs`):** Background sweeper sends `[0]` PING/PONG probes on idle pooled links to evict silently dropped NAT/DPI zombie connections before client `acquire()`.
- **Real L4 UDP Forward & Dual-Stack IPv6 UDP (`src/entry.rs`, `src/exit.rs`, `src/udp.rs`, `src/forward.rs`):** Implemented real `--forward .../udp` listener with per-client sessions, idle cleanup, quota and rate limiting; added dual-stack IPv4/IPv6 UDP relay (`IPV6_V6ONLY`) and IPv6 SOCKS5 `UDP ASSOCIATE` support; reused hot-path buffers to avoid per-datagram heap allocations.
- **Monotonic Token Bucket & Immediate Quota Cutoff (`src/forward.rs`):** Replaced 250ms capped sleep with monotonic `Instant`-based `TokenBucket` (accurate below 524 kbps without RTT jitter) and immediate bidirectional `Notify` cancellation on quota exhaustion.

### 4. DPI Camouflage Hardening (`src/camo.rs`, `src/exit.rs`)
- Valid ephemeral X25519 public keys in `key_share` via `snow` Curve25519 keygen.
- Chrome-like non-GREASE extension permutation, ALPS (`0x4469`), and `padding` (`0x0015`) placed before trailing GREASE.
- Deterministic Certificate record length per `--camo-sni` (`Sha256(sni)`) and exact 53-byte TLS 1.3 `Finished` records on both Server and Client flights.
- Lossless partial-read forwarding to decoy fallback, hard-capped fail-closed Replay cache (4096 entries), explicit `CLOCK_SKEW_DROPPED` telemetry, and authenticated `conn_sem` moved AFTER `camo::server()` so fallback probes never starve Exit capacity.

### 5. Control Plane, Systemd, TUI/Web & Kernel Tuning
- Escape-aware JSON string extractor in `src/control.rs` (`extract_json_str`).
- Added `RuntimeDirectory=khaymali`, `RuntimeDirectoryMode=0750`, and `--control /run/khaymali/<role>.sock` to all `deploy/*.service` units and `scripts/khaymali-manager` (plus `--require-channel-binding` and `--forward` support).
- Expanded `install.sh --tune` with `tcp_rmem`, `tcp_wmem`, `tcp_sack`, `tcp_keepalive_time=30`, `tcp_keepalive_intvl=10`, `tcp_keepalive_probes=3`, and `tcp_slow_start_after_idle=0`.
- Updated `scripts/khaymali-tui` and `scripts/khaymali-web` to compute live forward/user `tx_bps`/`rx_bps` and display real `transport`, `loss_pct`, `chunk_bytes`, and adaptive `recovery_pattern`.
- Added `scripts/verify_build_and_tests.sh` for one-command verification on Ubuntu with Rust 1.75+.

---

## v2 Core Engine Upgrades (Multiplexing, UDP Carrier, Rekeying & Smart Shaper)

### 6. Stream Multiplexing & Coordinated Rekeying (`src/mux.rs`)
- Added lightweight 5-byte framed stream multiplexer (`[cmd, stream_id, payload]`) running inside encrypted Noise_IK links (request type `[3]`).
- Up to **128 concurrent TCP streams** per warm Noise carrier (`--mux-carriers N`, default `4`, enabled by default; disable with `--no-mux`), eliminating per-connection TCP/TLS/Noise handshakes and cutting high-concurrency tail latency (`p95`).
- Transparent fallback to legacy single-stream `Link` if a carrier drops mid-open.
- **Automatic Coordinated Rekeying (`REKEY_MAX_BYTES = 512 MiB`, `REKEY_MAX_AGE = 15 min`):** Drains aging carriers via `CMD_REKEY` and rotates to a fresh ephemeral X25519 Noise_IK handshake for full Forward Secrecy and Post-Compromise Security.

### 7. Reliable Authenticated UDP Carrier Transport (`src/udp_transport.rs`, `src/transport.rs`)
- Added MTU-safe (1180 B payload), HMAC-SHA256 authenticated **Selective-Repeat ARQ** UDP transport (`udp://HOST:PORT`) with 32-bit SACK bitmaps, adaptive retransmission, and **session-ID roaming** across NAT rebinding.
- Eliminates TCP-over-TCP Head-of-Line blocking under packet loss while keeping full end-to-end Noise_IK encryption and Multiplexing on top.
- Usage:
  - Exit: `khaymali exit --listen 0.0.0.0:443 --udp-listen 0.0.0.0:443 --camo-secret <HEX> ...`
  - Entry / Bridge: `--exit udp://<EXIT_IP>:443` (can be mixed with TCP/Camo exits).

### 8. Smart Statistical Traffic Shaper (`src/shaper.rs`, `src/camo.rs`)
- Shapes initial-flight and interactive TLS 1.3 camouflage records toward realistic HTTP/2 record size buckets (`64, 128, 256, 512, 1024, 1400, 4096`) with randomized jitter and first-flight burst splitting, while keeping bulk transfer padding minimal (`<= 32 B`).

---

## v3 merge: Adaptive Decision / Pattern-Recovery / Bottleneck engine (`src/adapt.rs`)

Merged on top of the v3 core (mux keepalive/closed-watch, UDP RFC1982 seq + RTT-based RTO + per-IP session cap, forward half-close, health Open-cooldown guard, required `--camo-secret` for udp://). See `docs/ADAPTIVE.md`.
- Condition engine: normal / degraded / hostile / blackout / recovering (hysteresis, slow-start ramp),
  tuning of dial timeouts, pool size, link max-age, backoff, hedged dials and acquire deadline.
- Failure fingerprints (`connect_timeout`, `handshake_stall`, `early_reset`, `handshake_close`,
  `refused`, `unreachable`, `circuit_open`) and learned, persisted patterns (link kill-age, periodic outage).
- Bottlenecks: `pool_starved` (AIMD pool growth to `--pool-max`), `exit_slow` (growth frozen),
  `stale_pool`, `socks_saturated`.
- New flags: `--no-adapt`, `--pool-max N`, `--adapt-state FILE|off`; Control RPC `adapt.status`;
  metrics `khaymali_adapt_*`; tests `tests/chaos.sh` + 20 deterministic unit tests.
- Fixes: circuit cooldown capped during blackout, single overall deadline for mux+fallback open.


---

## Manager 0.4.0 / installer: operations hardening
`scripts/khaymali-manager` (new menu 10-17, new CLI: `update-manager|backup|restore|tune|tune-revert|tune-status|cleanup|notify-test`) and `install.sh`:
- **systemd unit hardening**: `StartLimitIntervalSec=0` + `RestartSteps/RestartMaxDelaySec` backoff, journald rate limit, `CapabilityBoundingSet`, `RestrictAddressFamilies`, `PrivateDevices`, `RuntimeDirectoryPreserve` (stopping one role no longer deletes another role's control socket), `StateDirectory` so the adaptive engine can really persist learned patterns (`--adapt-state /var/lib/khaymali-<role>/adapt.state`; before, the DynamicUser could not write `/var/lib/khaymali`).
- **Port-conflict detection** in the wizards (shows the owning process; optional kill with SIGTERM then SIGKILL; never offers for sshd/pid 1; recognises our own running unit).
- **Forward rules menu** with loop prevention (forward target = Exit tunnel port, or collision with SOCKS/bridge/metrics ports) and spec validation.
- **Validated config editor**: strict `KEY="value"` check (the file is sourced by root), automatic rollback on invalid file or failed restart.
- **Backup / restore** of `/etc/khaymali` (mode 600, last 10 kept, restore refuses archives with foreign paths).
- **Kernel tuning with a real revert**: original values saved once and restored, per-key support detection, native BBR check (`modprobe tcp_bbr`), status view. `install.sh --tune` no longer overwrites the saved originals on a second run; `--revert-tune` now restores them.
- **Opt-in scheduled restarts** via systemd timers (no cron needed), **weekly journal cleanup** timer.
- **Telegram alerts** (`khaymali-notify` + timer): service up/down, restart loops, adaptive `blackout`/`hostile`, boot report. Token is passed to curl on stdin (not visible in `ps`), config parsed as data, delivery through the Entry's own SOCKS5 -> direct -> optional user-supplied relay.
- **Safe self-update**: manager script is downloaded, validated (`bash -n`, marker, size), swapped atomically, previous copy restored on failure; latest release tag checked via the API.
- **Installer**: SHA-256 from GitHub release digest / `.sha256` / `checksums.txt` / `SHA256SUMS`; mismatch aborts, no checksum falls back to a source build (`--allow-unverified` to override); auto-installs curl when missing. Fixed: a fresh install exited silently under `set -e` (`backup_existing` returned 1 when nothing existed yet).
- Public-IP detection tries five services with IPv4 validation, flags private/NAT addresses; config dir is `0700`; actions logged to `/var/log/khaymali-manager.log`.
- New `tests/manager.sh` (34 offline checks), wired into `verify_build_and_tests.sh`.
