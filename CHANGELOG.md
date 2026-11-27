## [0.22.0] - Pure Tunneling Edition (Web Panel Stripped & Live Micro-NLP Integration)

- **Pure Tunneling Only**: Removed the bundled `panel/` directory (~37 MB Go web panel binaries & source), `src/customers.rs` (reseller billing/quota module), and all panel-only HTTP/UI hooks from `ops_suite.rs`, `node_cluster.rs`, `main.rs`, and `scripts/khaymali-manager`.
- **Live Harsh-Network Micro-NLP Wiring**: Connected `harsh_nlp::HarshNlpController` directly into `AdaptiveRuntime` (`src/recovery.rs`) and Unix-socket RPC (`src/control.rs`: `harsh_nlp.status`, `harsh_nlp.mode`), controllable live via `khaymali harsh-nlp status` and `khaymali harsh-nlp mode shadow|active`.
- **Manager & CLI Completion**: Updated `khaymali --help` (`usage()`) to document the complete tunneling command set and added an interactive `Tunneling Suite` (`ts`) menu in `scripts/khaymali-manager` (100% ASCII, passing `tests/manager.sh`).

## [0.20.0] - Complete Khaymali Tunneling Suite Port (Phases 1-6) & Harsh-Network Micro-NLP

### Phase 3: Cluster Load Balancer, Multi-Hub Sync, DNS Rotation & Node Fleet
- **Cluster LB, Sync & DNS (`src/cluster_lb.rs`)**: 5 LB scheduling modes (`failover`, `balance`, `sticky`, `latency` with streak=10 hysteresis, `least`), live async Tokio TCP LB forwarder, deterministic `127.10.x.y` private bind allocator, `frps`/`backhaul` bind rewriters, nftables LB rule generator, AES-256-GCM sealed multi-hub tunnel delivery, and weighted multi-hub DNS rotation.
- **Node Link, Relay, Migration & Fleet (`src/node_cluster.rs`)**: Bounded JSON `NodeFrame` framing over Tokio, HMAC-SHA256 challenge auth, strict API allowlist HTTP relay, signed `NodeMigrateOffer` zero-downtime migration, and `NodeFleet` registry with live TCP latency probing.

### Phase 4: SSH Forward, Xray-Core Engine, Sentinel, Full Doctor, Kernel Perf & Hardening
- **SSH Forward & Bagher Key Lock (`src/sshfwd.rs`)**: `SshFwdConfig` persistence, locked `authorized_keys` (`command="/bin/false",restrict,port-forwarding` + `permitopen`), legacy key lock upgrader, systemd unit generator, and companion `frps` config.
- **Xray-Core Engine (`src/xray_engine.rs`)**: UUID v4 & REALITY X25519 keygen, 5 censorship-resistant presets (`reality-vision`, `reality-grpc`, `reality-xhttp`, `ws-tls`, `kcp-noise`), `XrayFragment`/`XrayNoise`, full Foreign server & Iran `dokodemo-door` bridge JSON renderer, and `vless://` client URI builder.
- **Ops Suite (`src/ops_suite.rs`)**: Sentinel health/port/eligibility, full kernel `DoctorReport` (`ip_forward`, `rp_filter`, BBR, `fq`, PMTU), `PerfConfig` sysctl BBR+FQ+buffer optimizer, and lock-free `InflightLimiter` hardening.

### Phase 5: Customer Quotas, Rate Limits & Traffic Accounting
- **Customers, Limits & Usage (`src/customers.rs`)**: Multi-engine customer registry (`customers.json`, `hsell-{cid}-{lid}`), expiry & quota enforcement, `LimitRule` (`daily`/`weekly`/`monthly` resets), idempotent `nftables` counter/drop tables, `tc` HTB bandwidth policing, and wrap-safe `UsageStore` (`traffic_peers.json`).

### Phase 6: Compact Harsh-Network Micro-NLP & 200/300 Concurrent-User Netem A/B Suite
- **Micro-NLP Controller (`src/harsh_nlp.rs`)**: Zero-dependency fixed-weight classifier fusing telemetry (`rtt`, `jitter`, `loss`, `retransmit`, `disconnects`, `big_pkt_drop`) + log cues into 6 harsh regimes (`Clean`, `Congested`, `LossyBurst`, `MtuBlackhole`, `DpiReset`, `SevereThrottling`), emitting concrete tuning (`carrier`, `chunk_bytes`, `pacing_kbps`, `fec_parity_pct`, `mtu`), with **Shadow mode default**, **automatic rollback** on regression, and **180s cooldown lockout**.
- **200/300 Stress & Netem A/B Harness (`scripts/stress_harsh_300_ab.sh`)**: Network-namespace + `tc netem` test rig (`good`/`bad`/`harsh` profiles at 200 & 300 concurrent clients) comparing Shadow vs Active Micro-NLP with tabular & JSON metrics (goodput, p50/p95/p99, success rate).

## [0.19.0-phase1-phase2] - Khaymali Port Phases 1 & 2

### Phase 1: Real Spoof Carrier, Live Cluster Mesh & Live Carrier Swap
- **Spoof Carrier (`src/spoof_carrier.rs`)**: Full port of Khaymali `spoof.go` & `spoof_tester.go`, including `spoof.json` persistence, reserved port protection, idempotent `forward.nft` with bidirectional MSS clamping, UFW hooks, WireGuard handshake freshness check, Khaymali `spf1_` bundles (plus backward-compatible `SPOOF1:`), pure-Rust constant-time X25519 pubkey derivation (RFC 7748 verified), and native `RawSpoofEngine` over `socket2` (`IP_HDRINCL`, RFC 1071 checksums) for UDP/TCP/ICMP spoofing.
- **Cluster Mesh (`src/cluster_mesh.rs`)**: Real Tokio HTTP/1.1 mesh server & client on `/_hc/hello`, `/_hc/beat`, `/_hc/adopt` with Khaymali `X-Khaymali-Ts`/`Nonce`/`Sig` HMAC-SHA256 headers, stealth `404` on invalid/replayed requests, pure-Rust AES-256-GCM `sync_seal`/`sync_open` (verified against OpenSSL), `hc1_` join codes, transitive `mesh_meet`, graceful `bye`, EWMA link bps tracker, and 3s heartbeat loop feeding DNS writer election.
- **Live Carrier Swap (`src/carrier_swap.rs`)**: `CarrierChoice` parser, atomic file+unit `UnitSwitchTx` with full rollback, 4-phase Iran<->Foreign `execute_live_swap` coordinator (`foreign -> local -> verify -> automatic revert`), `ForeignSwapAgent` HTTP endpoints (`/api/peer/swap-carrier`, `/api/peer/swap-status`), state persistence (`carrier_swap.json`, `tunnel_links.json`), and manual bundle fallback.

### Phase 2: FRP & Backhaul Engine Managers, Setup Bundles & Auto Pool
- **Setup Bundles (`src/setup_bundle.rs`)**: Full `hsh1_`, `bh1_`, and `gh1_` encode/parse/apply (`+udp<port>` companion, `fou<p1>-<p2>`, `tr-<transport>`), port range & mapping parser (`443, 8080-8090, 2083=8443`), `rewrite_frpc_toml_ports` carrying over per-proxy options, and UFW `ufw.opened` tracking.
- **Engine Managers & Setup (`src/engines.rs`)**: FRP (`frps`/`frpc` TOML for `tcp`/`kcp`/`quic`/`websocket` + PROXY protocol v1/v2, bandwidth cap, TCP health checks), Backhaul (`backhaul-server`/`backhaul-client` TOML for all 7 transports, flat+sectioned TOML parser, live `connection_pool` 1..64 tuning, `backhaul-udp-*` companion), transactional Iran/Foreign setup planner, and `auto_pool_for_clash` / `undo_auto_pools`.

# Changelog

All notable changes to Khaymali Tunnel are documented here. Historical version changelogs and audits (`v0.5.0` through `v0.14.0`) are preserved in [`docs/archive/`](docs/archive/).

## [0.18.0] - Complete Khaymali Tunneling Suite Port

### Added
- `src/ws_transport.rs`: Pure-Rust RFC 6455 WebSocket (`ws://`) & WSS-over-Camo TLS (`wss://`) carriers with HMAC-SHA256 `X-Khaymali-Auth`, Ping/Pong keepalive, Decoy fallback on WSS, and Exit listeners (`--ws-listen`, `--wss-listen`).
- `src/ssh_carrier.rs`: Bagher SSH tunnel carrier (`ssh://[user@]host[:ssh_port][/remote_port]`) solving OpenSSH `ssh -N` Nagle latency via session-exec `TCP_NODELAY` nudge, IPv6 bracketed `known_hosts`, and multi-link port conflict detection.
- `src/spoof_carrier.rs`: Spoof IP-spoofing pipe + WireGuard overlay carrier (`spoof://10.20.0.2:443`), `spoof-core` JSON, `wg-spoof.conf` (MTU 1280), nftables forwarding rules, and `SPOOF1:` setup bundles (`khaymali spoof gen|parse`).
- `src/l3_wraps.rs`: All 4 Khaymali GRE wraps (`direct` proto 47, `wss`, `6to4` SIT proto 41 + `ip6gre`, `4in6` public IPv6 `ip6gre`), persistent `PathMtuKeeper` (`1380 -> 1360 -> 1340 -> 1300 -> 1280` + TCP MSS clamp), collision-free `/30` `GrePairAllocator`, and `CarrierAdvisor` (`khaymali carrier wrap|mtu|pair|swap`).
- `src/dial_route.rs`: Smart Dial Route (`auto | gre | public`) with automatic GRE->Public fallback, 5 consecutive healthy GRE checks to return, and 30-minute failback lock (`khaymali dial status|set`).
- `src/pathtest.rs`: End-to-end multi-carrier PathTest & Benchmark (`khaymali pathtest serve|run <pt1_CODE>`) testing TCP, UDP, Camo, WS, WSS, UDP+FEC, Ktunnel, TCP over IPv6, and SSH with RTT, Jitter, Loss, Mbps, and 0-100 Khaymali quality scoring.
- `src/revpath.rs`: 6-layer Reverse-Path Doctor & safe Auto-Fix (`khaymali revpath check|fix`) classifying all 11 Khaymali verdicts (`HEALTHY`, `RP_FILTER`, `SRC_SELECT`, `NO_RETURN_ROUTE`, `FW_INPUT`, `MTU_BLACKHOLE`, `CONNTRACK_INVALID`, `ISP_ICMP_ONE_WAY`, `ISP_GRE_BLOCK`, `CLOUD_SG`, `UNKNOWN`).
- `src/cluster_mesh.rs`: Iran-to-Iran Hub Mesh HMAC-SHA256 signed heartbeats with anti-replay nonce cache, emergency DNAT+MASQUERADE hub-forward rules (`khaymali mesh hub-fwd`), deterministic single DNS Writer election, `A`/`AAAA` failover & balance records, and Cloudflare `curl -K -` config generation.
- `src/rescue.rs`: Passive one-way block detector (`khaymali rescue check`) and loopback Tunnel Egress SOCKS5 Bridge (`--egress-bridge` / `khaymali rescue egress`) restricted to `api.telegram.org:443` and `api.cloudflare.com:443` with `--alert-proxy` integration.
- `src/watchdog.rs`: Upgraded with 3-Layer Tunnel Health (`service + session + data probe` -> `PASS | FAIL | UNREACHABLE`, `khaymali health`) and Per-Exit exponential backoff watchdog (`3m -> 6m -> 12m -> 30m`).
- Extended `src/transport.rs`, `src/transport_engine.rs`, `src/autopilot.rs`, `src/control.rs`, `src/entry.rs`, `src/exit.rs`, `src/bridge.rs`, `src/stats.rs`, `src/main.rs` with full scheme routing and zero extra crate dependencies.

## [0.17.0] - Multi-Exit pool, Autopilot, alerts

### Added
- `src/pool.rs`: multi-Exit pool policy. `--pool-mode failover|balance|sticky|latency|least`, `--failback auto|manual`, per-exit options `;w=N;p=N;max=N;standby;drain`. Live control: `khaymali pool status|drain|undrain|failback`. Without these flags behaviour is unchanged.
- `src/autopilot.rs`: `--autopilot` (`--ap-down`, `--ap-cooldown`, `--ap-per-day`, `--ap-no-path-test`, `--ap-quiet FROM-TO`, `--ap-carriers`, `--ap-state`). A tunnel down for N minutes is path-tested over every allowed carrier, moved to the fastest one, verified for 45 s and rolled back on failure; failed carriers go last for 6 h; max 3 carriers per run. History: `khaymali autopilot`.
- `src/alerts.rs`: `--alert-webhook URL`, `--alert-telegram BOT_TOKEN:CHAT_ID` (down / recovered / switched). Alone, they run Autopilot in monitor-only mode.
- `Exits::force`, live-link counting per Exit (`Link::with_guard`), control RPCs `pool.status|drain|undrain|failback`.
- Tests: 17 unit tests, `tests/pool_e2e.sh`, `tests/autopilot_e2e.sh`.

### Notes
- Autopilot needs one `--exit` per carrier (tcp, `udp://`, `ktunnel://`) and an Exit listening on each.
- `sticky` has no client identity at link-dial level yet.
- Quiet hours use `KHAYMALI_TZ_OFFSET_MIN` (e.g. 210 for Iran).

## [0.16.0] - One-command setup, clock guard, live dashboard

### Fixed (found in the first real Entry <- Bridge -> Exit test)
- Manager `role: unbound variable` in `apply_role` (line 83); `install.sh` now always installs the latest manager/TUI.
- Clock skew silently killed every Bridge link (`timestamp skew 1093s`): `status`/`doctor` show the skew, `fix-clock` command, automatic `ktime` cron on servers without NTP, clearer error text in the binary.
- Duplicate keys in `ALLOW`/`ALLOW_BRIDGE` (deduplicated on every edit; adding an existing key is refused).
- `Bridge`/`BRIDGE` input accepted (case-insensitive menu choices and modes).
- Garbled `...`/`/1000` characters: the manager is pure ASCII, the TUI falls back to ASCII on non-UTF-8 terminals (`--ascii`).
- TUI sidebar actions now call the manager (Setup Iran/Kharej, Update, Optimize were using an outdated wizard).

### Added
- `install.sh --join CODE` / `--join-bridge CODE`: Exit prints one command; Iran pastes it; keys are pre-exchanged.
- `khaymali-manager push user@ip`: install on Iran over SSH when GitHub is blocked.
- Automatic DIRECT/BRIDGE choice from a path test; multi-Bridge failover codes (menu 8 -> n).
- `khaymali ui` / `khaymali menu` sub-commands.
- TUI keys: space start/stop, R restart, l link, c clock.

### Changed
- Default link pool 8 -> 16 (faster ramp-up; Bridge test started at ~4.7 MB/s), `--pool-max 128`.
- Stronger sysctl tuning profile (32 MB buffers, notsent_lowat, wider port range).

## [0.15.1] — Runtime safety envelope, model accuracy, honest A/B

> Not compiled in the preparation environment (no Rust toolchain). Run `bash scripts/verify_build_and_tests.sh` before tagging.

### Fixed
- **fsync under the runtime lock (`src/kani_nlp.rs`, `src/recovery.rs`):** hourly decay and candidate saves no longer write files inside `gate()` / `record_outcome()`. They serialize to bytes (`PendingWrite`); `AdaptiveRuntime` drops its lock first and writes via `spawn_blocking` (inline outside Tokio). Failures are counted in `khaymali_nlp_persist_failures_total`. Rare operator RPCs (promote/rollback/reset) still write synchronously.
- **Promotion judged on its own training data:** the candidate records its learning stream (`<candidate>.learned.txt`, bounded 4096 lines); `promote-nlp-candidate` refuses with `HoldoutOverlapsTraining` if > 5 % of the holdout overlaps it, and prints the overlap.
- **NaN-unstable sorts (`src/intelligence.rs`):** path ranking and latency percentiles use `total_cmp` with deterministic tie-breaks.

### Model (TinyNetNlp v4.3)
- `dropped/drop/drops` contribute only bigrams, so "speed dropped" is no longer read as MTU.
- Stage-qualified timeout feature (`stage_stream` / `stage_dial` / "mid stream").
- Contrast clauses (`but/however/ولی/اما`): if the clause after the marker contains a fault cue, only that clause is classified; a reassuring tail ("slow but alive") keeps the whole sentence.
- +19 targeted samples (corpus 132; class-interleaved rounds of variable length).

Offline benchmark (Python twin rebuilt from the final `kani_nlp.rs` text, including its corpus; 10 × 300 hostile lines, 20 % junk/normal logs):

| | v0.15.0 | **v0.15.1** |
|---|---|---|
| correct & acting | 85.9 % | **91.9 %** |
| abstained on real symptom | 11.0 % | **6.3 %** |
| wrong action on real symptom | 2.8 % | **1.6 %** |
| action on junk / normal logs | 0.0 % | 0.0 % |
| fresh seeds: correct / wrong | 83.8 / 3.0 % | **89.7 / 2.0 %** |
| never-seen templates: correct / wrong | 73.3 / 0.0 % | **86.4 / 0.0 %** |

These are synthetic logs. Hand-annotated real logs remain the only valid acceptance data.

### Runtime safety envelope (`src/recovery.rs::NlpActionGuard`)
- At most 6 NLP-applied knob changes per rolling minute; one change under evaluation at a time.
- Pre-action baseline (window success ratio, goodput) stored with every change.
- Automatic revert after ≥ 8 events (or 30 s) when success drops ≥ 10 points or goodput ≥ 25 %. Only knobs NLP still owns are restored, so a newer rule-engine decision is never undone. The action kind is then locked for 10 minutes and its learning label is dropped.
- `ReduceChunkSize` steps 14 KiB → 4 KiB → 1200 B instead of jumping straight to survival size.
- One rate-limited (2 lines/s, separate budget) explanation line per change: action, intent, confidence, knob before → after, top evidence words with weights, metrics.
- New metrics, also in `recovery.status`: `khaymali_nlp_reverts_total`, `khaymali_nlp_rate_limited_total`, `khaymali_nlp_persist_failures_total`.

### Tooling
- `tests/stress_harsh.sh`: `REPEATS` (default 3) per profile/step; NLP counters attached to each result.
- `scripts/ab_compare.py` rewritten: medians over repetitions; p95, p99, goodput, NLP actions/reverts; "better/worse" only beyond the run-to-run spread; exit 1 when `active` is worse on `clean`.
- `scripts/make_annotation_set.py`: de-duplicated sampling for hand labelling, plus a template-grouped holdout/dev split in the `promote-nlp-candidate` format.
- Digital twin: seed-derived outage phase and per-period jitter (still deterministic).
- `verify_build_and_tests.sh` and CI run the `v0151_` regression tests; `RUN_AB=1` runs the full A/B.
- Tests that construct `NlpAdvisor` serialize on a shared lock (no environment-variable races).

## [0.15.0] — GitHub-Ready Adaptive Network Intelligence

### Critical Correctness & Security Fixes
- **Locked `Unrelated` class in online learning (`src/kani_nlp.rs`):** `train_online_verified` excludes `NetIntent::Unrelated` from rival-class weight updates so `delta_weights[Unrelated]` and `delta_bias[Unrelated]` remain strictly zero and persisted candidate artifacts always pass loader validation.
- **Zero false positives on bare numbers (`src/kani_nlp.rs`):** `no_known_evidence` requires at least one known network word or atomic `errno` token (`known_words == 0 && !ex.has_atomic`); bare PIDs/ports/hex strings like `"16384"` or `"0x7f3a 0xdeadbeef 12345"` classify safely as `Unrelated` (`KeepNormal`).
- **Rollback preserved across reload (`src/kani_nlp.rs`):** `reload_configured_model` retains both the replaced in-memory model and `.previous.model` on disk so `kani.rollback` remains available after `promote-nlp-candidate` + `kani.reload`.
- **Artifact integrity & durability (`src/kani_nlp.rs`, `src/intelligence.rs`):** `KTMNLP01` v2 adds an 8-byte SHA-256 trailer (backward-compatible with v1 reads), temp-file cleanup on write/rename error, and Unix parent-directory `fsync`.
- **Configured model loading in CLI & RPC (`src/main.rs`, `src/control.rs`):** `diagnose` (single, `--stdin`, `--stdin-combined`) and `kani.diagnose` now honor `KHAYMALI_NLP_MODEL_PATH` via `TinyNetNlp::load_configured_or_pretrained()`.

### Adaptive Intelligence & Telemetry Completion
- **Per-path Entry + Bridge intelligence (`src/entry.rs`, `src/bridge.rs`, `src/health.rs`):** Entry `dial_once` records per-exit path IDs and both Entry/Bridge feed scores into `Exits::update_path_intel`. Opt-in `KHAYMALI_PATH_INTEL=active` (default `shadow`) applies a bounded ±20% soft tie-breaker on `Closed` circuits with `>=5` observations without bypassing circuit breakers or hysteresis.
- **Windowed goodput & real jitter/UDP loss (`src/recovery.rs`, `src/udp_transport.rs`, `src/stats.rs`):** Replaced single-gap goodput with a 5-second sliding byte-completion window stable under 200–300 concurrent clients; wired `ewma_jitter_ms` into `LinkMetrics.jitter_ms`; published real `UDP_LOSS_PER_MILLE` when UDP sessions are active.
- **Automatic calibration collector (`src/intelligence.rs`, `src/control.rs`):** Added bounded `CalibrationCollector` (30s horizon) and control RPCs `intelligence.paths` and `intelligence.export_calibration`.
- **Unified `src/intelligence.rs` & realistic packet twin:** Removed duplicate legacy primitives, migrated `NetworkIntelligence` to `HardResourceBudget`, added `offered_load_kbps` + bounded `service_credit` to `simulate_packet_twin`, and added `--offered-kbps` / `--compare-capacity-kbps` to `khaymali intelligence-lab`.
- **Built-in `khaymali doctor`:** Local zero-dependency host/clock/ulimit/loopback/artifact readiness check.

### GitHub & Deployment Readiness
- Added `.gitignore`, `.github/workflows/ci.yml`, `.github/workflows/release.yml` (static musl `amd64`/`arm64` + provenance attestation), `.github/ISSUE_TEMPLATE/` (with mandatory key-redaction checkbox), hardened `deploy/systemd/*.service`, `deploy/env/*.env.example`, and `deploy/grafana/khaymali-dashboard.json`.
- Fixed `scripts/ab_compare.py` newline & zero-division handling and added `LABEL_FROM_PROFILE=1` replay labeling in `tests/stress_harsh.sh`.
