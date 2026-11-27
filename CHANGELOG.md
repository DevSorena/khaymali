# Changelog

All notable changes to Khaymali Tunnel are documented here. Historical version changelogs and audits (`v0.5.0` through `v0.14.0`) are preserved in [`docs/archive/`](docs/archive/).

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
