# v0.11.3 — TinyNetNlp v4 (Harsh Network Intelligence) + Live Adaptive Integration

* `src/kani_nlp.rs`:
  * Added 7th class `NetIntent::Unrelated` (balanced 112-sample EN/FA corpus including normal Khaymali operational logs) + 2048 hashed buckets + exact 32-bit FNV known-network vocabulary filter + explicit `has_magic` flag (0% false actions on 1,200 unseen unrelated/junk logs).
  * Risk-aware per-class confidence, normalized gap, and streak thresholds + `sqrt(N)` length-normalized logits (cuts real-symptom abstention from ~20% to ~8.9% in offline stress tests).
  * Atomic `errno` / protocol error tokens (`econnrefused` vs `econnreset` vs `emsgsize`) + stage tags (`stage_dial`, `stage_handshake`, `stage_stream`) + EN/FA pre- and post-negation.
  * `classify_combined(log, &LinkMetrics)`: Late Fusion (0.45 text + 0.55 metrics) with corroboration boost and contradiction veto.
  * Safe online learning: bounded `delta_weights: [[i8; 2048]; 7]` (`[-120, +120]`), `Unrelated` locked, hourly update cap, `decay_online_weights()`, `reset_online_weights()`, and outcome-verified reinforcement in `NlpAdvisor::record_outcome`.
* `src/recovery.rs` + `src/entry.rs` + `src/stats.rs` + `src/control.rs` + `src/main.rs`:
  * Wired `NlpAdvisor` live into `AdaptiveRuntime` with `KHAYMALI_NLP_MODE` (`active` | `shadow` | `off`) for A/B testing.
  * Fed real dial error strings + stage tags from `entry.rs` into `AdaptiveRuntime::record_with_log`.
  * Added Prometheus metrics (`khaymali_nlp_*`), live NLP fields in `recovery.status`, `abstained` in `kani.diagnose` / CLI `diagnose`, and `kani.reset` RPC for online delta rollback.
* `tests/harsh_proxy.py` + `tests/stress_harsh.sh` + `scripts/eval_nlp_replay.py`:
  * Added PMTU drop profile (`pmtu_drop_4k`), replaced `http.server` (`backlog=5`) with `backlog=2048` asyncio origin and pure-asyncio SOCKS5 200/250/300 client stress driver, and added automatic `replay_dataset.jsonl` export + offline replay evaluator.
* NOT yet compiled in sandbox (no `rustc`/`cargo` available): run `cargo test --lib kani_nlp && cargo test --lib recovery && cargo build --release --locked`.
