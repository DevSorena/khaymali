# Project memory (read this first when continuing work)

Last updated: 2026-11-28, after the v0.22.1 hardening pass. Keep this file short and factual;
update it at the end of every work round.

## What it is
Khaymali Tunnel: a Rust (single `khaymali` binary, edition 2021, toolchain pinned to 1.85.0) censorship-
circumvention tunnel. Entry (Iran) <-> optional Bridge <-> Exit (abroad), Noise_IK, TLS camouflage, mux +
session-resume, adaptive recovery, pool/autopilot, Tunneling Suite (WS/WSS, SSH, Spoof+WG, GRE/FOU wraps,
FRP/Backhaul/Xray managers, Cluster Mesh/LB), Micro-NLP (`harsh_nlp.rs`, shadow by default), backups, Telegram
bot. Web panel and `customers.rs` were removed in 0.22.0 and must stay out.

## Layout
- `src/` 50+ modules (~33k lines). Entry points: `main.rs` (CLI/`Args`), `entry.rs`, `exit.rs`, `bridge.rs`.
  NLP: `kani_nlp.rs` (text/telemetry classifier), `harsh_nlp.rs` (6 regimes, wired in `recovery.rs`,
  RPC in `control.rs`, env `KHAYMALI_NLP_MODE=shadow|active|off`).
- `tests/` loopback e2e (`integration`, `eof_e2e`, `pool_e2e`, `autopilot_e2e`, `khaymali_suite_e2e`, `chaos`,
  `netem`, `stress`, `stress_harsh`), `neg_security.rs`, `harsh_proxy.py` (userspace impairment proxy),
  `scripts_selftest.sh` + `tools/mini_socks5.py` (tests the test tooling, no binary needed).
- `scripts/` `server_verify.sh` (everything root-only, one command), `real_path_check.sh` (two real servers),
  `stress_live_300.sh` (loopback-only load generator), `stress_harsh_300_ab.sh` (netns + netem A/B),
  `ab_compare.py`, `check_baseline_regression.py`, `eval_nlp_replay.py`, `khaymali-manager`, `khaymali-tui`.
- `docs/RELEASE_GUIDE.md` is the release procedure. `RELEASE_STATUS.txt` is the honest test status.

## Verified vs not verified (as of this round)
Verified earlier (1 CPU core, Rust 1.75 + older crates): 163 unit + 22 security tests, eof/pool/autopilot/
integration/suite e2e, manager 43/43, CLI smoke, harsh loopback stress (~89% ok over 15,000 requests/mode).
Verified this round (no compiler available): shell/Python syntax, `scripts_selftest.sh` 11/11, raw-socket
spoof primitive, `systemd-analyze verify` on the three units, `real_path_check.sh` against a local SOCKS5.
NOT verified: any Rust change since 0.22.1 (none was made), root-only features on a real host, real Telegram,
real Iran<->abroad path, `chaos.sh`/`netem.sh`/`stress.sh`/`stress_harsh_300_ab.sh` on a real host,
multi-core stress, a real PMTU blackhole (the synthetic `pmtu_drop_4k` profile fails in both modes by design
of the proxy), and any benefit of active NLP over shadow (A/B shows noise-level difference).
=> `sudo bash scripts/server_verify.sh` closes most of this in one run.

## Decisions / conventions
- Never run the load generator against non-loopback targets (guard in `stress_live_300.sh`); real-path tests
  put the origin on the Exit's loopback and reach it through the tunnel.
- Keep NLP in shadow by default; enable active only if `ab_compare.py` gate passes on `clean`.
- Tokens/secrets never on a command line (curl `-K -` config, env, `0600` files).
- `install.sh` must not fetch executable helpers from `main` over a pinned/verified install.
- Every change to Rust needs `cargo test --release --locked` before it ships; scripts need `bash -n`.

## Open items (next round)
1. Run `server_verify.sh` (+ `real_path_check.sh`) and paste results into `RELEASE_STATUS.txt`.
2. Real PMTU blackhole test on a host with a controllable MTU path; decide on a keepalive-size probe fix.
3. NLP: label a real replay dataset (`make_annotation_set.py`) before touching `harsh_nlp.rs` weights.
4. Review `unwrap()` use on network paths (`mux.rs`, `session_resume.rs`, `health.rs`, `cluster_mesh.rs`);
   most are probably poisoned-lock unwraps, confirm and convert hot-path ones.
5. Consider a multi-core-aware load generator (the Python origin and generator are the likely bottleneck).
