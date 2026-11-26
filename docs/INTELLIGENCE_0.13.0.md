# Khaymali v0.13.0 — Adaptive Network Intelligence

## Scope and safety boundary

The v0.13 intelligence layer is a bounded, advisory control-plane module. It does not open sockets,
run shell commands, alter routes, change authentication, weaken encryption, change allowlists, or
modify SSRF policy. The live `AdaptiveRuntime` feeds it observed telemetry and publishes summary
metrics. The intelligence report is not an instruction to perform a disruptive action.

## Included capabilities

1. **Predictive degradation scoring** — a bounded linear trend over recent severity scores. It emits
   current/projected severity and a boolean early-warning flag. The score is a heuristic, not a
   calibrated probability or a guarantee of future failure.
2. **Hysteretic adaptive state controller** — Normal/Watch/Degraded/Critical states, repeated evidence,
   stricter escalation to Critical, cooldown, and slower recovery transitions. It only changes its
   internal advisory state.
3. **Deterministic network digital twin** — in-process synthetic scenarios for clean, added latency,
   loss, jitter, throttling, and intermittent outage. It sends no packets and does not alter the host.
4. **Per-path intelligence** — bounded per-path predictor/controller state, EWMA severity/RTT/goodput,
   and a ranked path summary. The live recovery runtime currently reports its own `runtime-default`
   path; callers with independent path telemetry can use `NetworkIntelligence::observe` with distinct IDs.
5. **Explainable decisions** — evidence tags and advisory-only recommendations. Every explanation
   currently reports `executed=false` because this module never executes a transport action.
6. **Safe model promotion gate** — candidate model evaluation requires a minimum holdout size, no
   accuracy regression, no material false-positive regression, and a minimum score gain. Promotion
   and rollback are version decisions; actual TinyNetNlp weight serialization/deployment remains an
   explicit separate operation and is not silently performed by this gate.
7. **Resource budgets** — hard limits on path registries, history buffers, experiment history, and
   observation/experiment quotas.
8. **Experiment manager** — runs a bounded standard digital-twin suite and retains a fixed-size report
   history. It does not spawn processes or target remote systems.

## Runtime integration

`src/recovery.rs` feeds the intelligence layer from the real transport event window. Fields not
measured by the current runtime (for example, goodput and jitter when unavailable) are passed as zero;
the implementation does not fabricate measurements. The latest summary is included in
`AdaptiveSnapshot` and exported through Prometheus metrics:

- `khaymali_intelligence_mode` (0 normal, 1 watch, 2 degraded, 3 critical)
- `khaymali_intelligence_predicted_severity`
- `khaymali_intelligence_projected_severity`
- `khaymali_intelligence_degradation_likely` (0/1)
- `khaymali_intelligence_path_score_tenths`

The live integration is observation-only. Existing recovery logic remains the owner of bounded
transport changes. The new predictor/controller does not independently trigger handover, route
switching, survival fallback, or other disruptive operations.

## Public Rust API

The module is exposed as `khaymali::intelligence`:

- `NetworkSample` — validated numeric observation
- `PredictiveEngine` — bounded trend projection
- `AdaptiveController` — hysteretic state machine
- `PathIntelligence` — per-path EWMA and ranking
- `simulate_twin` / `TwinScenario` — offline deterministic simulation
- `explain` / `DecisionExplanation` — human-readable evidence
- `SafeLearningGate` / `CandidateEvaluation` — generic promotion/rollback decision gate
- `NlpModelRollout` — isolated TinyNetNlp candidate training, holdout evaluation, promotion, rollback
- `ResourceBudget` / `ExperimentManager` — bounded experiment execution
- `NetworkIntelligence` — unified per-path observer

## Validation

Run on a host with the project's pinned Rust toolchain:

```bash
cargo test --lib intelligence:: -- --nocapture
cargo test --lib
cargo test --test neg_security
cargo build --release
bash scripts/verify_build_and_tests.sh
```

The test suite includes deterministic predictor, hysteresis, path ranking, digital-twin, explanation,
generic learning-gate, TinyNetNlp candidate-rollout/rollback, resource-budget, and unified-observer
tests. These tests must be executed before claiming a verified release. This source archive was
prepared in an environment without Rust/Cargo; therefore no Rust compilation or Cargo test result is
claimed here. No generated Cargo.lock is included; run `cargo generate-lockfile`, review the result,
and commit it before a reproducible release build.

## Limits

- The predictor is a small trend heuristic, not an ML probability model.
- Path quality ranking is relative to observed telemetry and should be evaluated on representative
  paths before being used for selection.
- The digital twin is a synthetic model, not a packet-accurate emulator of the kernel, ISP, or WAN.
- The learning gate validates candidate metrics but does not itself train, serialize, or hot-swap the
  TinyNetNlp model.
- Runtime goodput and jitter are not currently collected in all event paths; unavailable fields remain
  zero until instrumentation is added at their true measurement points.
