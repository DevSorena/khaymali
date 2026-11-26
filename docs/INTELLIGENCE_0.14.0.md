# Adaptive Network Intelligence v0.14.0

## Components

- `PredictiveEngine`: bounded trend projection; probability is available only through `RiskCalibrator` after fitting labeled horizon outcomes.
- `RiskCalibrator`: Platt scaling with strict sample/class minimums, holdout Brier/log-loss/ECE evaluation, versioned artifact persistence, and runtime reload.
- `AdaptiveController`: hysteresis and cooldown state machine; advisory only.
- `PathIntelligence`: independent EWMA severity/RTT/goodput/loss/jitter, evidence-aware ranking, bounded registry and explicit path removal.
- `PathRuntimeTelemetry`: independent 30-second per-path event windows in the recovery runtime; Bridge uses the selected exit address as path identity.
- `simulate_packet_twin`: deterministic offline packet/queue model with queue limit, capacity, seeded loss/jitter, outage, latency distribution and goodput.
- `AdaptiveExperimentManager`: under-tested-scenario selection and paired baseline/candidate configuration comparison using a common seed.
- `HardResourceBudget`: hard observation/experiment counters and estimated-memory quota.
- `NlpModelRollout`: isolated candidate training, holdout gate, promotion and rollback; `save_active_model`/`load_active_model` support explicit artifact persistence. `NlpAdvisor` loads the active model through `KHAYMALI_NLP_MODEL_PATH`; verified updates train a separate candidate and can persist it through `KHAYMALI_NLP_CANDIDATE_PATH`. Candidate promotion requires an independent labeled holdout via `khaymali promote-nlp-candidate HOLDOUT.tsv`, then writes a previous-model backup. `kani.reload` reloads the active artifact and `kani.rollback` restores the previous artifact. Candidate promotion requires both `KHAYMALI_NLP_MODEL_PATH` and `KHAYMALI_NLP_CANDIDATE_PATH` to be set and an independent holdout with at least five safe and five fault records.
The holdout TSV uses `log<TAB>class`, where class is one of `healthy`, `early_rst`, `byte_freeze`, `pmtu_drop`, `throttle`, `route_or_dns_fail`, or `unrelated`. Example:

```text
connection reset by peer<TAB>early_rst
user logged in config reload<TAB>unrelated
```

Candidate updates remain advisory and isolated until promotion. A promotion requires no accuracy regression, a configured minimum accuracy gain (CLI default 0.5 percentage points), and no false-positive increase above 0.25 percentage points. `kani.rollback` restores the previous active artifact.
- `TinyNetNlp` artifact API: versioned, bounded, validated serialization; atomic save; optional runtime persistence through `KHAYMALI_NLP_MODEL_PATH`.

## Runtime telemetry semantics

- RTT/baseline: measured from ConnectOk events.
- Jitter: EWMA of absolute differences between consecutive ConnectOk RTT observations.
- Goodput: EWMA of completed-stream bytes divided by elapsed time between StreamOk completion events.
- Per-path loss/retransmit: left at zero when no true per-path counters are supplied. Do not interpret zero as a measured guarantee of no loss.
- Entry/link events without path identity use `runtime-default`; Bridge exit events use the exit address as the path key.

## Calibration workflow

Prepare two independent TSV files, one row per sample. The holdout must contain at least five safe (`healthy`/`unrelated`) and five fault examples for model promotion:

```text
score<TAB>degraded_within_horizon
72.5<TAB>1
18.0<TAB>0
```

Fit on the training file and evaluate on the separate holdout file:

```bash
khaymali calibrate-risk train.tsv holdout.tsv /var/lib/khaymali/risk.model
```

Set `KHAYMALI_RISK_CALIBRATOR_PATH=/var/lib/khaymali/risk.model` before starting the service. The calibration label must use the same explicitly defined prediction horizon in both files. `intelligence.reload_calibrator` reloads the artifact through the local control socket.

## Offline experiments

`DigitalTwinConfig` controls packet size, link capacity, queue capacity, base latency, seed and outage period/length. `AdaptiveExperimentManager::compare_configs` evaluates baseline and candidate configurations under the same seed. It requires two experiment-budget units and stores a bounded observation.

The `khaymali intelligence-lab` CLI runs the deterministic offline twin. For example:

```bash
khaymali intelligence-lab --scenario all --steps 1000 --capacity-kbps 2500 --queue 64
```

## Model artifact

`KHAYMALI_NLP_MODEL_PATH=/var/lib/khaymali/nlp.model` loads a model at process startup and persists verified online updates. On Unix, the temporary artifact is created with mode 0600 before atomic rename. Keep the parent directory owned by the service account and not writable by untrusted users. Artifact version/dimensions/ranges/vocabulary are checked on load. Model updates remain disabled unless `KHAYMALI_NLP_ONLINE_LEARNING=1` is explicitly set. Candidate updates do not affect inference until the holdout promotion gate passes. `kani.reload` loads the configured model into the running AdaptiveRuntime after an operator has replaced the artifact.

## Validation

Run on a host with Rust 1.75+:

```bash
cargo generate-lockfile
cargo test --lib intelligence:: -- --nocapture
cargo test --lib kani_nlp:: -- --nocapture
cargo test --lib recovery:: -- --nocapture
cargo test --lib
cargo test --test neg_security
cargo build --release
bash scripts/verify_build_and_tests.sh
```

Then run `RUN_HARSH=1 bash scripts/verify_build_and_tests.sh` to execute the harsh loopback profiles at 200, 250 and 300 concurrent clients in Shadow mode. Capture separate Shadow/Active output directories and compare with `scripts/ab_compare.py`. These are loopback-only tests. No Rust build or real 300-client run is claimed from the preparation environment.
