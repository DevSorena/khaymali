# Khaymali v0.14.0 — Intelligence Completion

## Completed source changes
- Added labeled Platt calibration with holdout Brier/log-loss/ECE metrics, a strict 32-byte versioned calibrator artifact, startup load, and explicit hot reload. The predictive layer returns no probability until a minimum-size, two-class validation set is fitted; the existing trend score remains explicitly heuristic.
- Added deterministic packet/queue digital-twin simulation with bounded queue capacity, link service rate, seeded loss/jitter, outage windows, latency distribution, packet counters, and goodput estimate.
- Improved path ranking to account for measured goodput, jitter, loss, and evidence count rather than a near-zero throughput bonus.
- Added per-path runtime telemetry windows and per-path IDs for Bridge exit observations, including bounded LRU eviction.
- Added completed-stream goodput estimation and RTT-variation jitter estimation. Unmeasured packet loss/retransmission remain zero rather than being fabricated.
- Added an adaptive offline experiment scheduler and paired baseline/candidate configuration comparison under a shared deterministic seed.
- Added explicit byte and count budgets for observations/experiments.
- Added versioned TinyNetNlp model artifact serialization, strict dimensions/length/range/vocabulary checks, atomic replacement, restrictive Unix file mode, optional runtime load/save via `KHAYMALI_NLP_MODEL_PATH`, and explicit in-process model reload.
- Online learning now stages updates in an isolated candidate model; the active model is unchanged until an independent holdout passes accuracy and false-positive gates. Candidate artifacts can be persisted separately, promoted with an automatic previous-model backup, hot-reloaded, and rolled back. Persistence failure leaves the active model unchanged. Reset clears candidate/previous state and persists the baseline.
- Added tests for calibration, packet twin determinism, experiment scheduling/comparison, resource budgets, per-path isolation, and model artifact round-trip/corruption rejection.

## Important limitations
- Calibration is meaningful only when trained on representative, independently labeled data with a clearly defined prediction horizon. No probability is emitted before that fit.
- The digital twin is a deterministic synthetic queue/link model, not a packet-accurate Linux kernel, ISP, or Internet emulator.
- Runtime goodput is estimated from completed stream byte counts between completion events; it is not a continuously sampled NIC counter. Per-path packet loss and retransmit percentages remain unavailable unless a transport emits those counters.
- Per-path intelligence receives independent measurements for Bridge exit observations. Entry/link events without a stable path identifier remain under `runtime-default`.
- Experiment scheduling chooses among bounded offline scenarios. It does not generate arbitrary experiments, run shell commands, or touch remote systems.
- Model artifact format is versioned and validated, but active model hot-swap across already-running workers is not performed; a restart reloads the configured artifact.
- Rust compilation, Cargo tests, release build, and 200/250/300-client stress runs must be executed on a host with the pinned Rust toolchain. They are not claimed as passed in this environment.
