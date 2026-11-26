# Khaymali v0.13.0 — Adaptive Network Intelligence

## Added
- Bounded predictive degradation scoring with trend projection (heuristic, not probability).
- Hysteretic Normal/Watch/Degraded/Critical advisory controller with cooldown and repeated-evidence gates.
- Deterministic offline digital-twin scenarios for latency, loss, jitter, throttle, and intermittent outage.
- Per-path EWMA profiles and path ranking with hard registry bounds.
- Explainable advisory decisions with evidence tags and explicit `executed=false` semantics.
- Candidate-learning promotion gate with holdout-size, accuracy, false-positive, and rollback checks.
- Bounded resource budgets and an experiment manager with fixed-size history.
- Live observation integration in `AdaptiveRuntime` and Prometheus intelligence metrics.
- New unit tests for all intelligence primitives.

## Safety and limitations
- Intelligence remains observation-only; it does not perform route switching, handover, or survival fallback.
- Synthetic digital-twin experiments are local deterministic calculations and do not emit network traffic.
- Unmeasured runtime telemetry (goodput/jitter) is not fabricated.
- Rust build and Cargo tests were not executable in the preparation environment because Rust/Cargo are absent.
