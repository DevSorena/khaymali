# NLP reliability notes — v0.11.5

## Runtime mode
The NLP runtime defaults to `shadow`. Set `KHAYMALI_NLP_MODE=active` only after local validation to allow bounded parameter changes; `off` disables inference.

## Action semantics
`reduce_chunk_size` is the only NLP action in this set that directly changes a bounded runtime parameter. `recommend_exit_or_bridge` and `recommend_survival_fallback` are advisory outputs only; they do not claim a route switch or fallback transition.

## Online learning
Online learning is opt-in (`KHAYMALI_NLP_ONLINE_LEARNING=1`). It is still bounded by the existing hourly cap and delta clamps. Runtime calls require a stable streak and clean live telemetry. For production-grade causal attribution, collect a pre-action baseline and compare post-action telemetry over a fixed observation window before enabling this option.

## Temporal features
The runtime maps each actual `TransportEvent` to a fixed static token and pushes it into the bounded event window before classification. This is intentionally a compact event sequence, not a full HMM or sequence neural network.

## Replay evaluation
The JSONL evaluator accepts `log`, optional `expected`, and optional `metrics` fields. Metrics are passed to `classify_combined`; omitted fields default to no signal. Raw `stress_harsh.sh` logs are deliberately unlabeled because a profile-level label is not valid ground truth for every individual line; the evaluator reports their prediction distribution but excludes them from supervised accuracy. Add `expected` only after manual or independently derived annotation. Keep train and evaluation datasets disjoint. Do not split multiple lines from one incident across train and test.

## Build reproducibility
This source package does not include a generated Cargo.lock. Run `cargo generate-lockfile` with the pinned Rust toolchain, review the resolved dependency graph, commit Cargo.lock, then run `cargo test` and `cargo build --release`. This package does not claim Rust build success without those commands.
