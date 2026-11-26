# Khaymali v0.11.5 — NLP Reliability & Recovery

## Correctness fixes
- Online-learning rollback now restores the immutable pretrained known-network vocabulary as well as the weight overlay.
- Runtime temporal tokens are fed from actual `TransportEvent` values into the bounded NLP event window.
- NLP runtime defaults to `shadow`; applying actions requires explicit `KHAYMALI_NLP_MODE=active`.
- Online learning is disabled by default and requires `KHAYMALI_NLP_ONLINE_LEARNING=1` plus clean live telemetry and a stable streak.
- Byte-freeze action is now named `reduce_chunk_size` and maps to a bounded chunk-size reduction; it no longer claims to perform a handover.
- Exit/bridge and survival-fallback outputs are explicitly named recommendations because route/fallback ownership remains in their respective controllers.
- Replay evaluation now supports optional numeric `LinkMetrics` and uses `classify_combined` through `diagnose --stdin-combined`.
- Runtime publishes the exact `LinkMetrics` snapshot consumed by NLP; harsh replay capture keeps runtime counters separate from classifier inputs.
- Replay parsing validates JSONL records, class names, metrics objects, process exit status, and exact output count.
- Verification script no longer references absent manager files and no longer suppresses integration-suite failures.
- Live stress helper refuses non-loopback SOCKS and target endpoints.

## Validation status
- Python syntax checks and shell syntax checks are run during packaging.
- Rust compilation and Rust tests require the Rust 1.75 toolchain and must be run on a machine with Cargo installed. They are not represented as passed by this archive.
- Stress testing is limited to local loopback fixtures; no public or third-party endpoints are targeted.
