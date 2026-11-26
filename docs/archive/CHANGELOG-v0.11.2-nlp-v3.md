# v0.11.2 — TinyNetNlp v3 (rebuilt)
* Negation scope (no/without/بدون/هیچ), unit-aware numbers (ms, s, kb x1000/x1024), 4096-char input cap.
* Corpus 36 -> 72 samples (EN/FA), 14 epochs. Still 6 x 512 i16 = 6 KiB, zero deps, API unchanged.
* Evidence gate: abstain unless a known word backs the winner (or a magic number) and logit gap >= 256.
* Offline stress (10 sets x 300 hostile log lines, Python port bit-equivalent to the Rust model):
  accuracy 81% -> 91%, wrong non-healthy actions 398 -> 85 (-79%), junk safely ignored 73/300 -> 235/300.
  Cost: abstains on ~20% of real symptoms (=> keep_normal; NlpAdvisor + health.rs still act).
* NOT compiled here (no Rust toolchain in sandbox): run `cargo test kani_nlp` then `bash tests/stress_harsh.sh`.
