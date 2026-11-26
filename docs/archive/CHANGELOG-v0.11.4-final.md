# v0.11.4 — final merge (base: v0.11.3-nlp-v4-harsh)

Two independent v4 builds were compared on the same offline benchmark (10 x 300 hostile log lines,
20 % junk/normal logs; a Python twin of each Rust model). v4-harsh was kept as the base:

| | v4 (Quick) | v4-harsh | **v0.11.4** |
|---|---|---|---|
| correct & acting on real symptom | 81.5 % | 86.1 % | **85.9 %** |
| abstained on real symptom | 12.1 % | 10.8 % | 11.0 % |
| wrong action on real symptom | 6.0 % | 2.8 % | **2.8 %** |
| action on junk/normal logs | 0.2 % | 6.5 % | **0.0 %** |
Fresh seeds: 83.8 % / 13.0 % / 3.0 % / 0.0 %.

Fixes on top of v4-harsh:
* kani_nlp: a fault verdict needs >=1 known network word, an errno token or a magic number
  (hex ids / bare numbers / "new client connected" no longer trigger actions); tests extended.
* recovery: KHAYMALI_NLP_MODE read once (OnceLock), not std::env::var on every event under the lock.
* main: `khaymali diagnose --stdin`; eval_nlp_replay.py uses it (1 process instead of 1 fork per line).
* scripts/ab_compare.py: shadow vs active side by side (ok %, p95) per profile/step.
NOT compiled in the authoring sandbox (no Rust toolchain).
