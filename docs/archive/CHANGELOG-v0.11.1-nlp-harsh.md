# v0.11.0 + TinyNetNlp v2 / harsh stress (merge notes)

* `src/kani_nlp.rs`: rebuilt (API-compatible: `new_pretrained`, `classify`, `train_sample`, `push_event_token`,
  `NlpPrediction{intent,confidence,action}` + new `abstained`). 512 buckets (~6 KiB), Persian normalisation,
  log-noise stripping, magic-size features, Unicode trigrams, `LinkMetrics`, abstention (<0.5 -> keep_normal),
  `NlpAdvisor` hysteresis. 36-sample corpus (EN/FA).
* `tests/harsh_proxy.py` + `tests/stress_harsh.sh`: no-root impairment proxy and 200/300-client stress over 9 hostile profiles.
* NOT yet compiled or run against the v0.11.0 binary: run `cargo test kani_nlp` and `bash tests/stress_harsh.sh` first.
