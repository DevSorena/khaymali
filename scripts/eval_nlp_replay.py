#!/usr/bin/env python3
"""Evaluate NLP replay data, including optional numeric LinkMetrics.

JSONL fields: log, expected; optional metrics object with LinkMetrics field names.
Uses `diagnose --stdin-combined` so text and telemetry are evaluated together.
"""
import json, math, subprocess, sys
from collections import defaultdict

if len(sys.argv) < 3:
    print("usage: eval_nlp_replay.py <khaymali-bin> <replay_dataset.jsonl>", file=sys.stderr)
    sys.exit(2)

bin_path, dataset_path = sys.argv[1], sys.argv[2]
CLASSES = ["healthy", "early_rst", "byte_freeze", "pmtu_drop", "throttle", "route_or_dns_fail", "unrelated"]
conf = {c: defaultdict(int) for c in CLASSES}
total_fault = ok_fault = abst_fault = wrong_fault = 0
total_safe = false_act_safe = 0
unlabeled = 0
pred_counts = defaultdict(int)

def bit(v): return "1" if bool(v) else "0"
def num(m, key, default=0):
    v = m.get(key, default)
    return str(v if v is not None else "")

recs = []
with open(dataset_path, encoding="utf-8") as fh:
    for n, line in enumerate(fh, 1):
        if not line.strip(): continue
        try: rec = json.loads(line)
        except json.JSONDecodeError as ex: raise SystemExit(f"invalid JSONL at line {n}: {ex}")
        if not isinstance(rec.get("log", ""), str): raise SystemExit(f"line {n}: log must be a string")
        recs.append(rec)

rows = []
metric_records = 0
metric_float_keys = ("loss_pct", "retransmit_pct", "connect_fail_ratio")
metric_int_keys = ("rtt_ms", "base_rtt_ms", "jitter_ms", "rx_idle_ms", "resets_last_min")
for rec in recs:
    m = rec.get("metrics") or {}
    if not isinstance(m, dict): raise SystemExit("metrics must be a JSON object")
    recognized = set(metric_float_keys + metric_int_keys + ("stall_bytes", "big_frames_lost", "small_frames_ok"))
    if any(k in m for k in recognized): metric_records += 1
    for key in metric_float_keys:
        if key in m:
            try: value = float(m[key])
            except (TypeError, ValueError): raise SystemExit(f"metrics.{key} must be numeric")
            if not math.isfinite(value) or value < 0 or (key == "connect_fail_ratio" and value > 1):
                raise SystemExit(f"metrics.{key} is outside its valid range")
    for key in metric_int_keys + (("stall_bytes",) if m.get("stall_bytes") is not None else ()):
        if key in m and (isinstance(m[key], bool) or not isinstance(m[key], int) or m[key] < 0):
            raise SystemExit(f"metrics.{key} must be a non-negative integer")
    for key in ("big_frames_lost", "small_frames_ok"):
        if key in m and not isinstance(m[key], bool):
            raise SystemExit(f"metrics.{key} must be boolean")
    fields = [rec.get("log", "").replace("\t", " ").replace("\n", " "),
              num(m, "loss_pct"), num(m, "rtt_ms"), num(m, "base_rtt_ms"),
              num(m, "jitter_ms"), num(m, "retransmit_pct"), num(m, "stall_bytes", None),
              num(m, "rx_idle_ms"), num(m, "resets_last_min"), num(m, "connect_fail_ratio"),
              bit(m.get("big_frames_lost", False)), bit(m.get("small_frames_ok", False))]
    rows.append("\t".join(fields))

proc = subprocess.run([bin_path, "diagnose", "--stdin-combined"], input="\n".join(rows) + ("\n" if rows else ""),
                      capture_output=True, text=True)
if proc.returncode:
    raise SystemExit(f"diagnose failed ({proc.returncode}): {proc.stderr.strip()}")
outs = proc.stdout.splitlines()
if len(outs) != len(recs):
    raise SystemExit(f"binary returned {len(outs)} verdicts for {len(recs)} records")

for rec, out in zip(recs, outs):
    exp = rec.get("expected")
    if exp is not None and exp != "unlabeled" and exp not in CLASSES:
        raise SystemExit(f"unknown expected class: {exp}")
    parts = out.split("\t")
    if len(parts) != 4: raise SystemExit(f"malformed diagnose output: {out!r}")
    pred, _confidence, abstained, action = parts
    if pred not in CLASSES: raise SystemExit(f"unknown predicted class: {pred}")
    pred_counts[pred] += 1
    if exp is None or exp == "unlabeled":
        unlabeled += 1
        continue
    conf[exp][pred] += 1
    if exp in ("healthy", "unrelated"):
        total_safe += 1
        if action != "keep_normal": false_act_safe += 1
    else:
        total_fault += 1
        if abstained == "true" or action == "keep_normal": abst_fault += 1
        elif pred == exp: ok_fault += 1
        else: wrong_fault += 1

import os
print("=== NLP REPLAY AUDIT (text + optional numeric metrics) ===")
print("Model evaluated: " + (os.environ.get("KHAYMALI_NLP_MODEL_PATH") or "pretrained baseline")
      + "  (set KHAYMALI_NLP_MODEL_PATH to audit the deployed artifact)")
print(f"Records: {len(recs)}; records with LinkMetrics: {metric_records}; unlabeled: {unlabeled}")
print("Predictions across all records: " + ", ".join(f"{k}={pred_counts[k]}" for k in CLASSES))
if total_fault:
    print(f"Fault records ({total_fault}): accurate={ok_fault} ({100*ok_fault/total_fault:.1f}%), "
          f"abstained={abst_fault} ({100*abst_fault/total_fault:.1f}%), wrong_action={wrong_fault} ({100*wrong_fault/total_fault:.1f}%)")
if total_safe:
    print(f"Safe/unrelated records ({total_safe}): false_action_rate={false_act_safe}/{total_safe} ({100*false_act_safe/total_safe:.2f}%)")
print("\nConfusion Matrix (row=expected, col=predicted):")
print("True\\Pred         " + " ".join(f"{c[:6]:>6}" for c in CLASSES))
for r in CLASSES:
    print(f"{r:<17} " + " ".join(f"{conf[r][c]:>6}" for c in CLASSES))
