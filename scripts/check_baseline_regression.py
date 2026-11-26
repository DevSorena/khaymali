#!/usr/bin/env python3
"""Compare candidate Khaymali live-stress JSON against a saved baseline (SPEC §1.1, §6).

Fails (exit 1) if any step regresses beyond allowed tolerances:
  * p99_ms increased by > 20% (and > 5ms absolute)
  * rss_mb increased by > 25% (and > 4MB absolute)
  * goodput_kbps dropped by > 20%
  * success ratio dropped below 95%

Usage:
  python3 scripts/check_baseline_regression.py baseline.json candidate.json
"""
import argparse, json, sys

def compare(base_doc, cand_doc, max_p99_pct=20.0, max_rss_pct=25.0, max_gp_drop_pct=20.0):
    base_steps = {s["concurrency"]: s for s in base_doc.get("steps", [])}
    cand_steps = {s["concurrency"]: s for s in cand_doc.get("steps", [])}
    failures = []

    for conc, b in sorted(base_steps.items()):
        if conc not in cand_steps:
            failures.append(f"step {conc}: missing from candidate report")
            continue
        c = cand_steps[conc]
        if c["total"] > 0 and (c["ok"] / c["total"]) < 0.95:
            failures.append(f"step {conc}: success rate {c['ok']}/{c['total']} < 95%")

        if b["p99_ms"] > 0 and c["p99_ms"] > b["p99_ms"] * (1.0 + max_p99_pct / 100.0) and (c["p99_ms"] - b["p99_ms"]) > 5.0:
            failures.append(f"step {conc}: p99 regression {b['p99_ms']}ms -> {c['p99_ms']}ms")

        if b["rss_mb"] > 0 and c["rss_mb"] > b["rss_mb"] * (1.0 + max_rss_pct / 100.0) and (c["rss_mb"] - b["rss_mb"]) > 4.0:
            failures.append(f"step {conc}: RSS regression {b['rss_mb']}MB -> {c['rss_mb']}MB")

        if b["goodput_kbps"] > 0 and c["goodput_kbps"] < b["goodput_kbps"] * (1.0 - max_gp_drop_pct / 100.0):
            failures.append(f"step {conc}: goodput drop {b['goodput_kbps']} -> {c['goodput_kbps']} kbps")

    return failures

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("baseline")
    ap.add_argument("candidate")
    ap.add_argument("--max-p99-pct", type=float, default=20.0)
    ap.add_argument("--max-rss-pct", type=float, default=25.0)
    ap.add_argument("--max-goodput-drop-pct", type=float, default=20.0)
    a = ap.parse_args()

    with open(a.baseline, encoding="utf-8") as f:
        b = json.load(f)
    with open(a.candidate, encoding="utf-8") as f:
        c = json.load(f)

    fails = compare(b, c, a.max_p99_pct, a.max_rss_pct, a.max_goodput_drop_pct)
    if fails:
        print("REGRESSION DETECTED:")
        for line in fails:
            print(" -", line)
        sys.exit(1)
    print("OK: No performance/RSS regression detected against baseline.")

if __name__ == "__main__":
    main()
