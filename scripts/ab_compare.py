#!/usr/bin/env python3
"""A/B comparison of two stress_harsh.sh output dirs (e.g. shadow vs active).

usage: python3 scripts/ab_compare.py /tmp/khaymali-shadow /tmp/khaymali-active [--json out.json]

Aggregates all repetitions per profile x client-step (`<profile>-<step>-r<N>.json`; legacy
`<profile>-<step>.json` also accepted) and reports the median ok%, p95, p99, goodput and the NLP
action/revert counts. "better"/"worse" is only reported when the difference exceeds the spread
seen between repetitions of the same side, so run-to-run noise is not mistaken for an effect.
Exit code 1 if B is worse than A on the `clean` profile (gate for enabling active mode).
"""
import glob, json, os, re, statistics, sys


def load(d):
    out = {}
    for p in glob.glob(os.path.join(d, "*.json")):
        m = re.match(r"(.+)-(\d+)(?:-r(\d+))?\.json$", os.path.basename(p))
        if not m:
            continue
        try:
            st = json.load(open(p, encoding="utf-8"))["steps"][0]
        except Exception:
            continue
        if not st.get("total"):
            continue
        out.setdefault((m.group(1), int(m.group(2))), []).append(st)
    return out


def agg(runs):
    ok = [100.0 * r["ok"] / r["total"] for r in runs]
    f = lambda k: [float(r.get(k, 0) or 0) for r in runs]
    nlp = lambda k: [float((r.get("nlp") or {}).get(k, 0)) for r in runs]
    med = statistics.median
    gp = f("goodput_kbps")
    return {
        "n": len(runs), "ok": med(ok), "ok_spread": max(ok) - min(ok),
        "p95": med(f("p95_ms")), "p99": med(f("p99_ms")), "goodput": med(gp),
        "gp_spread": max(gp) - min(gp),
        "actions": med(nlp("nlp_actions_total")), "reverts": med(nlp("nlp_reverts_total")),
    }


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    A, B = load(argv[0]), load(argv[1])
    keys = sorted(set(A) & set(B))
    if not keys:
        print(f"no common profile/step results between {argv[0]} and {argv[1]}")
        return 2
    rows, better, worse, clean_worse = [], 0, 0, False
    print(f"{'profile':<16}{'step':>5}{'n':>3} | {'ok% A':>6} {'ok% B':>6} {'d':>6} | {'p95 A':>7} {'p95 B':>7} | "
          f"{'p99 A':>7} {'p99 B':>7} | {'gp A':>7} {'gp B':>7} | {'act':>4} {'rev':>4} | verdict")
    for k in keys:
        a, b = agg(A[k]), agg(B[k])
        noise_ok = max(1.0, a["ok_spread"], b["ok_spread"])
        noise_gp = max(0.05 * max(a["goodput"], 1.0), a["gp_spread"], b["gp_spread"])
        d_ok, d_gp = b["ok"] - a["ok"], b["goodput"] - a["goodput"]
        if d_ok > noise_ok or (abs(d_ok) <= noise_ok and d_gp > noise_gp):
            verdict = "better"; better += 1
        elif d_ok < -noise_ok or (abs(d_ok) <= noise_ok and d_gp < -noise_gp):
            verdict = "WORSE"; worse += 1
            clean_worse |= k[0] == "clean"
        else:
            verdict = "same (within noise)"
        if min(a["n"], b["n"]) < 3:
            verdict += " [<3 runs]"
        rows.append({"profile": k[0], "step": k[1], "A": a, "B": b, "verdict": verdict})
        print(f"{k[0]:<16}{k[1]:>5}{min(a['n'], b['n']):>3} | {a['ok']:>6.1f} {b['ok']:>6.1f} {d_ok:>+6.1f} | "
              f"{a['p95']:>7.0f} {b['p95']:>7.0f} | {a['p99']:>7.0f} {b['p99']:>7.0f} | "
              f"{a['goodput']:>7.0f} {b['goodput']:>7.0f} | {b['actions']:>4.0f} {b['reverts']:>4.0f} | {verdict}")
    print(f"\nB better on {better}, worse on {worse} of {len(keys)} (beyond repetition noise).")
    if "--json" in argv:
        with open(argv[argv.index("--json") + 1], "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=2)
    if clean_worse:
        print("GATE: B is worse on the clean profile -> do NOT enable KHAYMALI_NLP_MODE=active.")
        return 1
    print("GATE: clean profile not worse." + (" Review WORSE rows before enabling active mode." if worse else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
