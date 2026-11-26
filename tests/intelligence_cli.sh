#!/usr/bin/env bash
set -euo pipefail
BIN="${1:-target/release/khaymali}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
python3 - "$TMP" <<'PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1])
train = []
for i in range(40):
    score = 10 + i if i < 20 else 70 + (i - 20)
    train.append(f"{score}\t{1 if i >= 20 else 0}")
holdout = ["15\t0", "20\t0", "75\t1", "90\t1", "30\t0", "85\t1"]
(root / "train.tsv").write_text("\n".join(train) + "\n", encoding="utf-8")
(root / "holdout.tsv").write_text("\n".join(holdout) + "\n", encoding="utf-8")
PY
"$BIN" doctor | grep -q "doctor:"
"$BIN" calibrate-risk "$TMP/train.tsv" "$TMP/holdout.tsv" "$TMP/risk.model"
test "$(wc -c < "$TMP/risk.model")" -eq 32
"$BIN" intelligence-lab --scenario all --steps 500 --capacity-kbps 2500 --offered-kbps 2000 --queue 64 > "$TMP/twin.out"
test "$(wc -l < "$TMP/twin.out")" -eq 6
"$BIN" intelligence-lab --scenario throttle --steps 200 --capacity-kbps 1000 --offered-kbps 1500 --compare-capacity-kbps 4000 --queue 32 > "$TMP/cmp.out"
grep -q "cand_goodput_kbps=" "$TMP/cmp.out"
printf "connection reset by peer\nuser logged in\n16384\n" | "$BIN" diagnose --stdin > "$TMP/diag.out"
test "$(wc -l < "$TMP/diag.out")" -eq 3
grep -q "^early_rst" "$TMP/diag.out"
echo "intelligence CLI: PASS"
