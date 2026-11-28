#!/usr/bin/env bash
# Offline self-test of the test/stress TOOLING itself (no khaymali binary, no root, no network):
#   - scripts/stress_live_300.sh against a local SOCKS5 + HTTP origin
#   - tests/harsh_proxy.py: transparent forwarding, added delay, early-RST mode
#   - scripts/ab_compare.py and scripts/check_baseline_regression.py gates
# Usage: bash tests/scripts_selftest.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$HERE/.."
for c in curl python3; do command -v "$c" >/dev/null || { echo "need $c" >&2; exit 1; }; done
T=$(mktemp -d); PIDS=""
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
PASS=0; FAIL=0
check() { if [ "$2" = yes ]; then echo "  PASS: $1"; PASS=$((PASS+1)); else echo "  FAIL: $1"; FAIL=$((FAIL+1)); fi; }
freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }

mkdir "$T/www"; head -c 65536 /dev/urandom > "$T/www/payload.bin"
HP=$(freeport); SP=$(freeport); PP=$(freeport); RP=$(freeport)
python3 -m http.server "$HP" --bind 127.0.0.1 --directory "$T/www" >/dev/null 2>&1 & PIDS="$PIDS $!"
python3 "$HERE/tools/mini_socks5.py" "127.0.0.1:$SP" >/dev/null 2>&1 & PIDS="$PIDS $!"
sleep 1
WANT=$(sha256sum "$T/www/payload.bin" | cut -d' ' -f1)

echo "== stress_live_300.sh against local SOCKS5 + origin"
KHAYMALI_STEPS="10 25" bash "$ROOT/scripts/stress_live_300.sh" "127.0.0.1:$SP" "http://127.0.0.1:$HP/payload.bin" 300 --json >"$T/live.json" 2>"$T/live.err"; RC=$?
check "load generator exits 0 when everything succeeds" "$([ $RC -eq 0 ] && echo yes || echo no)"
check "JSON: step 10 and 25 present, 100% ok" "$(python3 -I - "$T/live.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1])); s=r["steps"]
print("yes" if [x["concurrency"] for x in s]==[10,25] and all(x["ok"]==x["total"] for x in s) else "no")
PY
)"
bash "$ROOT/scripts/stress_live_300.sh" "10.1.2.3:1080" "http://127.0.0.1:$HP/payload.bin" 10 >/dev/null 2>&1
check "load generator refuses a non-loopback SOCKS target" "$([ $? -eq 2 ] && echo yes || echo no)"
KHAYMALI_STEPS="7" bash "$ROOT/scripts/stress_live_300.sh" "127.0.0.1:$SP" "http://127.0.0.1:$HP/payload.bin" 300 >/dev/null 2>&1
check "load generator rejects an unsupported step list" "$([ $? -ne 0 ] && echo yes || echo no)"

echo "== harsh_proxy.py"
python3 "$HERE/harsh_proxy.py" "127.0.0.1:$PP" "127.0.0.1:$HP" >/dev/null 2>&1 & PIDS="$PIDS $!"
python3 "$HERE/harsh_proxy.py" "127.0.0.1:$RP" "127.0.0.1:$HP" --rst-early 1.0 >/dev/null 2>&1 & PIDS="$PIDS $!"
sleep 1
GOT=$(curl -s --max-time 15 "http://127.0.0.1:$PP/payload.bin" | sha256sum | cut -d' ' -f1)
check "clean proxy forwards a 64 KiB file byte-exact" "$([ "$GOT" = "$WANT" ] && echo yes || echo no)"
: > "$T/rst.bin"; curl -s --max-time 8 "http://127.0.0.1:$RP/payload.bin" -o "$T/rst.bin" 2>/dev/null
check "--rst-early 1.0 really breaks the transfer" "$([ "$(sha256sum < "$T/rst.bin" | cut -d' ' -f1)" != "$WANT" ] && echo yes || echo no)"
DP=$(freeport)
python3 "$HERE/harsh_proxy.py" "127.0.0.1:$DP" "127.0.0.1:$HP" --delay 150 >/dev/null 2>&1 & PIDS="$PIDS $!"
sleep 1
S=$(date +%s%N); curl -s --max-time 20 "http://127.0.0.1:$DP/payload.bin" -o /dev/null; E=$(( ($(date +%s%N) - S) / 1000000 ))
check "--delay 150 adds latency (${E} ms >= 250)" "$([ "$E" -ge 250 ] && echo yes || echo no)"

echo "== ab_compare.py / check_baseline_regression.py"
mk() { python3 -I - "$1" "$2" "$3" "$4" "$5" <<'PY'
import json,sys
p,ok,p95,gp,rss=sys.argv[1],int(sys.argv[2]),float(sys.argv[3]),float(sys.argv[4]),float(sys.argv[5])
json.dump({"steps":[{"concurrency":200,"ok":ok,"total":200,"p50_ms":p95/2,"p95_ms":p95,"p99_ms":p95*1.2,"goodput_kbps":gp,"rss_mb":rss}]},open(p,"w"))
PY
}
mkdir "$T/A" "$T/B" "$T/B2"
for r in 1 2 3; do mk "$T/A/clean-200-r$r.json" 198 100 5000 40; mk "$T/B/clean-200-r$r.json" 198 100 5000 40; mk "$T/B2/clean-200-r$r.json" 120 400 1000 40; done
python3 "$ROOT/scripts/ab_compare.py" "$T/A" "$T/B" >/dev/null 2>&1
check "ab_compare: identical sides pass the clean gate" "$([ $? -eq 0 ] && echo yes || echo no)"
python3 "$ROOT/scripts/ab_compare.py" "$T/A" "$T/B2" >/dev/null 2>&1
check "ab_compare: a clearly worse B fails the gate" "$([ $? -eq 1 ] && echo yes || echo no)"
python3 "$ROOT/scripts/check_baseline_regression.py" "$T/A/clean-200-r1.json" "$T/B/clean-200-r1.json" >/dev/null 2>&1
check "baseline check: no regression passes" "$([ $? -eq 0 ] && echo yes || echo no)"
python3 "$ROOT/scripts/check_baseline_regression.py" "$T/A/clean-200-r1.json" "$T/B2/clean-200-r1.json" >/dev/null 2>&1
check "baseline check: big regression fails" "$([ $? -eq 1 ] && echo yes || echo no)"

echo; echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
