#!/usr/bin/env bash
# Chaos test of the adaptive system with the REAL binary (no mocks):
#   1. healthy tunnel                      -> condition normal
#   2. Exit killed (blackout)              -> condition blackout, clients fail FAST (not a 20 s hang)
#   3. Exit restarted                      -> condition recovering/normal, traffic flows again, recovery counted
#   4. adapt.status on the control socket works, --no-adapt keeps the system inert
# Usage: bash tests/chaos.sh [path/to/khaymali]
set -u
B="$(readlink -f "${1:-$(dirname "$0")/../target/release/khaymali}")"
T=$(mktemp -d); cd "$T"
PASS=0; FAIL=0; PIDS=""
check() { if [ "$2" = yes ]; then echo "  PASS: $1"; PASS=$((PASS+1)); else echo "  FAIL: $1"; FAIL=$((FAIL+1)); fi; }
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null; done; rm -rf "$T"; }
trap cleanup EXIT
metric() { curl -s --max-time 3 "http://127.0.0.1:$1/metrics" | awk -v k="khaymali_$2" '$1==k{print $2}'; }
get() { timeout 25 curl -s --max-time 20 --socks5-hostname 127.0.0.1:$1 http://127.0.0.1:8000/index.html | grep -q CHAOS-OK && echo yes || echo no; }

mkdir www; echo CHAOS-OK > www/index.html
python3 -m http.server 8000 --bind 127.0.0.1 --directory www >/dev/null 2>&1 & PIDS="$PIDS $!"
EX=$("$B" keygen); EXPK=$(echo "$EX" | awk '/public/{print $2}'); EXSK=$(echo "$EX" | awk '/private/{print $2}')
EN=$("$B" keygen); ENPK=$(echo "$EN" | awk '/public/{print $2}'); ENSK=$(echo "$EN" | awk '/private/{print $2}')
sleep 1
start_exit() { KHAYMALI_KEY=$EXSK "$B" exit --listen 127.0.0.1:4470 --allow "$ENPK" --allow-private >/dev/null 2>exit.log & EXIT_PID=$!; }
start_exit
KHAYMALI_KEY=$ENSK "$B" entry --socks 127.0.0.1:1090 --exit-pub "$EXPK" --exit 127.0.0.1:4470 --pool 4 \
  --metrics 127.0.0.1:9190 --control "$T/entry.sock" --adapt-state "$T/adapt.state" 2>entry.log & PIDS="$PIDS $!"
sleep 3

echo "== 1. healthy"
check "traffic flows" "$(get 1090)"
check "condition is normal (0)" "$([ "$(metric 9190 adapt_condition)" = 0 ] && echo yes || echo no)"

echo "== 2. blackout: Exit killed"
kill "$EXIT_PID"; wait "$EXIT_PID" 2>/dev/null
# the pool still holds ready links; burn through them so clients really need new ones
for i in 1 2 3 4 5 6; do timeout 12 curl -s --max-time 10 --socks5-hostname 127.0.0.1:1090 http://127.0.0.1:8000/index.html >/dev/null 2>&1; done
sleep 12
C=$(metric 9190 adapt_condition)
check "decision engine reports blackout (3), got $C" "$([ "$C" = 3 ] && echo yes || echo no)"
check "pool shrinks to a probe set (target $(metric 9190 adapt_pool_target))" "$([ "$(metric 9190 adapt_pool_target)" -le 2 ] && echo yes || echo no)"
S=$(date +%s); timeout 25 curl -s --max-time 20 --socks5-hostname 127.0.0.1:1090 http://127.0.0.1:8000/index.html >/dev/null 2>&1; D=$(( $(date +%s) - S ))
check "clients fail fast during blackout (${D}s <= 12s, not a 20s+ hang)" "$([ "$D" -le 12 ] && echo yes || echo no)"
check "entry log explains the transition" "$(grep -q 'condition .* -> blackout' entry.log && echo yes || echo no)"

echo "== 3. recovery: Exit restarted"
start_exit; T0=$(date +%s)
OK=no; for i in $(seq 1 40); do if [ "$(get 1090)" = yes ]; then OK=yes; break; fi; sleep 1; done
R=$(( $(date +%s) - T0 ))
check "traffic recovers by itself (${R}s)" "$OK"
check "recovery within 20s" "$([ "$R" -le 20 ] && echo yes || echo no)"
sleep 14
C=$(metric 9190 adapt_condition)
check "condition left blackout (now $C: 0 normal / 1 degraded / 4 recovering)" "$([ "$C" != 3 ] && echo yes || echo no)"
check "recovery counted (adapt_recoveries_total=$(metric 9190 adapt_recoveries_total))" "$([ "$(metric 9190 adapt_recoveries_total)" -ge 1 ] && echo yes || echo no)"
OKS=""; for i in $(seq 1 20); do [ "$(get 1090)" = yes ] && OKS="$OKS."; done
check "20/20 requests after recovery (${#OKS}/20)" "$([ ${#OKS} -eq 20 ] && echo yes || echo no)"

echo "== 4. control socket + opt-out"
if command -v python3 >/dev/null; then
  ST=$(python3 - "$T/entry.sock" <<'PY'
import socket,sys
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall(b'{"method":"adapt.status"}\n'); print(s.recv(4096).decode().strip())
PY
)
  check "adapt.status answers with condition+tuning" "$(echo "$ST" | grep -q '"condition"' && echo "$ST" | grep -q '"tuning"' && echo yes || echo no)"
fi
KHAYMALI_KEY=$ENSK "$B" entry --socks 127.0.0.1:1091 --exit-pub "$EXPK" --exit 127.0.0.1:4470 --pool 4 --no-adapt \
  --metrics 127.0.0.1:9191 2>noadapt.log & PIDS="$PIDS $!"
sleep 3
check "--no-adapt: traffic works" "$(get 1091)"
check "--no-adapt: system stays inert (condition 0, pool target = --pool 4)" "$([ "$(metric 9191 adapt_condition)" = 0 ] && [ "$(metric 9191 adapt_pool_target)" = 4 ] && echo yes || echo no)"

echo; echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
