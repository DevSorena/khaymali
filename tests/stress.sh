#!/usr/bin/env bash
# Self-contained stress test: brings up origin + Exit + Entry on loopback, then runs the stepped
# stress (10/25/50/100/200/300 concurrent SOCKS5 clients) against it.
#
#   bash tests/stress.sh [path/to/khaymali] [MAX_STEP]            # clean loopback
#   sudo NETEM=1 bash tests/stress.sh [path/to/khaymali] [MAX_STEP]   # + degraded-network profiles
#   KHAYMALI_STEPS="200 300" bash tests/stress.sh                 # only the heavy steps
#
# Pass rule (same as stress_live_300.sh): every step needs >= 95% successful requests.
# JSON per profile is saved in $OUT (default /tmp/khaymali-stress) for check_baseline_regression.py.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
B="$(readlink -f "${1:-$HERE/../target/release/khaymali}")"
MAX_STEP="${2:-300}"
OUT="${OUT:-/tmp/khaymali-stress}"
POOL="${POOL:-16}"
mkdir -p "$OUT"
ulimit -n 65535 2>/dev/null || true

for c in curl python3; do command -v "$c" >/dev/null || { echo "need $c" >&2; exit 1; }; done
[ -x "$B" ] || { echo "binary not found: $B (cargo build --release first)" >&2; exit 1; }

T=$(mktemp -d); PIDS=""
cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null; done
  command -v tc >/dev/null && tc qdisc del dev lo root 2>/dev/null
  rm -rf "$T"
}
trap cleanup EXIT
bg() { "$@" >/dev/null 2>&1 & PIDS="$PIDS $!"; }

mkdir -p "$T/www"; echo "STRESS-OK" > "$T/www/index.html"
head -c 65536 /dev/urandom > "$T/www/small.bin"
bg python3 -m http.server 8000 --bind 127.0.0.1 --directory "$T/www"

EX=$("$B" keygen); EXPK=$(echo "$EX" | awk '/public/{print $2}'); EXSK=$(echo "$EX" | awk '/private/{print $2}')
EN=$("$B" keygen); ENPK=$(echo "$EN" | awk '/public/{print $2}'); ENSK=$(echo "$EN" | awk '/private/{print $2}')
sleep 1

tunnel_up() {
  KHAYMALI_KEY=$EXSK "$B" exit --listen 127.0.0.1:4440 --allow "$ENPK" --allow-private >/dev/null 2>"$T/exit.log" &
  EXIT_PID=$!
  KHAYMALI_KEY=$ENSK "$B" entry --socks 127.0.0.1:1080 --exit-pub "$EXPK" --exit 127.0.0.1:4440 --pool "$POOL" >/dev/null 2>"$T/entry.log" &
  ENTRY_PID=$!
  sleep 2
}
tunnel_down() { kill "$EXIT_PID" "$ENTRY_PID" 2>/dev/null; wait "$EXIT_PID" "$ENTRY_PID" 2>/dev/null; sleep 1; }

FAIL=0
run_profile() {
  local name="$1" netem="$2"
  command -v tc >/dev/null && tc qdisc del dev lo root 2>/dev/null
  if [ -n "$netem" ]; then tc qdisc add dev lo root netem $netem || { echo "tc failed for $name"; return; }; fi
  tunnel_up
  echo "=== profile: $name ${netem:+($netem)} ==="
  # warm-up: make sure the tunnel really carries traffic before measuring
  curl -s --max-time 20 --socks5-hostname 127.0.0.1:1080 http://127.0.0.1:8000/index.html | grep -q STRESS-OK \
    || { echo "  tunnel did not come up (see $T/entry.log)"; tail -5 "$T/entry.log"; FAIL=1; tunnel_down; return; }
  bash "$HERE/../scripts/stress_live_300.sh" 127.0.0.1:1080 http://127.0.0.1:8000/small.bin "$MAX_STEP"
  local rc=$?
  bash "$HERE/../scripts/stress_live_300.sh" 127.0.0.1:1080 http://127.0.0.1:8000/small.bin "$MAX_STEP" --json >"$OUT/$name.json" 2>/dev/null || true
  [ $rc -eq 0 ] && echo "  RESULT $name: PASS" || { echo "  RESULT $name: FAIL (<95% ok on some step)"; FAIL=1; }
  tunnel_down
}

run_profile clean ""
if [ "${NETEM:-0}" = "1" ]; then
  [ "$(id -u)" -eq 0 ] && command -v tc >/dev/null || { echo "NETEM=1 needs root + iproute2 (tc)"; exit 1; }
  run_profile loss5        "loss 5%"
  run_profile lat150_jit50 "delay 150ms 50ms distribution normal"
  run_profile reorder      "delay 40ms reorder 25% 50%"
  run_profile lossy_mobile "delay 80ms 40ms loss 8% 25%"
fi
echo; echo "JSON reports: $OUT/*.json"
exit $FAIL
