#!/usr/bin/env bash
# Real Iran <-> abroad path check. Needs TWO real servers; this is the one thing a single host cannot test.
#
# The load generator only accepts loopback SOCKS/targets (safety guard), so the origin lives on the
# EXIT host's loopback and is reached THROUGH the tunnel (the Exit resolves 127.0.0.1 itself; the Exit
# must run with --allow-private, as in deploy/systemd/khaymali-exit.service).
#
# 1) on the EXIT (abroad) server:    bash scripts/real_path_check.sh origin
# 2) on the ENTRY (Iran) server, with the Entry already running and its SOCKS on 127.0.0.1:1080:
#      bash scripts/real_path_check.sh run [EXIT_PUBLIC_IP]
#    -> RTT/loss to the Exit (ping), a warm-up fetch, the stepped load test (10..300 clients),
#       JSON saved to $OUT (default /tmp/khaymali-real-path). Exit 0 only if every step is >= 95% ok.
# Env: SOCKS=127.0.0.1:1080  ORIGIN_PORT=18088  MAX_STEP=300  KHAYMALI_STEPS="50 100"  OUT=dir
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SOCKS="${SOCKS:-127.0.0.1:1080}"
ORIGIN_PORT="${ORIGIN_PORT:-18088}"
MAX_STEP="${MAX_STEP:-300}"
OUT="${OUT:-/tmp/khaymali-real-path}"
cmd="${1:-}"

case "$cmd" in
  origin)
    D="$(mktemp -d)"; trap 'rm -rf "$D"' EXIT
    echo REAL-PATH-OK > "$D/index.html"; head -c 262144 /dev/urandom > "$D/payload.bin"
    echo "origin on 127.0.0.1:$ORIGIN_PORT (loopback only). Ctrl-C to stop."
    exec python3 -m http.server "$ORIGIN_PORT" --bind 127.0.0.1 --directory "$D"
    ;;
  run)
    EXIT_IP="${2:-}"
    for c in curl python3; do command -v "$c" >/dev/null || { echo "need $c" >&2; exit 1; }; done
    mkdir -p "$OUT"
    if [ -n "$EXIT_IP" ] && command -v ping >/dev/null; then
      echo "== ping $EXIT_IP (50 probes, 0.2 s apart)"
      ping -c 50 -i 0.2 -q "$EXIT_IP" 2>&1 | tee "$OUT/ping.txt" | tail -n 3
    fi
    echo "== warm-up through the tunnel ($SOCKS)"
    curl -fsS --max-time 30 --socks5-hostname "$SOCKS" "http://127.0.0.1:$ORIGIN_PORT/index.html" | grep -q REAL-PATH-OK \
      || { echo "FAIL: nothing came back through the tunnel. Is the origin running on the Exit and the Entry up?" >&2; exit 1; }
    echo "OK: tunnel carries traffic"
    echo "== stepped load (JSON: $OUT/real-path.json)"
    bash "$HERE/stress_live_300.sh" "$SOCKS" "http://127.0.0.1:$ORIGIN_PORT/payload.bin" "$MAX_STEP" --json > "$OUT/real-path.json"; rc=$?
    python3 -I - "$OUT/real-path.json" <<'PY'
import json, sys
try: r = json.load(open(sys.argv[1]))
except Exception as e: print("no result:", e); sys.exit(0)
for s in r["steps"]:
    print(f" [STEP {s['concurrency']:>3}] ok={s['ok']:>3}/{s['total']:<3} p50={s['p50_ms']:>7.1f}ms p95={s['p95_ms']:>7.1f}ms p99={s['p99_ms']:>7.1f}ms goodput={s['goodput_kbps']:>9.1f}kbps")
PY
    [ $rc -eq 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL (a step was below 95% ok)"
    exit $rc
    ;;
  *) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
