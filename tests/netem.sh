#!/usr/bin/env bash
# Run the loopback integration test under degraded-network profiles using tc netem.
# Needs root + iproute2. netem on `lo` affects both directions, so effective loss/delay is ~2x.
#   sudo bash tests/netem.sh target/release/khaymali
#   sudo STRESS=1 bash tests/netem.sh target/release/khaymali   # + 200/300 client stress per profile
set -u
BIN="${1:-target/release/khaymali}"
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
command -v tc >/dev/null || { echo "need iproute2 (tc)"; exit 1; }
cleanup() { tc qdisc del dev lo root 2>/dev/null || true; }
trap cleanup EXIT

declare -A PROFILES=(
  [clean]=""
  [loss5]="loss 5%"
  [loss15]="loss 15%"
  [lat150_jit50]="delay 150ms 50ms distribution normal"
  [reorder]="delay 40ms reorder 25% 50%"
  [lossy_mobile]="delay 80ms 40ms loss 8% 25%"
)
# STRESS=1 -> also run the 200/300 concurrent-client stress under every profile
STRESS="${STRESS:-0}"
fail=0
for name in clean loss5 loss15 lat150_jit50 reorder lossy_mobile; do
  cleanup
  [ -n "${PROFILES[$name]}" ] && tc qdisc add dev lo root netem ${PROFILES[$name]}
  start=$(date +%s)
  if [ "$STRESS" = "1" ]; then
    if KHAYMALI_STEPS="${KHAYMALI_STEPS:-100 200 300}" bash tests/stress.sh "$BIN" 300 >/tmp/netem-stress-$name.log 2>&1; then rs=PASS; else rs=FAIL; fail=1; fi
    printf '%-14s stress(200/300) %s  log: /tmp/netem-stress-%s.log\n' "$name" "$rs" "$name"
  fi
  if bash tests/integration.sh "$BIN" >/tmp/netem-$name.log 2>&1; then r=PASS; else r=FAIL; fail=1; fi
  printf '%-14s %s  (%ss)  log: /tmp/netem-%s.log\n' "$name" "$r" "$(( $(date +%s) - start ))" "$name"
done
exit $fail
