#!/usr/bin/env bash
# Diagnostic netns + veth + tc netem check used by scripts/server_verify.sh.
# Exit codes:
#   0  = netns + veth + ping + tc netem all verified
#   77 = kernel lacks sch_netem (SKIP, not FAIL)
#   1  = unexpected failure (prints full network/route/firewall diagnostics)
set -u

S=$((RANDOM % 90000 + 1000))
N="khn$S"
VK="vk$S"
VP="vp$S"

dump_diag() {
  echo "=== netns_veth_check diagnostics ==="
  ip -br addr show "$VK" 2>&1 || true
  ip route show 10.99.250.0/30 2>&1 || true
  ip netns exec "$N" ip -br addr 2>&1 || true
  ip netns exec "$N" ip route 2>&1 || true
  if command -v nft >/dev/null 2>&1; then
    nft list ruleset 2>&1 | head -n 40 || true
  fi
  modinfo sch_netem 2>&1 | head -n 5 || true
}

cleanup() {
  ip netns del "$N" 2>/dev/null || true
  ip link del "$VK" 2>/dev/null || true
}
trap cleanup EXIT

set -e
ip netns add "$N"
ip link add "$VK" type veth peer name "$VP"
ip link set "$VP" netns "$N"
ip addr add 10.99.250.1/30 dev "$VK"
ip link set "$VK" up
ip netns exec "$N" ip addr add 10.99.250.2/30 dev "$VP"
ip netns exec "$N" ip link set "$VP" up
ip netns exec "$N" ip link set lo up
set +e

ping_ok=0
for attempt in 1 2 3; do
  sleep 0.1
  echo "[attempt $attempt/3] ping 10.99.250.2"
  if ping -c 2 -W 2 10.99.250.2; then
    ping_ok=1
    break
  fi
done
if [ "$ping_ok" -ne 1 ]; then
  dump_diag
  exit 1
fi

modprobe sch_netem 2>/dev/null || true
tc_err=$(tc qdisc add dev "$VK" root netem delay 40ms loss 5% 2>&1)
tc_rc=$?
if [ "$tc_rc" -ne 0 ]; then
  echo "$tc_err"
  if echo "$tc_err" | grep -qiE "qdisc kind is unknown|specified qdisc kind is unknown|Operation not supported|No such file or directory"; then
    echo "SKIP: kernel lacks sch_netem support"
    exit 77
  fi
  dump_diag
  exit 1
fi

tc qdisc show dev "$VK" | tee /dev/stderr | grep -q netem || {
  dump_diag
  exit 1
}
exit 0
