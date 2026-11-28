#!/usr/bin/env bash
# Is a netem failure the tunnel's fault, or just a profile too harsh for any TCP path?
#
# tests/netem.sh puts `tc netem` on `lo`, which impairs EVERY hop of the loopback test: client->entry,
# entry->exit AND exit->origin. A request through the tunnel therefore crosses 3 impaired hops.
# This script measures the same requests two ways under the same profile:
#   control : client -> relay -> relay -> origin     (3 loopback hops, plain TCP, no tunnel)
#   tunnel  : client -> SOCKS entry -> exit -> origin (3 loopback hops, Khaymali)
# and prints success rate and latency for both, plus an 8 MB download. If the control path is
# already below 100% or much slower, the profile (not the tunnel) is what a "20/20" rule trips on.
#
#   sudo bash tests/netem_control.sh target/release/khaymali          # all profiles
#   sudo PROFILES="clean loss5" N=40 bash tests/netem_control.sh ...   # subset
# Needs root + iproute2 (tc) for the impaired profiles; without them only "clean" runs.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$(readlink -f "${1:-$HERE/../target/release/khaymali}")"
[ -x "$BIN" ] || { echo "binary not found: $BIN"; exit 1; }
N="${N:-30}"; TO="${REQ_TIMEOUT:-20}"; BULK_MB="${BULK_MB:-8}"
declare -A P=(
  [clean]=""
  [loss5]="loss 5%"
  [loss15]="loss 15%"
  [lat150_jit50]="delay 150ms 50ms distribution normal"
  [reorder]="delay 40ms reorder 25% 50%"
  [lossy_mobile]="delay 80ms 40ms loss 8% 25%"
)
PROFILES="${PROFILES:-clean loss5 loss15 lat150_jit50 reorder lossy_mobile}"
T=$(mktemp -d); cd "$T" || exit 1
PIDS=""
cleanup() { tc qdisc del dev lo root 2>/dev/null; for p in $PIDS; do kill "$p" 2>/dev/null; done; rm -rf "$T"; }; trap cleanup EXIT
bg() { "$@" & PIDS="$PIDS $!"; }
HAVE_TC=0; [ "$(id -u)" = 0 ] && command -v tc >/dev/null && HAVE_TC=1
if [ "$HAVE_TC" = 0 ]; then echo "NOTE: need root + tc: only the 'clean' profile will run"; fi

head -c $((BULK_MB*1024*1024)) /dev/urandom > bulk.bin; echo "<html>SMALL-OK</html>" > index.html
bg python3 -m http.server 8010 --bind 127.0.0.1 >/dev/null 2>&1
RELAY="$HERE/harsh_proxy.py"            # with no impairment options it is a plain TCP relay
bg python3 "$RELAY" 127.0.0.1:8011 127.0.0.1:8012 2>/dev/null     # client -> relay A -> relay B
bg python3 "$RELAY" 127.0.0.1:8012 127.0.0.1:8010 2>/dev/null     # relay B -> origin

EX=$("$BIN" keygen); EXPK=$(echo "$EX"|awk '/public/{print $2}'); EXSK=$(echo "$EX"|awk '/private/{print $2}')
EN=$("$BIN" keygen); ENPK=$(echo "$EN"|awk '/public/{print $2}'); ENSK=$(echo "$EN"|awk '/private/{print $2}')
KHAYMALI_KEY=$EXSK bg "$BIN" exit --listen 127.0.0.1:5440 --allow "$ENPK" --allow-private 2>exit.log >/dev/null
sleep 1
KHAYMALI_KEY=$ENSK bg "$BIN" entry --socks 127.0.0.1:5081 --exit-pub "$EXPK" --exit 127.0.0.1:5440 --pool 4 2>entry.log >/dev/null
sleep 3

cat > probe.py <<'PY'
import socket, struct, sys, time
mode, n, path, to = sys.argv[1], int(sys.argv[2]), sys.argv[3], float(sys.argv[4])
def fetch():
    t0 = time.monotonic()
    try:
        if mode == "tunnel":
            s = socket.create_connection(("127.0.0.1", 5081), timeout=to)
            s.settimeout(to)
            s.sendall(b"\x05\x01\x00"); assert s.recv(2) == b"\x05\x00"
            s.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack(">H", 8010))
            r = s.recv(10); assert len(r) >= 2 and r[1] == 0, "socks error %r" % r[:2]
        else:
            s = socket.create_connection(("127.0.0.1", 8011), timeout=to); s.settimeout(to)
        s.sendall(("GET %s HTTP/1.0\r\nHost: x\r\n\r\n" % path).encode())
        total = 0; head = b""
        while time.monotonic() - t0 < to:
            d = s.recv(65536)
            if not d: break
            total += len(d)
            if len(head) < 64: head += d
        s.close()
        return (total, time.monotonic() - t0) if head.startswith(b"HTTP/1.") and total > 0 else (0, time.monotonic() - t0)
    except Exception:
        return (0, time.monotonic() - t0)
res = [fetch() for _ in range(n)]
ok = [t for b, t in res if b > 0]
ok.sort()
p = lambda q: ok[min(len(ok) - 1, int(q * len(ok)))] if ok else 0
print("%d/%d p50=%.2fs p95=%.2fs total=%.1fs bytes=%d" % (len(ok), n, p(0.5), p(0.95), sum(t for _, t in res), sum(b for b, _ in res)))
PY

printf '%-14s %-52s %s\n' PROFILE "SMALL REQUESTS (sequential, timeout ${TO}s)" "BULK ${BULK_MB}MB"
for name in $PROFILES; do
  tc qdisc del dev lo root 2>/dev/null
  if [ -n "${P[$name]:-}" ]; then
    [ "$HAVE_TC" = 1 ] || { echo "$name: skipped (no root/tc)"; continue; }
    tc qdisc add dev lo root netem ${P[$name]} || { echo "$name: tc netem failed (sch_netem missing?)"; continue; }
  fi
  c=$(python3 probe.py control "$N" /index.html "$TO"); t=$(python3 probe.py tunnel "$N" /index.html "$TO")
  cb=$(python3 probe.py control 1 /bulk.bin 120); tb=$(python3 probe.py tunnel 1 /bulk.bin 120)
  printf '%-14s control %-44s\n' "$name" "$c"
  printf '%-14s tunnel  %-44s bulk control: %s | tunnel: %s\n' "" "$t" "$cb" "$tb"
done
tc qdisc del dev lo root 2>/dev/null
echo
echo "Reading it: if 'control' is already below $N/$N or slow, the profile is too harsh for a strict"
echo "all-requests-must-succeed check; compare the tunnel line to the control line, not to 100%."
