#!/usr/bin/env bash
# One-shot verification on YOUR server: everything that cannot be proven in a CI sandbox.
#
#   sudo bash scripts/server_verify.sh                     # full run (~30-60 min)
#   sudo bash scripts/server_verify.sh --quick             # skip the long stress/A-B parts (~10 min)
#   sudo bash scripts/server_verify.sh --bin target/release/khaymali --skip-build
#   sudo TG_TOKEN=123:ABC TG_CHAT=-100123 bash scripts/server_verify.sh     # + real Telegram delivery
#
# Options : --quick  --skip-build  --bin PATH  --out DIR  --repeats N  --help
# Env     : TG_TOKEN / TG_CHAT   real Telegram Bot API check (sends ONE test message)
#           FORCE=1               run even if test ports are already in use (not recommended)
#           STRESS_STEPS="200 250 300"   REPEATS=2
#
# Every step is logged to <out>/logs/<step>.log and recorded as PASS / FAIL / SKIP.
# A failing step never stops the run. Final summary: <out>/server_verify_report.txt
# Exit code: 0 = no FAIL, 1 = at least one FAIL. SKIP means "not testable on this host" (reason shown).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 2

QUICK=0; SKIP_BUILD=0; BIN=""; OUT=""; REPEATS="${REPEATS:-2}"; STRESS_STEPS="${STRESS_STEPS:-200 250 300}"
while (( $# )); do
  case "$1" in
    --quick) QUICK=1; shift ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --bin) BIN="${2:?--bin needs a path}"; shift 2 ;;
    --out) OUT="${2:?--out needs a directory}"; shift 2 ;;
    --repeats) REPEATS="${2:?--repeats needs a number}"; shift 2 ;;
    -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
done
OUT="${OUT:-/tmp/khaymali-server-verify-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT/logs" || { echo "cannot create $OUT" >&2; exit 2; }
REPORT="$OUT/server_verify_report.txt"
: > "$REPORT"
ulimit -n 65535 2>/dev/null || true

if [ -t 1 ]; then G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; Z=$'\e[0m'; else G=""; R=""; Y=""; Z=""; fi
NP=0; NF=0; NS=0
say()  { printf '%s\n' "$*" | tee -a "$REPORT"; }
rec()  { # status name detail
  case "$1" in
    PASS) NP=$((NP+1)); c=$G ;; FAIL) NF=$((NF+1)); c=$R ;; *) NS=$((NS+1)); c=$Y ;;
  esac
  printf '%s%-5s%s %-34s %s\n' "$c" "$1" "$Z" "$2" "${3:-}"
  printf '%-5s %-34s %s\n' "$1" "$2" "${3:-}" >> "$REPORT"
}
step() {
  local name="$1" to="$2"; shift 2
  local log="$OUT/logs/$name.log" t0 rc
  t0=$(date +%s)
  timeout "$to" "$@" >"$log" 2>&1; rc=$?
  if [ $rc -eq 0 ]; then rec PASS "$name" "($(( $(date +%s) - t0 ))s)"
  elif [ $rc -eq 124 ]; then rec FAIL "$name" "timeout after ${to}s  log: $log"
  else rec FAIL "$name" "exit $rc  log: $log ; last: $(tail -n 1 "$log" | cut -c1-100)"; fi
}
skip() { rec SKIP "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }
IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1

say "=== Khaymali server verification  $(date -u +%FT%TZ) ==="
say "host: $(uname -srm)   cpu cores: $(nproc 2>/dev/null || echo ?)   root: $([ $IS_ROOT = 1 ] && echo yes || echo NO)"
say "out : $OUT"
[ "$(nproc 2>/dev/null || echo 1)" -ge 2 ] || say "NOTE: this host has 1 core; the multi-core stress claim is NOT verified by this run."
[ $IS_ROOT = 1 ] || say "NOTE: not root - all root-only checks will be SKIPped. Re-run with sudo."
say ""

say "--- 0. preflight"
MISSING=""
for t in curl python3 awk; do have "$t" || MISSING="$MISSING $t"; done
if [ -n "$MISSING" ]; then rec FAIL preflight-tools "missing:$MISSING"; else rec PASS preflight-tools; fi
if ! have cc && ! have gcc && [ "$SKIP_BUILD" = 0 ] && [ -z "${KHAYMALI_NO_CARGO:-}" ]; then
  rec FAIL preflight-compiler "no C compiler/linker (cc) in PATH"
  say ""; say "Aborting: install the build tools first:  apt update && apt install -y build-essential pkg-config"
  say "(or build elsewhere and run:  bash $0 --skip-build --bin /path/to/khaymali)"
  exit 1
fi
rec PASS preflight-compiler
if ! have cargo && [ -x "$HOME/.cargo/bin/cargo" ]; then
  say "NOTE: cargo exists in ~/.cargo/bin but not in PATH (sudo resets PATH). Run:  sudo env \"PATH=$PATH:$HOME/.cargo/bin\" bash $0 $*"
fi
BUSY="$(python3 -I - <<'PY' 2>/dev/null
import socket
busy = []
for p in (1080, 1081, 1090, 1091, 4440, 4441, 4470, 8000, 9190, 9191, 18080, 29080):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try: s.bind(("127.0.0.1", p))
    except OSError: busy.append(str(p))
    finally: s.close()
print(" ".join(busy))
PY
)"
BUSY="${BUSY:+ $BUSY}"
if [ -n "$BUSY" ] && [ "${FORCE:-0}" != 1 ]; then
  rec FAIL preflight-ports "ports in use:$BUSY (a live Khaymali/other service?). Stop it or FORCE=1."
  say ""; say "Aborting: the tests bind fixed loopback ports. Free them, or run with FORCE=1."
  exit 1
fi
rec PASS preflight-ports "${BUSY:+(forced: busy$BUSY)}"

say ""; say "--- 1. build and unit tests"
if [ -n "$BIN" ]; then
  BIN="$(readlink -f "$BIN")"
elif [ "$SKIP_BUILD" = 1 ]; then
  BIN="$ROOT/target/release/khaymali"
else
  BIN="$ROOT/target/release/khaymali"
fi
if [ "$SKIP_BUILD" = 0 ] && [ -z "${KHAYMALI_NO_CARGO:-}" ]; then
  if have cargo; then
    rec PASS toolchain "$(rustc --version 2>/dev/null) (project pins 1.85.0 via rust-toolchain.toml)"
    step cargo-test 3600 cargo test --release --locked
    step cargo-build 3600 cargo build --release --locked
  else
    rec FAIL toolchain "cargo not found (install rustup; rust-toolchain.toml pins 1.85.0)"
  fi
else
  skip cargo-test "--skip-build"
  skip cargo-build "--skip-build"
fi
if [ ! -x "$BIN" ]; then
  rec FAIL binary "not found: $BIN"
  say ""; say "Cannot continue without the binary."; exit 1
fi
rec PASS binary "$BIN ($("$BIN" version 2>/dev/null | head -n1))"

say ""; say "--- 2. tooling and loopback end-to-end"
for f in install.sh scripts/*.sh tests/*.sh scripts/khaymali-manager; do
  bash -n "$f" 2>>"$OUT/logs/syntax.log" || BADSH="${BADSH:-} $f"
done
[ -z "${BADSH:-}" ] && rec PASS shell-syntax || rec FAIL shell-syntax "$BADSH"
step py-syntax 60 python3 -I -m py_compile scripts/ab_compare.py scripts/check_baseline_regression.py scripts/eval_nlp_replay.py scripts/make_annotation_set.py tests/harsh_proxy.py tests/tools/mini_socks5.py
step scripts-selftest 300 bash tests/scripts_selftest.sh
step manager-tests 300 bash tests/manager.sh
step intelligence-cli 300 bash tests/intelligence_cli.sh "$BIN"
step eof-e2e 600 bash tests/eof_e2e.sh "$BIN"
step pool-e2e 600 bash tests/pool_e2e.sh "$BIN"
step autopilot-e2e 600 bash tests/autopilot_e2e.sh "$BIN"
step suite-e2e 600 bash tests/khaymali_suite_e2e.sh "$BIN"
bash tests/integration.sh "$BIN" >"$OUT/logs/integration.log" 2>&1
BAD=$(grep -E "^  FAIL:" "$OUT/logs/integration.log" | grep -vc "plain-HTTP probe" || true)
if [ "${BAD:-0}" = 0 ]; then rec PASS integration "($(grep -c '^  PASS' "$OUT/logs/integration.log") checks)"; else rec FAIL integration "$BAD unexpected failure(s)  log: $OUT/logs/integration.log"; fi
step chaos 900 bash tests/chaos.sh "$BIN"

say ""; say "--- 3. root-only features: netns/tc, GRE/FOU, nft, WireGuard, raw socket, systemd"
if [ $IS_ROOT = 1 ]; then
  step doctor 120 "$BIN" doctor
  if have ip && have tc; then
    step netns-veth-netem 120 bash -c '
      set -e; N="$1"
      trap "ip netns del $N 2>/dev/null; ip link del vk$N 2>/dev/null" EXIT
      ip netns add "$N"
      ip link add "vk$N" type veth peer name "vp$N"
      ip link set "vp$N" netns "$N"
      ip addr add 10.99.250.1/30 dev "vk$N"; ip link set "vk$N" up
      ip netns exec "$N" ip addr add 10.99.250.2/30 dev "vp$N"
      ip netns exec "$N" ip link set "vp$N" up; ip netns exec "$N" ip link set lo up
      ping -c 2 -W 2 10.99.250.2 >/dev/null
      tc qdisc add dev "vk$N" root netem delay 40ms loss 5%
      tc qdisc show dev "vk$N" | grep -q netem
    ' _ "$((RANDOM % 90000 + 1000))"
    step netem-suite 3600 bash tests/netem.sh "$BIN"
  else
    skip netns-veth-netem "ip/tc (iproute2) missing"; skip netem-suite "ip/tc missing"
  fi
  if have ip; then
    step gre-tunnel 120 bash -c '
      set -e; S=$((RANDOM % 90000 + 1000)); N="khg$S"
      trap "ip netns del $N 2>/dev/null; ip link del gk$S 2>/dev/null; ip link del grek$S 2>/dev/null" EXIT
      ip netns add "$N"
      ip link add "gk$S" type veth peer name "gp$S"; ip link set "gp$S" netns "$N"
      ip addr add 10.99.251.1/30 dev "gk$S"; ip link set "gk$S" up
      ip netns exec "$N" ip addr add 10.99.251.2/30 dev "gp$S"; ip netns exec "$N" ip link set "gp$S" up
      ip link add "grek$S" type gre local 10.99.251.1 remote 10.99.251.2 ttl 64
      ip addr add 10.99.252.1/30 dev "grek$S"; ip link set "grek$S" up
      ip netns exec "$N" ip tunnel add "grep$S" mode gre local 10.99.251.2 remote 10.99.251.1 ttl 64
      ip netns exec "$N" ip addr add 10.99.252.2/30 dev "grep$S"; ip netns exec "$N" ip link set "grep$S" up
      ping -c 2 -W 2 10.99.252.2 >/dev/null'
    if modprobe fou 2>/dev/null || ip fou show >/dev/null 2>&1; then
      step fou-port 60 bash -c 'ip fou add port 59999 ipproto 47 && ip fou show | grep -q 59999; r=$?; ip fou del port 59999 2>/dev/null; exit $r'
    else skip fou-port "kernel module fou not available"; fi
    if modprobe wireguard 2>/dev/null || ip link add wgkhchk type wireguard 2>/dev/null; then
      ip link del wgkhchk 2>/dev/null
      step wireguard-link 60 bash -c 'ip link add wgkhchk type wireguard && ip link del wgkhchk'
    else skip wireguard-link "wireguard kernel support not available"; fi
  else
    skip gre-tunnel "ip missing"; skip fou-port "ip missing"; skip wireguard-link "ip missing"
  fi
  if have nft; then
    step nft-rules 60 bash -c 'nft add table inet khverify && nft add chain inet khverify c "{ type filter hook input priority 0; }" && nft list table inet khverify >/dev/null; r=$?; nft delete table inet khverify 2>/dev/null; exit $r'
  else skip nft-rules "nft missing (apt install nftables)"; fi
  step raw-socket-spoof 60 python3 -I - <<'PY'
import socket, struct, sys
def csum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b)//2), b)); s = (s >> 16) + (s & 0xffff); s += s >> 16
    return ~s & 0xffff
rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); rx.bind(("127.0.0.1", 0)); rx.settimeout(3)
port = rx.getsockname()[1]
payload = b"khaymali-spoof"
udp = struct.pack("!HHHH", 40000, port, 8 + len(payload), 0) + payload
src, dst = socket.inet_aton("127.0.0.5"), socket.inet_aton("127.0.0.1")
ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0x1234, 0, 64, socket.IPPROTO_UDP, 0, src, dst)
ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
tx.sendto(ip + udp, ("127.0.0.1", 0))
data, addr = rx.recvfrom(2048)
print("received", data, "from", addr)
sys.exit(0 if data == payload and addr[0] == "127.0.0.5" else 1)
PY
  if have systemd-analyze; then
    SD="$OUT/units"; mkdir -p "$SD"
    for u in deploy/systemd/*.service; do sed "s|/usr/local/bin/khaymali|$BIN|g" "$u" > "$SD/$(basename "$u")"; done
    step systemd-units 120 systemd-analyze verify "$SD"/khaymali-entry.service "$SD"/khaymali-exit.service "$SD"/khaymali-bridge.service
  else skip systemd-units "systemd-analyze missing"; fi
  if have systemctl && [ -d /run/systemd/system ]; then rec PASS systemd-running; else skip systemd-running "no systemd PID 1 (container?)"; fi
else
  for n in doctor netns-veth-netem netem-suite gre-tunnel fou-port wireguard-link nft-rules raw-socket-spoof systemd-units; do skip "$n" "needs root"; done
fi

say ""; say "--- 4. Telegram (real Bot API)"
if [ -n "${TG_TOKEN:-}" ] && [ -n "${TG_CHAT:-}" ]; then
  export TG_TOKEN TG_CHAT
  step tg-getme 60 bash -c 'set -o pipefail; printf "url = \"https://api.telegram.org/bot%s/getMe\"\n" "$TG_TOKEN" | curl -sS --max-time 20 -K - | grep -q "\"ok\":true"'
  step tg-send 60 bash -c 'set -o pipefail; printf "url = \"https://api.telegram.org/bot%s/sendMessage\"\n" "$TG_TOKEN" | curl -sS --max-time 20 -K - --data-urlencode "chat_id=$TG_CHAT" --data-urlencode "text=khaymali server_verify OK $(hostname) $(date -u +%FT%TZ)" | grep -q "\"ok\":true"'
else
  skip tg-getme "set TG_TOKEN and TG_CHAT to test real delivery"
  skip tg-send  "set TG_TOKEN and TG_CHAT to test real delivery"
fi

say ""; say "--- 5. stress (loopback, 10 hostile profiles x $STRESS_STEPS clients)"
if [ "$QUICK" = 1 ]; then
  skip stress-clean "--quick"; skip stress-netem "--quick"; skip stress-harsh-shadow "--quick"
  skip stress-harsh-active "--quick"; skip ab-compare "--quick"; skip ab-netns "--quick"
else
  step stress-clean 3600 env OUT="$OUT/stress-clean" POOL=16 bash tests/stress.sh "$BIN" 300
  if [ $IS_ROOT = 1 ] && have tc; then step stress-netem 7200 env NETEM=1 OUT="$OUT/stress-netem" POOL=16 bash tests/stress.sh "$BIN" 300
  else skip stress-netem "needs root + tc"; fi
  step stress-harsh-shadow 14400 env OUT="$OUT/shadow" POOL=48 REPEATS="$REPEATS" KHAYMALI_STEPS="$STRESS_STEPS" KHAYMALI_NLP_MODE=shadow bash tests/stress_harsh.sh "$BIN"
  step stress-harsh-active 14400 env OUT="$OUT/active" POOL=48 REPEATS="$REPEATS" KHAYMALI_STEPS="$STRESS_STEPS" KHAYMALI_NLP_MODE=active bash tests/stress_harsh.sh "$BIN"
  step ab-compare 120 python3 scripts/ab_compare.py "$OUT/shadow" "$OUT/active" --json "$OUT/ab.json"
  if [ -s "$OUT/active/replay_dataset.jsonl" ]; then
    step nlp-replay 600 python3 scripts/eval_nlp_replay.py "$BIN" "$OUT/active/replay_dataset.jsonl"
  else skip nlp-replay "no replay dataset produced"; fi
  if [ $IS_ROOT = 1 ] && have ip && have tc; then step ab-netns 7200 bash scripts/stress_harsh_300_ab.sh "$BIN" "$OUT/ab-netns"
  else skip ab-netns "needs root + ip + tc"; fi
fi

say ""
say "=== SUMMARY: $NP PASS, $NF FAIL, $NS SKIP ==="
say "Not covered by this script (needs two real servers): real Iran<->abroad path."
say "  -> run: scripts/real_path_check.sh  (see docs/RELEASE_GUIDE.md)"
say "Logs: $OUT/logs   Report: $REPORT"
[ "$NF" -eq 0 ]
