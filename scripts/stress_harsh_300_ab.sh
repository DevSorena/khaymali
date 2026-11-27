#!/usr/bin/env bash
# Khaymali v0.20.0 — 200 & 300 Concurrent-User Harsh-Network Stress & Micro-NLP A/B Suite
# Simulates 3 network profiles (good, bad, harsh) via Linux network namespace + tc netem
# and produces a side-by-side numeric A/B report (Shadow vs Active Micro-NLP).
#
# Usage:
#   sudo bash scripts/stress_harsh_300_ab.sh [BIN_PATH] [OUT_DIR]
#   STEPS="200 300" sudo bash scripts/stress_harsh_300_ab.sh target/release/khaymali /tmp/khaymali-ab
set -euo pipefail

BIN="${1:-target/release/khaymali}"
OUT_DIR="${2:-/tmp/khaymali-harsh-ab}"
STEPS="${STEPS:-200 300}"
PROFILES="${PROFILES:-good bad harsh}"

[[ -x "$BIN" ]] || { echo "Binary not found/executable: $BIN (run cargo build --release first)" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl required" >&2; exit 1; }
ulimit -n 65535 2>/dev/null || true
mkdir -p "$OUT_DIR"

USE_NETEM=0
if [[ "$(id -u)" -eq 0 ]] && command -v ip >/dev/null && command -v tc >/dev/null; then
  USE_NETEM=1
else
  echo "[WARN] Not root or missing ip/tc: running loopback stress without tc netem injection." >&2
fi

NS_EXIT="kh-ns-exit-$$"
VETH_EN="kh-ve-en-$$"
VETH_EX="kh-ve-ex-$$"
EN_IP="10.233.77.1"
EX_IP="10.233.77.2"
HTTP_PID=""
EX_PID=""
EN_PID=""

cleanup() {
  kill "$EN_PID" "$EX_PID" "$HTTP_PID" 2>/dev/null || true
  if [[ "$USE_NETEM" -eq 1 ]]; then
    ip netns del "$NS_EXIT" 2>/dev/null || true
    ip link del "$VETH_EN" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Prepare 64 KiB test payload & lightweight HTTP server
PAYLOAD_DIR="$OUT_DIR/www"
mkdir -p "$PAYLOAD_DIR"
python3 - "$PAYLOAD_DIR/payload.bin" <<'PYGEN'
import sys, os
with open(sys.argv[1], "wb") as f:
    f.write(os.urandom(65536))
PYGEN

if [[ "$USE_NETEM" -eq 1 ]]; then
  ip netns add "$NS_EXIT"
  ip link add "$VETH_EN" type veth peer name "$VETH_EX"
  ip link set "$VETH_EX" netns "$NS_EXIT"
  ip addr add "${EN_IP}/30" dev "$VETH_EN"
  ip link set "$VETH_EN" up
  ip netns exec "$NS_EXIT" ip link set lo up
  ip netns exec "$NS_EXIT" ip addr add "${EX_IP}/30" dev "$VETH_EX"
  ip netns exec "$NS_EXIT" ip link set "$VETH_EX" up
  ip netns exec "$NS_EXIT" python3 -m http.server 18080 --bind 127.0.0.1 -d "$PAYLOAD_DIR" >/dev/null 2>&1 &
  HTTP_PID=$!
  EXIT_DIAL_IP="$EX_IP"
else
  python3 -m http.server 18080 --bind 127.0.0.1 -d "$PAYLOAD_DIR" >/dev/null 2>&1 &
  HTTP_PID=$!
  EXIT_DIAL_IP="127.0.0.1"
fi

apply_netem() {
  local profile="$1"
  [[ "$USE_NETEM" -eq 1 ]] || return 0
  tc qdisc del dev "$VETH_EN" root 2>/dev/null || true
  ip netns exec "$NS_EXIT" tc qdisc del dev "$VETH_EX" root 2>/dev/null || true
  case "$profile" in
    good)
      tc qdisc add dev "$VETH_EN" root netem delay 15ms 2ms
      ip netns exec "$NS_EXIT" tc qdisc add dev "$VETH_EX" root netem delay 15ms 2ms
      ;;
    bad)
      tc qdisc add dev "$VETH_EN" root netem delay 65ms 18ms distribution normal loss 4% 25%
      ip netns exec "$NS_EXIT" tc qdisc add dev "$VETH_EX" root netem delay 65ms 18ms distribution normal loss 4% 25%
      ;;
    harsh)
      tc qdisc add dev "$VETH_EN" root netem delay 130ms 45ms distribution normal loss 12% 35% corrupt 1% reorder 5% 50%
      ip netns exec "$NS_EXIT" tc qdisc add dev "$VETH_EX" root netem delay 130ms 45ms distribution normal loss 12% 35% corrupt 1% reorder 5% 50%
      ;;
  esac
}

SEC=$("$BIN" secret)
EX_KEYS=$("$BIN" keygen)
EX_SK=$(echo "$EX_KEYS" | awk '/^private:/{print $2}')
EX_PK=$(echo "$EX_KEYS" | awk '/^public:/{print $2}')
EN_KEYS=$("$BIN" keygen)
EN_SK=$(echo "$EN_KEYS" | awk '/^private:/{print $2}')
EN_PK=$(echo "$EN_KEYS" | awk '/^public:/{print $2}')

run_mode() {
  local mode="$1"
  local profile="$2"
  local report_file="$OUT_DIR/report_${mode}_${profile}.json"

  apply_netem "$profile"
  kill "$EN_PID" "$EX_PID" 2>/dev/null || true
  sleep 0.3

  if [[ "$USE_NETEM" -eq 1 ]]; then
    ip netns exec "$NS_EXIT" "$BIN" exit --listen "${EX_IP}:29443" --wss-listen "${EX_IP}:29444" \
      --key "$EX_SK" --allow "$EN_PK" --allow-private --camo-secret "$SEC" \
      --control "$OUT_DIR/exit.sock" >/dev/null 2>&1 &
    EX_PID=$!
  else
    "$BIN" exit --listen "127.0.0.1:29443" --wss-listen "127.0.0.1:29444" \
      --key "$EX_SK" --allow "$EN_PK" --allow-private --camo-secret "$SEC" \
      --control "$OUT_DIR/exit.sock" >/dev/null 2>&1 &
    EX_PID=$!
  fi
  sleep 0.5

  KHAYMALI_NLP_MODE="$mode" "$BIN" entry --key "$EN_SK" --exit-pub "$EX_PK" \
    --exit "wss://${EXIT_DIAL_IP}:29444" --camo-secret "$SEC" --camo-sni localhost \
    --socks "127.0.0.1:29080" --pool 8 --control "$OUT_DIR/entry.sock" >/dev/null 2>&1 &
  EN_PID=$!
  sleep 0.8

  # Run Micro-NLP decision telemetry probe for this profile
  case "$profile" in
    good)  "$BIN" harsh-nlp eval --mode "$mode" --rtt 30 --base-rtt 28 --jitter 3 --loss 0.2 --retx 0.1 > "$OUT_DIR/nlp_${mode}_${profile}.json" ;;
    bad)   "$BIN" harsh-nlp eval --mode "$mode" --rtt 130 --base-rtt 30 --jitter 35 --loss 4.5 --retx 5.0 > "$OUT_DIR/nlp_${mode}_${profile}.json" ;;
    harsh) "$BIN" harsh-nlp eval --mode "$mode" --rtt 260 --base-rtt 30 --jitter 85 --loss 14.0 --retx 16.0 --log "TLS timeout burst loss" > "$OUT_DIR/nlp_${mode}_${profile}.json" ;;
  esac

  KHAYMALI_STEPS="$STEPS" bash "$(dirname "$0")/stress_live_300.sh" \
    "127.0.0.1:29080" "http://127.0.0.1:18080/payload.bin" 300 --json > "$report_file" || true
}

for profile in $PROFILES; do
  echo ">>> Running profile=$profile (mode=shadow) ..."
  run_mode "shadow" "$profile"
  echo ">>> Running profile=$profile (mode=active) ..."
  run_mode "active" "$profile"
done

python3 - "$OUT_DIR" $PROFILES <<'PYREP'
import sys, json, os
out_dir, profiles = sys.argv[1], sys.argv[2:]
print("\n=== KHAYMALI v0.20.0 HARSH-NETWORK 200/300 STRESS A/B REPORT ===")
print(f"{'PROFILE':<8} {'CONC':>4} | {'SH_OK%':>6} {'SH_P95':>8} {'SH_P99':>8} {'SH_KBPS':>9} | {'AC_OK%':>6} {'AC_P95':>8} {'AC_P99':>8} {'AC_KBPS':>9}")
print("-" * 92)
summary = {}
for p in profiles:
    sh = json.load(open(f"{out_dir}/report_shadow_{p}.json"))
    ac = json.load(open(f"{out_dir}/report_active_{p}.json"))
    summary[p] = {"shadow": sh["steps"], "active": ac["steps"]}
    for s_row, a_row in zip(sh["steps"], ac["steps"]):
        c = s_row["concurrency"]
        sok = 100.0 * s_row["ok"] / max(s_row["total"], 1)
        aok = 100.0 * a_row["ok"] / max(a_row["total"], 1)
        print(f"{p:<8} {c:>4} | {sok:>5.1f}% {s_row['p95_ms']:>7.1f}ms {s_row['p99_ms']:>7.1f}ms {s_row['goodput_kbps']:>9.1f} | {aok:>5.1f}% {a_row['p95_ms']:>7.1f}ms {a_row['p99_ms']:>7.1f}ms {a_row['goodput_kbps']:>9.1f}")
with open(f"{out_dir}/ab_summary.json", "w") as f:
    json.dump(summary, f, indent=2)
print(f"\nSaved JSON summary to {out_dir}/ab_summary.json")
PYREP
