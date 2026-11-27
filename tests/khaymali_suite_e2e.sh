#!/usr/bin/env bash
set -euo pipefail
BIN="${1:-target/release/khaymali}"
[[ -x "$BIN" ]] || { echo "usage: $0 <path-to-khaymali-binary>"; exit 2; }

echo "[1/5] Checking registered carriers..."
"$BIN" transports | grep -q "wss"
"$BIN" transports | grep -q "ssh-bagher"
"$BIN" transports | grep -q "spoof-wg"
"$BIN" transports | grep -q "gre-6to4"
"$BIN" transports | grep -q "gre-4in6"

echo "[2/5] Checking GRE /30 allocator & wrap dry-run..."
"$BIN" carrier pair --used 10.11.10.0/24 | grep -q "10.11.11.1/30"
"$BIN" carrier wrap 6to4 --iface gre-test --local-inner 10.11.11.1 --peer-inner 10.11.11.2 \
  --local-v4 198.51.100.1 --remote-v4 203.0.113.2 | grep -q "mode sit"

echo "[3/5] Checking Spoof+WireGuard generator & SPOOF1 bundle parse..."
OUT=$("$BIN" spoof gen --role local --local-ip 198.51.100.1 --peer-ip 203.0.113.2 \
  --spoof-ips 1.1.1.1,8.8.8.8 --forward 443)
BUNDLE=$(echo "$OUT" | grep "^SPOOF1:" | head -n1)
"$BIN" spoof parse "$BUNDLE" | grep -q "ip=198.51.100.1"

echo "[4/5] Checking Iran-to-Iran Hub Mesh NAT rule generation..."
"$BIN" mesh hub-fwd --port 443 --proto both --peer-hub 198.51.100.9 | grep -q "KHAYMALI-HUBFWD"

echo "[5/5] Checking live WS + WSS Exit <-> Entry tunnel..."
SEC=$("$BIN" secret)
EX_KEYS=$("$BIN" keygen)
EX_SK=$(echo "$EX_KEYS" | awk '/^private:/{print $2}')
EX_PK=$(echo "$EX_KEYS" | awk '/^public:/{print $2}')
EN_KEYS=$("$BIN" keygen)
EN_SK=$(echo "$EN_KEYS" | awk '/^private:/{print $2}')
EN_PK=$(echo "$EN_KEYS" | awk '/^public:/{print $2}')

TMP=$(mktemp -d)
trap 'kill $PID_EX $PID_EN 2>/dev/null || true; rm -rf "$TMP"' EXIT

"$BIN" exit --listen 127.0.0.1:28443 --ws-listen 127.0.0.1:28080 --wss-listen 127.0.0.1:28444 \
  --key "$EX_SK" --allow "$EN_PK" --allow-private --camo-secret "$SEC" \
  --control "$TMP/exit.sock" &
PID_EX=$!
sleep 0.5

"$BIN" entry --key "$EN_SK" --exit-pub "$EX_PK" \
  --exit "wss://127.0.0.1:28444" --exit "ws://127.0.0.1:28080" \
  --camo-secret "$SEC" --camo-sni localhost \
  --socks 127.0.0.1:28081 --egress-bridge 127.0.0.1:28088 \
  --dial-mode auto --dial-gre-addr 10.11.11.2:443 --dial-public-addr 127.0.0.1:28443 \
  --pool 2 --control "$TMP/entry.sock" &
PID_EN=$!
sleep 1.2

"$BIN" health --control "$TMP/entry.sock" | grep -q '"verdict":"PASS"'
"$BIN" dial status --control "$TMP/entry.sock" | grep -q '"mode":"auto"'
"$BIN" carrier swap "ws://127.0.0.1:28080" --control "$TMP/entry.sock" | grep -q '"ok":true'

echo "ALL KHAYMALI SUITE E2E CHECKS PASSED!"
