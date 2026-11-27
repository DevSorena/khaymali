#!/usr/bin/env bash
# Loopback end-to-end test of the multi-Exit pool (balance / drain / failover / manual failback).
# Usage: tests/pool_e2e.sh [path/to/khaymali]
set -u
B=${1:-$(dirname "$0")/../target/release/khaymali}; B=$(readlink -f "$B")
T=$(mktemp -d); cd "$T" || exit 1
PIDS=""; PASS=0; FAIL=0
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null; done; rm -rf "$T"; }; trap cleanup EXIT
ok(){ echo "  PASS: $1"; PASS=$((PASS+1)); }; bad(){ echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
chk(){ if [ "$2" = yes ]; then ok "$1"; else bad "$1"; fi; }
EX=$("$B" keygen); EXPK=$(echo "$EX"|awk '/public/{print $2}'); EXSK=$(echo "$EX"|awk '/private/{print $2}')
EN=$("$B" keygen); ENPK=$(echo "$EN"|awk '/public/{print $2}'); ENSK=$(echo "$EN"|awk '/private/{print $2}')
"$B" exit --listen 127.0.0.1:5001 --key "$EXSK" --allow "$ENPK" >exitA.log 2>&1 & A=$!; PIDS="$PIDS $A"
"$B" exit --listen 127.0.0.1:5002 --key "$EXSK" --allow "$ENPK" >exitB.log 2>&1 & Bp=$!; PIDS="$PIDS $Bp"
sleep 1
start_entry() { # $@ = extra args
  "$B" entry --key "$ENSK" --exit-pub "$EXPK" --socks 127.0.0.1:1090 --pool 16 --no-adapt --control "$T/e.sock" "$@" >entry.log 2>&1 &
  E=$!; PIDS="$PIDS $E"; sleep 4
}
links() { "$B" pool status --control "$T/e.sock" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(' '.join(f\"{m['addr']}={m['links']}\" for m in d['members']))"; }
getl() { "$B" pool status --control "$T/e.sock" | python3 -c "
import sys,json
d=json.load(sys.stdin)
m={x['addr']:x['links'] for x in d['members']}
print(m.get('$1',0))"; }

echo "== balance 3:1"
start_entry --exit "127.0.0.1:5001;w=3" --exit "127.0.0.1:5002;w=1" --pool-mode balance
echo "   $(links)"
a=$(getl 127.0.0.1:5001); b=$(getl 127.0.0.1:5002)
chk "both exits get links" "$([ "$a" -gt 0 ] && [ "$b" -gt 0 ] && echo yes || echo no)"
chk "heavier exit holds more links ($a vs $b)" "$([ "$a" -gt "$b" ] && echo yes || echo no)"

echo "== drain A: new links stop going to A"
"$B" pool drain 127.0.0.1:5001 --control "$T/e.sock" | grep -q '"drain":true' && ok "drain accepted" || bad "drain accepted"
kill $E; wait $E 2>/dev/null
echo "== failover with standby"
start_entry --exit "127.0.0.1:5001;p=0" --exit "127.0.0.1:5002;p=1;standby" --pool-mode failover
a=$(getl 127.0.0.1:5001); b=$(getl 127.0.0.1:5002)
echo "   $(links)"
chk "primary serves, standby idle ($a / $b)" "$([ "$a" -gt 0 ] && [ "$b" -eq 0 ] && echo yes || echo no)"
kill -9 $A; sleep 25
a=$(getl 127.0.0.1:5001); b=$(getl 127.0.0.1:5002)
echo "   after primary died: $(links)"
chk "standby takes over after primary dies ($b links)" "$([ "$b" -gt 0 ] && echo yes || echo no)"
echo; echo "pool e2e: $PASS passed, $FAIL failed"; [ "$FAIL" = 0 ]
