#!/usr/bin/env bash
# Loopback test: the whole tunnel goes down, then the UDP carrier comes back.
# Checks down/recovered detection, the history file and the webhook alerts.
# (The carrier switch itself is covered by the deterministic Rust tests in src/autopilot.rs.)
set -u
B=${1:-$(dirname "$0")/../target/release/khaymali}; B=$(readlink -f "$B")
T=$(mktemp -d); cd "$T" || exit 1
PIDS=""; PASS=0; FAIL=0
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null; done; rm -rf "$T"; }; trap cleanup EXIT
ok(){ echo "  PASS: $1"; PASS=$((PASS+1)); }; bad(){ echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
chk(){ if [ "$2" = yes ]; then ok "$1"; else bad "$1"; fi; }
EX=$("$B" keygen); EXPK=$(echo "$EX"|awk '/public/{print $2}'); EXSK=$(echo "$EX"|awk '/private/{print $2}')
EN=$("$B" keygen); ENPK=$(echo "$EN"|awk '/public/{print $2}'); ENSK=$(echo "$EN"|awk '/private/{print $2}')
S=$("$B" secret)
cat > hook.py <<'PY'
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get('content-length',0)); open('hook.log','ab').write(self.rfile.read(n)+b'\n')
        self.send_response(200); self.end_headers()
    def log_message(self,*a): pass
http.server.HTTPServer(('127.0.0.1',9911),H).serve_forever()
PY
python3 hook.py & PIDS="$PIDS $!"
"$B" exit --listen 127.0.0.1:5001 --key "$EXSK" --allow "$ENPK" --camo-secret "$S" >exitA.log 2>&1 & A=$!; PIDS="$PIDS $A"
sleep 1
"$B" entry --key "$ENSK" --exit-pub "$EXPK" --socks 127.0.0.1:1091 --pool 4 --no-adapt \
  --camo-secret "$S" --camo-sni example.com \
  --exit 127.0.0.1:5001 --exit udp://127.0.0.1:5002 \
  --autopilot --ap-down 1 --ap-cooldown 1 --ap-state "$T/ap.state" \
  --alert-webhook http://127.0.0.1:9911/hook >entry.log 2>&1 & E=$!; PIDS="$PIDS $E"
sleep 8
grep -q "autopilot\] on" entry.log && ok "autopilot started" || bad "autopilot started"
kill -9 $A; echo "   TCP exit killed; whole tunnel is down"
sleep 20
"$B" exit --listen 127.0.0.1:5003 --udp-listen 127.0.0.1:5002 --key "$EXSK" --allow "$ENPK" --camo-secret "$S" >exitB.log 2>&1 & PIDS="$PIDS $!"
echo "   UDP carrier started; the pool should recover it before the 1-minute window ends"
for i in $(seq 1 20); do grep -q "recovered" ap.state 2>/dev/null && break; sleep 3; done
echo "   --- autopilot status"; "$B" autopilot --state "$T/ap.state" | sed 's/^/   /'
grep -q "^E|[0-9]*|recovered|" ap.state && ok "tunnel recovered on the UDP carrier" || bad "tunnel recovered on the UDP carrier"
! grep -q "^E|[0-9]*|switched|" ap.state && ok "autopilot did not switch needlessly (pool failover was faster)" || bad "needless switch"
sleep 3
grep -q "down" hook.log 2>/dev/null && ok "webhook got the down alert" || bad "webhook got the down alert"
grep -q "recovered" hook.log 2>/dev/null && ok "webhook got the recovered alert" || bad "webhook got the recovered alert"
[ "$FAIL" != 0 ] && { echo "--- entry.log (tail)"; tail -n 25 entry.log; }
echo; echo "autopilot e2e: $PASS passed, $FAIL failed"; [ "$FAIL" = 0 ]
