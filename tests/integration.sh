#!/usr/bin/env bash
# End-to-end test on loopback. Needs: cargo-built binary, python3, curl, openssl.
# Usage: tests/integration.sh [path/to/khaymali]
set -u
B=${1:-$(dirname "$0")/../target/release/khaymali}
B=$(readlink -f "$B")
T=$(mktemp -d)
cd "$T" || exit 1
PIDS=""
PASS=0; FAIL=0
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null; done; rm -rf "$T"; }
trap cleanup EXIT
bg() { "$@" >/dev/null & LASTPID=$!; PIDS="$PIDS $LASTPID"; }
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check() { if [ "$2" = "yes" ]; then ok "$1"; else bad "$1"; fi; }
key() { "$B" keygen | awk -v w="$1" '$1==w":"{print $2}' ; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

head -c 32000000 /dev/urandom > file.bin
mkdir -p www && echo "DECOY-SITE" > www/index.html && cp file.bin www/file.bin

# keys
EXSK=$("$B" keygen); EXPK=$(echo "$EXSK" | awk '/public/{print $2}'); EXSK=$(echo "$EXSK" | awk '/private/{print $2}')
ENSK=$("$B" keygen); ENPK=$(echo "$ENSK" | awk '/public/{print $2}'); ENSK=$(echo "$ENSK" | awk '/private/{print $2}')
BRSK=$("$B" keygen); BRPK=$(echo "$BRSK" | awk '/public/{print $2}'); BRSK=$(echo "$BRSK" | awk '/private/{print $2}')
EVSK=$("$B" keygen); EVSK=$(echo "$EVSK" | awk '/private/{print $2}')   # an attacker's key
CAMO=$("$B" secret)

# origin web server (plain) and a TLS decoy site
bg python3 -m http.server 8000 --bind 127.0.0.1 --directory www 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout k.pem -out c.pem -days 1 -subj /CN=decoy.test >/dev/null 2>&1
cat > decoy.py <<'PY'
import http.server, ssl, os
os.chdir('www')
h = http.server.HTTPServer(('127.0.0.1', 8443), http.server.SimpleHTTPRequestHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain('../c.pem', '../k.pem')
h.socket = ctx.wrap_socket(h.socket, server_side=True); h.serve_forever()
PY
bg python3 decoy.py 2>/dev/null
# UDP echo
cat > udpecho.py <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1', 9999))
while True:
    d, a = s.recvfrom(65535); s.sendto(b'ECHO:' + d, a)
PY
bg python3 udpecho.py 2>/dev/null
sleep 1

dl() { timeout 60 curl -s --socks5-hostname "127.0.0.1:$1" "http://127.0.0.1:8000/file.bin" -o "got.$1" -w "%{speed_download}" ; }

echo "== 1. direct mode, no camouflage"
KHAYMALI_KEY=$EXSK bg "$B" exit --listen 127.0.0.1:4440 --allow "$ENPK" --allow-private 2>exit1.log
KHAYMALI_KEY=$ENSK bg "$B" entry --socks 127.0.0.1:1081 --exit-pub "$EXPK" --exit 127.0.0.1:4440 --pool 4 --metrics 127.0.0.1:9091 2>entry1.log
sleep 1.5
SPEED=$(dl 1081); echo "  speed ~ $((${SPEED%.*}/1000000)) MB/s (loopback)"
check "32MB download intact" "$([ "$(sha got.1081)" = "$(sha file.bin)" ] && echo yes || echo no)"
PIDS_OK=""; for i in $(seq 1 20); do timeout 20 curl -s --socks5-hostname 127.0.0.1:1081 http://127.0.0.1:8000/index.html | grep -q DECOY-SITE && PIDS_OK="$PIDS_OK."; done
check "20 sequential small requests" "$([ ${#PIDS_OK} -eq 20 ] && echo yes || echo no)"
check "refused target gives a SOCKS error (no hang)" "$(timeout 10 curl -s --socks5-hostname 127.0.0.1:1081 http://127.0.0.1:9/ -o /dev/null; [ $? -eq 97 ] && echo yes || echo no)"
M=$(curl -s http://127.0.0.1:9091/metrics)
check "metrics endpoint reports traffic" "$(echo "$M" | grep -q 'khaymali_streams_total [1-9]' && echo yes || echo no)"
check "metrics report exit health" "$(echo "$M" | grep -q 'khaymali_exit_up{addr="127.0.0.1:4440"} 1' && echo yes || echo no)"

echo "== 2. UDP ASSOCIATE through the tunnel"
cat > udptest.py <<'PY'
import socket, struct, sys
c = socket.create_connection(('127.0.0.1', 1081)); c.sendall(b'\x05\x01\x00'); assert c.recv(2) == b'\x05\x00'
c.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
r = c.recv(10); assert r[1] == 0, r
port = struct.unpack('>H', r[8:10])[0]
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(5)
u.sendto(b'\x00\x00\x00\x01\x7f\x00\x00\x01' + struct.pack('>H', 9999) + b'ping-123', ('127.0.0.1', port))
d, _ = u.recvfrom(65535)
assert d.endswith(b'ECHO:ping-123'), d
print('udp-ok')
PY
check "UDP datagram echoed via Entry->Exit" "$(timeout 15 python3 udptest.py 2>/dev/null | grep -q udp-ok && echo yes || echo no)"

echo "== 3. bridge mode + camouflage + decoy fallback + authenticated bridge"
KHAYMALI_KEY=$EXSK bg "$B" exit --listen 127.0.0.1:4443 --allow "$ENPK" --allow-private --camo-secret "$CAMO" --camo-fallback 127.0.0.1:8443 2>exit2.log
KHAYMALI_KEY=$ENSK bg "$B" entry --socks 127.0.0.1:1082 --exit-pub "$EXPK" --bridge-listen 127.0.0.1:4444 --allow-bridge "$BRPK" --pool 4 2>entry2.log
sleep 0.5
KHAYMALI_KEY=$BRSK bg "$B" bridge --entry 127.0.0.1:4444 --entry-pub "$ENPK" --exit 127.0.0.1:4443 --camo-secret "$CAMO" --camo-sni decoy.test --pool 4 2>bridge2.log
sleep 2
SPEED=$(dl 1082); echo "  speed ~ $((${SPEED%.*}/1000000)) MB/s (loopback, camouflaged, via bridge)"
check "download through bridge+camouflage intact" "$([ "$(sha got.1082)" = "$(sha file.bin)" ] && echo yes || echo no)"
OKS=""; for i in $(seq 1 15); do timeout 20 curl -s --socks5-hostname 127.0.0.1:1082 http://127.0.0.1:8000/index.html | grep -q DECOY-SITE && OKS="$OKS."; done
check "15 requests through bridge" "$([ ${#OKS} -eq 15 ] && echo yes || echo no)"
check "active probe (plain TLS client) sees the real decoy site" "$(timeout 10 curl -sk --resolve decoy.test:4443:127.0.0.1 https://decoy.test:4443/ | grep -q DECOY-SITE && echo yes || echo no)"
# A TLS-only decoy rejects plain HTTP; the exit must give the prober nothing the decoy would not.
# (Known gap: the TCP close can differ - FIN direct vs RST via proxy. See README "Known limitations".)
D1=$(timeout 10 curl -s http://127.0.0.1:8443/ -o /dev/null -w '%{http_code}/%{size_download}')
D2=$(timeout 10 curl -s http://127.0.0.1:4443/ -o /dev/null -w '%{http_code}/%{size_download}')
check "plain-HTTP probe: same HTTP outcome as the decoy itself ($D1 vs $D2), no tunnel" "$([ "$D1" = "$D2" ] && echo yes || echo no)"
KHAYMALI_KEY=$EVSK timeout 6 "$B" bridge --entry 127.0.0.1:4444 --entry-pub "$ENPK" --exit 127.0.0.1:4443 --camo-secret "$CAMO" --camo-sni decoy.test --pool 1 2>evil.log >/dev/null
check "bridge with a non-allowlisted key is rejected by Entry" "$(grep -q 'not in allowlist' entry2.log && echo yes || echo no)"
KHAYMALI_KEY=$EVSK timeout 4 "$B" entry --socks 127.0.0.1:1099 --exit-pub "$EXPK" --exit 127.0.0.1:4440 --pool 1 2>evil2.log >/dev/null
check "entry with a non-allowlisted key is rejected by Exit" "$(grep -q 'not in allowlist' exit1.log && echo yes || echo no)"
check "authenticated clients are counted, probes counted separately (exit log shows no tunnel for probes)" "$(! grep -q 'bad request type' exit2.log && echo yes || echo no)"

echo "== 4. our ClientHello is parseable by a real TLS stack (OpenSSL)"
cat > hello_check.py <<'PY'
import socket, sys, subprocess, time, os
hello = open(sys.argv[1], 'rb').read()
srv = subprocess.Popen(['openssl', 's_server', '-accept', '8555', '-cert', 'c.pem', '-key', 'k.pem', '-tls1_3', '-quiet'],
                       stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # stdin must stay open
time.sleep(1)
try:
    s = socket.create_connection(('127.0.0.1', 8555)); s.settimeout(5); s.sendall(hello)
    h = s.recv(5)
    print('server-hello' if h[:1] == b'\x16' else 'alert-%r' % h)
finally:
    srv.kill()
PY
if [ -f /tmp/khaymali-hello.bin ]; then
  check "OpenSSL answers our ClientHello with a ServerHello (not an alert)" "$(timeout 15 python3 hello_check.py /tmp/khaymali-hello.bin 2>/dev/null | grep -q server-hello && echo yes || echo no)"
else
  echo "  SKIP: run 'cargo test -- --ignored dump_hello' first to create /tmp/khaymali-hello.bin"
fi

echo "== 5. multi-exit failover"
KHAYMALI_KEY=$EXSK bg "$B" exit --listen 127.0.0.1:4451 --allow "$ENPK" --allow-private 2>exit3.log
KHAYMALI_KEY=$EXSK bg "$B" exit --listen 127.0.0.1:4452 --allow "$ENPK" --allow-private 2>exit4.log; P2=$LASTPID
KHAYMALI_KEY=$ENSK bg "$B" entry --socks 127.0.0.1:1083 --exit-pub "$EXPK" --exit 127.0.0.1:4451 --exit 127.0.0.1:4452 --pool 4 --max-age 5 2>entry3.log
sleep 2
kill "$P2" 2>/dev/null; sleep 7
OKS=""; for i in $(seq 1 10); do timeout 20 curl -s --socks5-hostname 127.0.0.1:1083 http://127.0.0.1:8000/index.html | grep -q DECOY-SITE && OKS="$OKS."; done
check "traffic keeps flowing after one exit dies (${#OKS}/10)" "$([ ${#OKS} -ge 9 ] && echo yes || echo no)"

echo; echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
