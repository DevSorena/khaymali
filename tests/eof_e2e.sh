#!/usr/bin/env bash
# Regression test: stream end (EOF) must cross the tunnel in BOTH directions with the default
# settings (mux + session resume). Before the fix a "Connection: close" response never ended
# for the client, and a client that half-closed its sending side hung the request.
set -u
B=${1:-$(dirname "$0")/../target/release/khaymali}; B=$(readlink -f "$B")
T=$(mktemp -d); cd "$T" || exit 1
PIDS=""; PASS=0; FAIL=0
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null; done; rm -rf "$T"; }; trap cleanup EXIT
ok(){ echo "  PASS: $1"; PASS=$((PASS+1)); }; bad(){ echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
EX=$("$B" keygen); EXPK=$(echo "$EX"|awk '/public/{print $2}'); EXSK=$(echo "$EX"|awk '/private/{print $2}')
EN=$("$B" keygen); ENPK=$(echo "$EN"|awk '/public/{print $2}'); ENSK=$(echo "$EN"|awk '/private/{print $2}')
cat > origin.py <<'PY'
import asyncio
async def h(r, w):
    try:
        if (await r.readline()).startswith(b"ECHO"):      # read until the client half-closes, then answer
            data = await r.read()
            w.write(b"GOT:" + data)
        else:
            await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 10)
            w.write(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nSTRESS-OK\n")   # no Content-Length: ends at EOF
        await w.drain()
    finally:
        w.close()
async def m():
    s = await asyncio.start_server(h, "127.0.0.1", 8000); await s.serve_forever()
asyncio.run(m())
PY
cat > client.py <<'PY'
import asyncio, socket, struct, sys
mode = sys.argv[1]
async def main():
    r, w = await asyncio.open_connection("127.0.0.1", 1080)
    w.write(b"\x05\x01\x00"); await w.drain(); await r.readexactly(2)
    w.write(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", 8000)); await w.drain()
    await r.readexactly(10)
    if mode == "close":
        w.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"); await w.drain()
    else:
        w.write(b"ECHO\npayload-123"); await w.drain(); w.write_eof()    # half-close
    d = await asyncio.wait_for(r.read(), 6)                              # needs EOF to return
    print(d.decode(errors="replace").strip())
asyncio.run(main())
PY
python3 origin.py & PIDS="$PIDS $!"
KHAYMALI_KEY=$EXSK "$B" exit --listen 127.0.0.1:4440 --allow "$ENPK" --allow-private >/dev/null 2>exit.log & PIDS="$PIDS $!"
sleep 1
KHAYMALI_KEY=$ENSK "$B" entry --socks 127.0.0.1:1080 --exit-pub "$EXPK" --exit 127.0.0.1:4440 --pool 8 >/dev/null 2>entry.log & PIDS="$PIDS $!"
sleep 4
grep -q "session_resume=true" entry.log && ok "default settings in use (mux + session resume)" || bad "session resume not active"
out=$(python3 client.py close 2>&1); case "$out" in *STRESS-OK) ok "server EOF reaches the client (close-delimited response)";; *) bad "server EOF reaches the client: '$out'";; esac
out=$(python3 client.py echo 2>&1);  [ "$out" = "GOT:payload-123" ] && ok "client half-close reaches the server, reply still arrives" || bad "client half-close: '$out'"
n=0; for i in $(seq 1 20); do case "$(python3 client.py close 2>&1)" in *STRESS-OK) n=$((n+1));; esac; done
[ "$n" = 20 ] && ok "20/20 sequential close-delimited requests" || bad "sequential requests: $n/20"
echo; echo "eof e2e: $PASS passed, $FAIL failed"; [ "$FAIL" = 0 ]
