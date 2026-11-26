#!/usr/bin/env bash
# Harsh-network stress: 200, 250, 300 concurrent SOCKS5 clients over 10 hostile profiles.
# Captures real entry.log lines + LinkMetrics snapshots; records remain unlabeled until independently annotated
# Usage:
#   bash tests/stress_harsh.sh target/release/khaymali
#   KHAYMALI_NLP_MODE=shadow OUT=/tmp/khaymali-shadow bash tests/stress_harsh.sh
#   KHAYMALI_NLP_MODE=active OUT=/tmp/khaymali-active bash tests/stress_harsh.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
B="$(readlink -f "${1:-$HERE/../target/release/khaymali}")"
OUT="${OUT:-/tmp/khaymali-harsh}"
POOL="${POOL:-48}"
STEPS="${KHAYMALI_STEPS:-200 250 300}"
# v0.15.1: repetitions per profile/step so ab_compare.py can separate effects from run-to-run noise
REPEATS="${REPEATS:-3}"
TIMEOUT_S="${REQ_TIMEOUT:-20}"
export KHAYMALI_NLP_MODE="${KHAYMALI_NLP_MODE:-shadow}"
mkdir -p "$OUT"
: > "$OUT/replay_dataset.jsonl"
ulimit -n 65535 2>/dev/null || true

command -v python3 >/dev/null || { echo "need python3" >&2; exit 1; }
[ -x "$B" ] || { echo "binary not found: $B (run: cargo build --release)" >&2; exit 1; }

T=$(mktemp -d); PIDS=""
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null; done; rm -rf "$T"; }
trap cleanup EXIT

cat >"$T/origin.py" <<'PY'
import asyncio, os
BODY_OK = b"STRESS-OK\n"
BODY_64K = os.urandom(65536)
async def handle(r, w):
    try:
        req = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 10)
        body = BODY_64K if b"/small.bin" in req.split(b"\r\n", 1)[0] else BODY_OK
        w.write(f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
        await w.drain()
    except Exception:
        pass
    finally:
        try: w.close()
        except Exception: pass
async def main():
    srv = await asyncio.start_server(handle, "127.0.0.1", 8000, backlog=2048)
    async with srv: await srv.serve_forever()
asyncio.run(main())
PY

cat >"$T/socks_stress.py" <<'PY'
import asyncio, json, socket, struct, subprocess, sys, time
socks_h, socks_p = sys.argv[1].rsplit(":", 1)
socks_p, path, conc, timeout_s = int(socks_p), sys.argv[2], int(sys.argv[3]), float(sys.argv[4])

def rss_mb():
    try:
        pids = subprocess.check_output(["pgrep", "-x", "khaymali"], text=True).split()
        kb = sum(int(l.split()[1]) for p in pids for l in open(f"/proc/{p}/status") if l.startswith("VmRSS:"))
        return round(kb / 1024.0, 2)
    except Exception:
        return 0.0

async def one():
    t0, w = time.monotonic(), None
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(socks_h, socks_p), timeout_s)
        w.write(b"\x05\x01\x00"); await w.drain()
        if await asyncio.wait_for(r.readexactly(2), timeout_s) != b"\x05\x00": return (False, 0.0, 0)
        w.write(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", 8000)); await w.drain()
        if (await asyncio.wait_for(r.readexactly(10), timeout_s))[1] != 0: return (False, 0.0, 0)
        w.write(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".encode()); await w.drain()
        data = await asyncio.wait_for(r.read(), timeout_s)
        ok = b"200 OK" in data[:64] and (len(data) >= 65536 if path == "/small.bin" else b"STRESS-OK" in data)
        return (ok, (time.monotonic() - t0) * 1000.0, len(data))
    except Exception:
        return (False, 0.0, 0)
    finally:
        if w is not None:
            try: w.close()
            except Exception: pass

async def main():
    t0 = time.monotonic()
    res = await asyncio.gather(*(one() for _ in range(conc)))
    wall = max(time.monotonic() - t0, 1e-6)
    times = sorted(ms for ok, ms, _ in res if ok)
    total_b = sum(sz for ok, _, sz in res if ok)
    n_ok = len(times)
    p = lambda q: round(times[min(int(n_ok * q), n_ok - 1)], 2) if n_ok else 0.0
    print(json.dumps({"schema_version": 2, "timestamp": int(time.time()), "steps": [{
        "concurrency": conc, "ok": n_ok, "total": conc,
        "p50_ms": p(0.50), "p95_ms": p(0.95), "p99_ms": p(0.99),
        "goodput_kbps": round((total_b * 8.0) / (wall * 1000.0), 1), "rss_mb": rss_mb()
    }]}, indent=2))
asyncio.run(main())
PY

python3 "$T/origin.py" 2>>"$T/origin.log" & PIDS="$PIDS $!"
EX=$("$B" keygen); EXPK=$(echo "$EX" | awk '/public/{print $2}'); EXSK=$(echo "$EX" | awk '/private/{print $2}')
EN=$("$B" keygen); ENPK=$(echo "$EN" | awk '/public/{print $2}'); ENSK=$(echo "$EN" | awk '/private/{print $2}')
sleep 1

declare -A OPTS=(
  [clean]=""
  [lat300_jit100]="--delay 300 --jitter 100"
  [loss10_retx]="--delay 60 --jitter 30 --retx 0.10"
  [loss25_retx]="--delay 80 --jitter 40 --retx 0.25"
  [throttle_256k]="--rate 262144 --delay 80"
  [rst_early30]="--rst-early 0.30"
  [freeze16k_30]="--freeze 0.30 --freeze-at 16384"
  [pmtu_drop_4k]="--pmtu-drop-gt 4096 --pmtu-p 0.60"
  [blackhole_burst]="--blackhole-every 20 --blackhole-for 4"
  [hostile_mix]="--delay 120 --jitter 60 --retx 0.12 --rst-early 0.10 --freeze 0.10 --rate 524288"
)
declare -A LABEL=(
  [clean]="healthy" [lat300_jit100]="throttle" [loss10_retx]="throttle" [loss25_retx]="throttle"
  [throttle_256k]="throttle" [rst_early30]="early_rst" [freeze16k_30]="byte_freeze"
  [pmtu_drop_4k]="pmtu_drop" [blackhole_burst]="route_or_dns_fail" [hostile_mix]="throttle"
)
declare -A MINOK=(
  [clean]=95 [lat300_jit100]=90 [loss10_retx]=90 [loss25_retx]=75 [throttle_256k]=85
  [rst_early30]=80 [freeze16k_30]=80 [pmtu_drop_4k]=80 [blackhole_burst]=70 [hostile_mix]=65
)
[ "${STRICT:-0}" = 1 ] && for k in "${!MINOK[@]}"; do MINOK[$k]=95; done
ORDER="${PROFILES:-clean lat300_jit100 loss10_retx loss25_retx throttle_256k rst_early30 freeze16k_30 pmtu_drop_4k blackhole_burst hostile_mix}"

echo "=== KHAYMALI HARSH STRESS (NLP_MODE=$KHAYMALI_NLP_MODE, STEPS=$STEPS, POOL=$POOL) ==="
FAIL=0
for name in $ORDER; do
  opts="${OPTS[$name]-}"; min="${MINOK[$name]:-85}"; lbl="${LABEL[$name]:-unrelated}"
  : > "$T/entry.log"
  python3 "$HERE/harsh_proxy.py" 127.0.0.1:4441 127.0.0.1:4440 $opts 2>"$T/proxy-$name.log" & PX=$!
  KHAYMALI_KEY=$EXSK "$B" exit --listen 127.0.0.1:4440 --allow "$ENPK" --allow-private >/dev/null 2>"$T/exit.log" & EXP=$!
  KHAYMALI_KEY=$ENSK "$B" entry --socks 127.0.0.1:1080 --exit-pub "$EXPK" --exit 127.0.0.1:4441 --pool "$POOL" --metrics 127.0.0.1:9109 >/dev/null 2>"$T/entry.log" & ENP=$!
  sleep 2
  echo "=== profile: $name [$opts] (min ok ${min}%) ==="
  up=no
  for _ in 1 2 3 4 5 6; do
    if python3 "$T/socks_stress.py" 127.0.0.1:1080 /index.html 1 10 | grep -q '"ok": 1'; then up=yes; break; fi
    sleep 1
  done
  if [ "$up" = no ]; then
    echo "  tunnel never came up"; tail -3 "$T/entry.log"; FAIL=1
  else
    for s in $STEPS; do
     for rep in $(seq 1 "$REPEATS"); do
      J="$OUT/$name-$s-r$rep.json"
      python3 "$T/socks_stress.py" 127.0.0.1:1080 /small.bin "$s" "$TIMEOUT_S" > "$J"
      # attach the NLP counters at this point (actions / reverts / rate-limited) for ab_compare.py
      python3 - "$J" <<'PY' || true
import json, sys, urllib.request
p = sys.argv[1]; d = json.load(open(p))
try:
    txt = urllib.request.urlopen("http://127.0.0.1:9109/metrics", timeout=2).read().decode()
    kv = {l.split()[0][9:]: float(l.split()[1]) for l in txt.splitlines() if l.startswith("khaymali_nlp_") and len(l.split()) == 2}
    d["steps"][0]["nlp"] = {k: kv.get(k, 0) for k in ("nlp_actions_total", "nlp_reverts_total", "nlp_rate_limited_total", "nlp_recommendations_total")}
except Exception:
    pass
json.dump(d, open(p, "w"))
PY
      python3 - "$J" "$min" <<'PY' || FAIL=1
import json, sys
r = json.load(open(sys.argv[1]))["steps"][0]; need = int(sys.argv[2]); pct = 100.0 * r["ok"] / r["total"]
print(f"  [{r['concurrency']:>3} clients] ok={r['ok']}/{r['total']} ({pct:.1f}%) p50={r['p50_ms']}ms p95={r['p95_ms']}ms p99={r['p99_ms']}ms goodput={r['goodput_kbps']}kbps rss={r['rss_mb']}MB -> {'PASS' if pct>=need else 'FAIL'}")
sys.exit(0 if pct >= need else 1)
PY
     done
    done
    python3 - "$T/entry.log" "$OUT/replay_dataset.jsonl" "$name" "$lbl" "${LABEL_FROM_PROFILE:-0}" <<'PY' || true
import json, sys, urllib.request
log_path, out_path, prof, lbl, use_lbl = sys.argv[1:6]
runtime_metrics, raw = {}, {}
try:
    txt = urllib.request.urlopen("http://127.0.0.1:9109/metrics", timeout=2).read().decode()
    for line in txt.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].startswith("khaymali_"):
            try: raw[parts[0][len("khaymali_"):]] = float(parts[1])
            except ValueError: pass
    def val(k, d=0): return raw.get(k, d)
    has_stall = val("nlp_link_has_stall") >= 1
    metrics = {
        "loss_pct": val("nlp_link_loss_per_mille") / 10.0,
        "rtt_ms": int(val("nlp_link_rtt_ms")),
        "base_rtt_ms": int(val("nlp_link_base_rtt_ms")),
        "jitter_ms": int(val("nlp_link_jitter_ms")),
        "retransmit_pct": val("nlp_link_retransmit_tenths_pct") / 10.0,
        "stall_bytes": int(val("nlp_link_stall_bytes")) if has_stall else None,
        "rx_idle_ms": int(val("nlp_link_rx_idle_ms")),
        "resets_last_min": int(val("nlp_link_resets_last_min")),
        "connect_fail_ratio": val("nlp_link_connect_fail_per_mille") / 1000.0,
        "big_frames_lost": val("nlp_link_big_frames_lost") >= 1,
        "small_frames_ok": val("nlp_link_small_frames_ok") >= 1,
    }
    runtime_metrics = {k: v for k, v in raw.items() if k.startswith(("nlp_", "adaptive_", "links_ready", "link_fail"))}
    if runtime_metrics:
        print("  metrics:", " | ".join(f"{k}={v}" for k, v in list(runtime_metrics.items())[:8]))
except Exception:
    metrics = {}
with open(log_path, errors="replace") as f, open(out_path, "a") as out:
    for line in f:
        line = line.strip()
        if not line: continue
        rec = {"profile": prof, "profile_hint": lbl, "log": line, "runtime_metrics": runtime_metrics}
        if use_lbl == "1": rec["expected"] = lbl
        if metrics: rec["metrics"] = metrics
        out.write(json.dumps(rec, ensure_ascii=False) + "\n")
PY
    sleep 2; rec=no
    for _ in 1 2 3 4 5; do
      if python3 "$T/socks_stress.py" 127.0.0.1:1080 /index.html 1 10 | grep -q '"ok": 1'; then rec=yes; break; fi
      sleep 1
    done
    echo "  post-storm recovery: $rec"; [ "$rec" = yes ] || FAIL=1
  fi
  grep -h "harsh_proxy" "$T/proxy-$name.log" | tail -1 || true
  kill $PX $EXP $ENP 2>/dev/null; wait $PX $EXP $ENP 2>/dev/null; sleep 1
done

echo; echo "JSON reports: $OUT/*.json | Real-log replay dataset: $OUT/replay_dataset.jsonl"
[ $FAIL -eq 0 ] && echo "ALL 10 PROFILES PASS" || echo "SOME PROFILES FAILED"
exit $FAIL
