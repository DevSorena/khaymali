#!/usr/bin/env bash
# Stepped live tunnel stress test: 10, 25, 50, 100, 200, 300 concurrent SOCKS5 clients (SPEC §8)
# Usage: bash scripts/stress_live_300.sh [SOCKS_ADDR] [TARGET_URL] [MAX_STEP] [--json]
# Only the heavy steps:  KHAYMALI_STEPS="200 300" bash scripts/stress_live_300.sh
set -euo pipefail

SOCKS_ADDR="${1:-127.0.0.1:1080}"
TARGET_URL="${2:-http://127.0.0.1:8000/index.html}"
MAX_STEP="${3:-300}"
JSON_MODE=0
for arg in "$@"; do
  [ "$arg" = "--json" ] && JSON_MODE=1
done
# Safety guard: this load generator is intentionally restricted to loopback-only test rigs.
SOCKS_HOST="${SOCKS_ADDR%:*}"
TARGET_HOST="$(python3 - "$TARGET_URL" <<'PYURL'
import sys, urllib.parse
try: print(urllib.parse.urlparse(sys.argv[1]).hostname or "")
except Exception: print("")
PYURL
)"
case "$SOCKS_HOST" in 127.*|localhost|::1) ;; *) echo "Refusing non-loopback SOCKS target: $SOCKS_ADDR" >&2; exit 2;; esac
case "$TARGET_HOST" in 127.*|localhost|::1) ;; *) echo "Refusing non-loopback target URL: $TARGET_URL" >&2; exit 2;; esac

ulimit -n 65535 2>/dev/null || true
command -v curl >/dev/null || { echo "curl required" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }

python3 - "$SOCKS_ADDR" "$TARGET_URL" "$MAX_STEP" "$JSON_MODE" <<'PYEOF'
import sys, time, json, subprocess, concurrent.futures

socks, url, max_step, json_mode = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4] == "1"
import os
only = os.environ.get("KHAYMALI_STEPS", "").split()
steps = [int(x) for x in only] if only else [s for s in (10, 25, 50, 100, 200, 300) if s <= max_step]
if max_step < 1 or max_step > 300:
    raise SystemExit("MAX_STEP must be between 1 and 300")
if not steps or any(x not in (10, 25, 50, 100, 200, 300) for x in steps):
    raise SystemExit("KHAYMALI_STEPS may contain only 10 25 50 100 200 300")

def rss_mb():
    try:
        out = subprocess.check_output(["pgrep", "-x", "khaymali"], text=True).split()
        total_kb = 0
        for pid in out:
            with open(f"/proc/{pid}/status") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        total_kb += int(line.split()[1])
        return round(total_kb / 1024.0, 2)
    except Exception:
        return 0.0

def one(_):
    t0 = time.monotonic()
    p = subprocess.run(
        ["curl", "-fsS", "--max-time", "12", "--socks5-hostname", socks, "-o", "/dev/null", "-w", "%{size_download}", url],
        capture_output=True, text=True
    )
    ms = (time.monotonic() - t0) * 1000.0
    sz = int(p.stdout.strip()) if p.returncode == 0 and p.stdout.strip().isdigit() else 0
    return (p.returncode == 0, ms, sz)

report = {"schema_version": 1, "timestamp": int(time.time()), "socks": socks, "url": url, "steps": []}
if not json_mode:
    print(f"=== KHAYMALI STEPPED LIVE STRESS ({socks} -> {url}) ===")

failed_any = False
for conc in steps:
    t0 = time.monotonic()
    times, total_bytes = [], 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as ex:
        for ok, ms, sz in ex.map(one, range(conc)):
            if ok:
                times.append(ms)
                total_bytes += sz
    wall = max(time.monotonic() - t0, 1e-6)
    times.sort()
    n_ok = len(times)
    p50 = round(times[int(n_ok * 0.50)], 2) if n_ok else 0.0
    p95 = round(times[int(n_ok * 0.95)], 2) if n_ok else 0.0
    p99 = round(times[int(n_ok * 0.99)], 2) if n_ok else 0.0
    kbps = round((total_bytes * 8.0) / (wall * 1000.0), 1)
    rss = rss_mb()
    step_rec = {
        "concurrency": conc, "ok": n_ok, "total": conc,
        "p50_ms": p50, "p95_ms": p95, "p99_ms": p99,
        "goodput_kbps": kbps, "rss_mb": rss
    }
    report["steps"].append(step_rec)
    if not json_mode:
        print(f" [STEP {conc:>3}] ok={n_ok:>3}/{conc:<3} | p50={p50:>6.1f}ms p95={p95:>6.1f}ms p99={p99:>6.1f}ms | goodput={kbps:>8.1f}kbps | RSS={rss}MB")
    if n_ok < int(conc * 0.95):
        failed_any = True

if json_mode:
    print(json.dumps(report, indent=2))
sys.exit(1 if failed_any else 0)
PYEOF
