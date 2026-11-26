#!/usr/bin/env python3
"""Userspace impairment proxy (no root needed) between Entry and Exit.
Supports all KANI TinyNetNlp v4 harsh-network failure modes:
  --delay MS --jitter MS       latency + jitter per chunk
  --retx P --rto MS            simulated packet loss + RTO stall
  --rate BPS                   per-connection bandwidth cap (throttle)
  --rst-early F                fraction F of connections RST right after first bytes
  --freeze F --freeze-at N     fraction F stall silently after N server->client bytes
  --pmtu-drop-gt N --pmtu-p P  drop/hang chunks > N bytes with prob P (small keepalives pass)
  --blackhole-every S --blackhole-for S  periodic total drop windows
"""
import asyncio, argparse, random, socket, struct, sys, time

ap = argparse.ArgumentParser()
ap.add_argument("listen"); ap.add_argument("target")
ap.add_argument("--delay", type=float, default=0); ap.add_argument("--jitter", type=float, default=0)
ap.add_argument("--retx", type=float, default=0); ap.add_argument("--rto", type=float, default=200)
ap.add_argument("--rate", type=float, default=0)
ap.add_argument("--rst-early", type=float, default=0)
ap.add_argument("--freeze", type=float, default=0); ap.add_argument("--freeze-at", type=int, default=16384)
ap.add_argument("--pmtu-drop-gt", type=int, default=0); ap.add_argument("--pmtu-p", type=float, default=0.5)
ap.add_argument("--blackhole-every", type=float, default=0); ap.add_argument("--blackhole-for", type=float, default=0)
ap.add_argument("--seed", type=int, default=1)
a = ap.parse_args()
rnd = random.Random(a.seed)
T0 = time.monotonic()
host, port = a.target.rsplit(":", 1)
stats = {"conns": 0, "rst": 0, "frozen": 0, "pmtu_drops": 0, "blackholed": 0}

def in_blackhole():
    if not a.blackhole_every:
        return False
    return ((time.monotonic() - T0) % a.blackhole_every) >= (a.blackhole_every - a.blackhole_for)

def hard_rst(w):
    try:
        s = w.get_extra_info("socket")
        if s is not None:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except Exception:
        pass
    try:
        w.transport.abort()
    except Exception:
        pass

async def impair(n):
    d = a.delay + (rnd.uniform(-a.jitter, a.jitter) if a.jitter else 0.0)
    if a.retx and rnd.random() < a.retx:
        d += a.rto * rnd.choice((1, 1, 2, 4))
    if a.rate:
        d += (n / a.rate) * 1000.0
    if d > 0:
        await asyncio.sleep(d / 1000.0)

async def pipe(r, w, freeze_after=None, rst_first=False, peer=None):
    sent = 0
    try:
        while True:
            data = await r.read(16384)
            if not data:
                break
            if rst_first and sent == 0:
                stats["rst"] += 1
                hard_rst(peer)
                hard_rst(w)
                return
            if a.pmtu_drop_gt > 0 and len(data) > a.pmtu_drop_gt and rnd.random() < a.pmtu_p:
                stats["pmtu_drops"] += 1
                await asyncio.sleep(15)
                continue
            await impair(len(data))
            if freeze_after is not None and sent + len(data) > freeze_after:
                stats["frozen"] += 1
                await asyncio.sleep(3600)
            w.write(data)
            await w.drain()
            sent += len(data)
    except Exception:
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass

async def handle(cr, cw):
    stats["conns"] += 1
    if in_blackhole():
        stats["blackholed"] += 1
        cw.transport.abort()
        return
    try:
        sr, sw = await asyncio.wait_for(asyncio.open_connection(host, int(port)), 10)
    except Exception:
        cw.transport.abort()
        return
    rst = rnd.random() < a.rst_early
    frz = a.freeze_at if rnd.random() < a.freeze else None
    await asyncio.gather(
        pipe(cr, sw, rst_first=rst, peer=cw),
        pipe(sr, cw, freeze_after=frz),
    )

async def reporter():
    while True:
        await asyncio.sleep(10)
        print("[harsh_proxy]", stats, file=sys.stderr, flush=True)

async def main():
    lh, lp = (a.listen.rsplit(":", 1) if ":" in a.listen else ("127.0.0.1", a.listen))
    srv = await asyncio.start_server(handle, lh, int(lp), backlog=2048)
    asyncio.create_task(reporter())
    async with srv:
        await srv.serve_forever()

asyncio.run(main())
