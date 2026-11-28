#!/usr/bin/env python3
"""Tiny SOCKS5 (no auth, CONNECT only) used by tests/scripts_selftest.sh as a stand-in for the
Khaymali Entry, so the load generator and impairment proxy can be tested without the binary.
usage: mini_socks5.py HOST:PORT"""
import asyncio, socket, struct, sys

async def pipe(r, w):
    try:
        while (b := await r.read(65536)):
            w.write(b); await w.drain()
    except Exception:
        pass
    finally:
        try: w.close()
        except Exception: pass

async def handle(r, w):
    try:
        ver, n = struct.unpack("!BB", await r.readexactly(2))
        await r.readexactly(n); w.write(b"\x05\x00")
        _, cmd, _, atyp = struct.unpack("!BBBB", await r.readexactly(4))
        if atyp == 1: host = socket.inet_ntoa(await r.readexactly(4))
        elif atyp == 3: host = (await r.readexactly((await r.readexactly(1))[0])).decode()
        else: w.close(); return
        port = struct.unpack("!H", await r.readexactly(2))[0]
        ur, uw = await asyncio.open_connection(host, port)
        w.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"); await w.drain()
        await asyncio.gather(pipe(r, uw), pipe(ur, w))
    except Exception:
        try: w.close()
        except Exception: pass

async def main():
    h, p = sys.argv[1].rsplit(":", 1)
    srv = await asyncio.start_server(handle, h, int(p), backlog=1024)
    async with srv: await srv.serve_forever()

asyncio.run(main())
