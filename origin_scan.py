#!/usr/bin/env python3
import asyncio, argparse, random
import stealth
from config import HIGH_VALUE_PORTS, SCAN_CONC

async def probe(ip, port, sem, timeout=1.5):
    async with sem:
        await stealth.ALIMITER.wait()
        await asyncio.sleep(random.uniform(0.02, 0.2))
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
            w.close(); return port, True
        except Exception:
            return port, False

async def main(ip, ports, conc=SCAN_CONC):
    sem = asyncio.Semaphore(conc); random.shuffle(ports); open_ports = []
    for coro in asyncio.as_completed([probe(ip, p, sem) for p in ports]):
        p, ok = await coro
        if ok: open_ports.append(p); print(f"[+] {ip}:{p} open")
    print(f"\n[*] open: {sorted(open_ports) or 'none'}")
    return sorted(open_ports)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("ip")
    ap.add_argument("-p", "--ports", default=HIGH_VALUE_PORTS)
    ap.add_argument("-c", "--conc", type=int, default=SCAN_CONC)
    a = ap.parse_args()
    ports = []
    for part in a.ports.split(","):
        if "-" in part:
            lo, hi = map(int, part.split("-")); ports += list(range(lo, hi+1))
        else: ports.append(int(part))
    asyncio.run(main(a.ip, ports, a.conc))
