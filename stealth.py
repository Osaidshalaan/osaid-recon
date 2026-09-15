"""Stealth layer: rate limiting, proxy rotation, header/timing randomization."""
import time, random, threading, itertools, httpx
from config import (PROXY_POOL, MAX_RPS, JITTER_MIN, JITTER_MAX,
                    STEALTH, ROTATE_PROXY_EVERY, UA_POOL)

# ---------- rate limiting ----------
class RateLimiter:
    def __init__(self, rps=MAX_RPS):
        self.min_interval = 1.0 / max(rps, 0.01)
        self._lock = threading.Lock()
        self._last = 0.0
    def wait(self):
        if not STEALTH: return
        with self._lock:
            now = time.time()
            delta = now - self._last
            if delta < self.min_interval:
                time.sleep(self.min_interval - delta)
            self._last = time.time()

import asyncio
class AsyncRateLimiter:
    def __init__(self, rps=MAX_RPS):
        self.min_interval = 1.0 / max(rps, 0.01)
        self._lock = asyncio.Lock()
        self._last = 0.0
    async def wait(self):
        if not STEALTH: return
        async with self._lock:
            loop = asyncio.get_event_loop()
            now = loop.time()
            delta = now - self._last
            if delta < self.min_interval:
                await asyncio.sleep(self.min_interval - delta)
            self._last = loop.time()

LIMITER = RateLimiter()
ALIMITER = AsyncRateLimiter()

# ---------- randomization ----------
def jitter():
    if STEALTH:
        time.sleep(random.uniform(JITTER_MIN, JITTER_MAX))

def rand_ua():
    return random.choice(UA_POOL)

def rand_headers():
    return {
        "User-Agent": rand_ua(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8",
        "Accept-Language": random.choice(["en-US,en;q=0.9", "ar,en-US;q=0.8,en;q=0.7"]),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Site": random.choice(["none", "same-origin"]),
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Cache-Control": random.choice(["no-cache", "max-age=0"]),
    }

# ---------- proxy rotation ----------
_pool_cycle = itertools.cycle(PROXY_POOL) if PROXY_POOL else None
_counter = itertools.count()

def pick_proxy():
    if not PROXY_POOL: return None
    if next(_counter) % max(ROTATE_PROXY_EVERY, 1) != 0:
        return pick_proxy._last
    proxy = next(_pool_cycle)
    pick_proxy._last = proxy
    return proxy
pick_proxy._last = None

def make_client(http2=True, timeout=20, follow_redirects=False, proxy=None):
    """New client with randomized headers + optional rotated proxy."""
    LIMITER.wait()
    hdrs = rand_headers()
    kwargs = dict(headers=hdrs, verify=False, timeout=timeout,
                  follow_redirects=follow_redirects, http2=http2)
    p = proxy if proxy is not None else pick_proxy()
    if p:
        kwargs["proxies"] = p
    return httpx.Client(**kwargs), p
