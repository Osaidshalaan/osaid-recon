#!/usr/bin/env python3
import sys
import stealth

SIGNS = [
    ("Cloudflare", {"header":"server","contains":"cloudflare"}),
    ("Cloudflare", {"header":"cf-ray","any":True}),
    ("CloudFront", {"header":"x-amz-cf-id","any":True}),
    ("CloudFront", {"header":"via","contains":"cloudfront"}),
    ("AWS WAF",    {"header":"x-amzn-requestid","any":True}),
    ("Akamai",     {"header":"server","contains":"akamai"}),
    ("Imperva",    {"header":"x-iinfo","any":True}),
    ("Sucuri",     {"header":"x-sucuri-id","any":True}),
    ("ModSecurity",{"body_any":["mod_security","modsecurity"]}),
]
PROBE = ["/?id=1%27%20OR%20%271%27%3D%271", "/../../etc/passwd", "/?q=<script>alert(1)</script>"]

def detect(url):
    client, proxy = stealth.make_client(http2=True, follow_redirects=True)
    base = client.get(url); hits = set()
    for name, sig in SIGNS:
        if "header" in sig:
            v = base.headers.get(sig["header"], "").lower()
            if sig.get("any") and v: hits.add(name)
            elif "contains" in sig and sig["contains"] in v: hits.add(name)
        if "body_any" in sig and any(k in base.text.lower() for k in sig["body_any"]): hits.add(name)
    for p in PROBE:
        try:
            r = client.get(url.rstrip("/") + p)
            if r.status_code in (403,406,429,503): hits.add(f"Blocking({r.status_code})")
        except Exception: pass
        stealth.jitter()
    client.close()
    return base, hits, proxy

if __name__ == "__main__":
    base, hits, proxy = detect(sys.argv[1])
    print(f"[*] baseline: {base.status_code} len={len(base.content)} server={base.headers.get('server','-')} proxy={proxy or 'direct'}")
    print(f"[*] WAF signals: {', '.join(sorted(hits)) if hits else 'none obvious'}")
