#!/usr/bin/env python3
import re, httpx
try: import dns.resolver
except ImportError: dns = None
import fingerprints as fp
SIG_F5 = "bigipserver"; SIG_ASM = "ts01"
CDN = ("cloudflare","cloudfront","akamai","fastly","sucuri","imperva","incapsula","edgecast","stackpath","bunny","gcore")

def _host(ip): return f"[{ip}]" if ":" in ip else ip

def gather(domain):
    ips = set()
    try:
        r = httpx.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=30)
        for rec in r.json().get("passive_dns", []):
            if rec.get("address"): ips.add(rec["address"])
    except Exception: pass
    try:
        r = httpx.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=30)
        for line in r.text.splitlines():
            if "," in line:
                ip = line.split(",",1)[1].strip()
                if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip): ips.add(ip)
    except Exception: pass
    try:
        r = httpx.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100", timeout=30)
        for res in r.json().get("results", []):
            ip = res.get("page", {}).get("ip")
            if ip: ips.add(ip)
    except Exception: pass
    try:
        r = httpx.get(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=30,
                      headers={"User-Agent":"Mozilla/5.0"})
        for m in re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", r.text): ips.add(m)
    except Exception: pass
    if dns:
        try:
            for a in dns.resolver.resolve(domain, "A", lifetime=8): ips.add(a.to_text())
        except Exception: pass
    return ips

def _title(t):
    tl = t.lower()
    if "<title" in tl:
        return tl.split("<title",1)[1].split(">",1)[1].split("</title",1)[0].strip()[:60]
    return ""

def reference(domain):
    try:
        r = httpx.get(f"https://{domain}/", verify=False, timeout=15, follow_redirects=True,
                      headers={"User-Agent":"Mozilla/5.0"})
        return {"len": len(r.content), "title": _title(r.text), "favicon": fp.favicon_hash(f"https://{domain}")}
    except Exception:
        return {"len":0,"title":"","favicon":None}

def test_ip(ip, domain, ref):
    for sch in ("https","http"):
        try:
            r = httpx.get(f"{sch}://{_host(ip)}/", headers={"Host": domain, "User-Agent":"Mozilla/5.0"},
                          verify=False, timeout=10, follow_redirects=True)
            srv = r.headers.get("server","-"); via = r.headers.get("via","")
            ck = " ".join(r.headers.get_list("set-cookie")).lower()
            title = _title(r.text)
            is_cdn = any(m in srv.lower() for m in CDN) or "cloudfront" in via.lower()
            reasons = []
            if SIG_F5 in ck: reasons.append("F5-cookie")
            if SIG_ASM in ck: reasons.append("ASM-cookie")
            if ref["title"] and title and ref["title"][:30] == title[:30] and not is_cdn: reasons.append("title")
            return {"ip":ip,"scheme":sch,"status":r.status_code,"server":srv,
                    "cdn":is_cdn,"reasons":reasons,"origin":bool(reasons) and not is_cdn}
        except Exception:
            continue
    return {"ip":ip,"origin":False,"error":"unreachable","reasons":[],"server":"-","cdn":False}

def find(domain, verbose=True):
    ref = reference(domain)
    if verbose: print(f"[*] reference: title={ref['title'][:40]!r} len={ref['len']}")
    ips = gather(domain)
    if verbose: print(f"[*] {len(ips)} IPs")
    found = []
    for ip in sorted(ips):
        res = test_ip(ip, domain, ref)
        if verbose:
            tag = ""
            if res.get("cdn"): tag = "   [CDN edge - skip]"
            elif res.get("origin"): tag = "   <<< ORIGIN: " + ",".join(res.get("reasons",[]))
            print(f"  {ip:26} {res.get('status',res.get('error',''))}  server={res.get('server','-')}{tag}")
        if res.get("origin"): found.append(ip)
    return found

if __name__ == "__main__":
    import sys; print(find(sys.argv[1]))
