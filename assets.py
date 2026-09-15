#!/usr/bin/env python3
"""Asset intelligence: role + confidence + evidence per candidate."""
import time, httpx
import f5_origin, fingerprints as fp
CDN_ORG = ("cloudflare","amazon","akamai","fastly","sucuri","imperva","incapsula",
           "google","microsoft","edgecast","stackpath","bunny","gcore")
CDN_SRV = ("cloudflare","cloudfront","akamai","fastly","sucuri","imperva",
           "incapsula","edgecast","stackpath")
_CACHE = {}
def _host(ip): return f"[{ip}]" if ":" in ip else ip

def whois_ip(ip):
    if ip in _CACHE: return _CACHE[ip]
    info = {"org":"","as":"","isp":"","hosting":None}
    try:
        r = httpx.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        j = r.json(); org = j.get("org","") or ""
        if org:
            parts = org.split(" ",1)
            info["as"] = parts[0] if parts[0].startswith("AS") else ""
            info["org"] = parts[1] if len(parts)>1 else org
            info["isp"] = info["org"]
    except Exception: pass
    if not info["org"]:
        try:
            r = httpx.get(f"http://ip-api.com/json/{ip}?fields=status,org,as,isp,hosting", timeout=10)
            j = r.json()
            if j.get("status")=="success":
                info = {"org":j.get("org",""),"as":j.get("as",""),
                        "isp":j.get("isp",""),"hosting":j.get("hosting",False)}
        except Exception: pass
    if not info["org"]:
        try:
            r = httpx.get(f"https://rdap.org/ip/{ip}", timeout=12, follow_redirects=True)
            name = r.json().get("name","") or ""
            if name: info["org"] = name
        except Exception: pass
    _CACHE[ip] = info; return info


def probe_ip(ip, domain, ref):
    for sch in ("https","http"):
        try:
            r = httpx.get(f"{sch}://{_host(ip)}/", headers={"Host":domain,"User-Agent":"Mozilla/5.0"},
                          verify=False, timeout=10, follow_redirects=True)
            title = f5_origin._title(r.text)
            san = fp.cert_san(ip).get("san",[]) if sch=="https" and ":" not in ip else []
            san_match = any(s == domain or s.endswith("."+domain) for s in san)
            return {"ip":ip,"reachable":True,"status":r.status_code,
                    "server":r.headers.get("server","-"),"len":len(r.content),
                    "title_match":bool(ref["title"] and title and ref["title"][:30]==title[:30]),
                    "san_match":san_match,"scheme":sch}
        except Exception:
            continue
    return {"ip":ip,"reachable":False,"server":"-","title_match":False,"san_match":False}

def classify(c):
    ev=[]; srv=(c.get("server") or "").lower(); org=(c.get("org") or "").lower()
    if any(m in srv for m in CDN_SRV) or any(m in org for m in CDN_ORG):
        return {"role":"CDN_EDGE","confidence":100,"evidence":["- CDN provider/server"]}
    if not c.get("reachable"):
        return {"role":"REJECTED","confidence":10,"evidence":["- unreachable"]}
    score=40; ev.append("+ non-CDN server/ASN")
    if c.get("title_match"): score+=25; ev.append("+ title matches reference")
    if c.get("san_match"):   score+=20; ev.append("+ TLS SAN matches domain")
    if c.get("hosting") is False: score+=5; ev.append("+ not datacenter-hosted")
    if c.get("hosting") is True:  score-=10; ev.append("- datacenter-hosted")
    score=max(0,min(100,score))
    role=("CONFIRMED" if score>=80 else "PROBABLE" if score>=60 else "POSSIBLE" if score>=35 else "REJECTED")
    return {"role":role,"confidence":score,"evidence":ev}

def analyze(domain, verbose=True):
    ref=f5_origin.reference(domain); ips=f5_origin.gather(domain)
    if verbose: print(f"[*] {len(ips)} candidates | ref title={ref['title'][:30]!r}")
    rows=[]
    for ip in sorted(ips):
        p=probe_ip(ip,domain,ref); info=whois_ip(ip); p.update(info); a=classify(p)
        rows.append({"ip":ip,"provider":(info["org"] or info["isp"] or "Unknown"),
                     "asn":info["as"],"role":a["role"],"confidence":a["confidence"],
                     "evidence":a["evidence"],"server":p.get("server","-")})
        if verbose: print(f"  {ip:24} {a['role']:<11} {a['confidence']:>3}/100  {info['org'][:26]}")
        time.sleep(0.3)
    rows.sort(key=lambda r:-r["confidence"]); return rows

def print_inventory(domain, rows):
    print(f"\nAsset Inventory — {domain}")
    print(f"{'IP':<24}{'Provider':<24}{'Role':<12}{'Conf':<6}{'Server'}")
    print("-"*90)
    for r in rows:
        print(f"{r['ip']:<24}{r['provider'][:22]:<24}{r['role']:<12}{r['confidence']:<6}{r['server']}")
    print("\nEvidence:")
    for r in rows:
        print(f"\n  {r['ip']}  ({r['role']}, {r['confidence']}/100)")
        for e in r["evidence"]: print(f"    {e}")
