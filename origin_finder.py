#!/usr/bin/env python3
import sys, re, httpx, dns.resolver
import fingerprints as fp
from config import (SECURITYTRAILS_KEY, VIRUSTOTAL_KEY, SHODAN_KEY,
                    CENSYS_ID, CENSYS_SECRET, COMMON_SUBS)
def crt_sh(domain):
    try:
        r = httpx.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30)
        names = {n.strip().lower() for row in r.json() for n in row.get("name_value","").split("\n")}
        return {n for n in names if n.endswith(domain) and "*" not in n}
    except Exception as e: print(f"[!] crt.sh: {e}"); return set()
def passive_dns(domain):
    ips = set()
    if SECURITYTRAILS_KEY:
        try:
            r = httpx.get(f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
                          headers={"APIKEY": SECURITYTRAILS_KEY}, timeout=30)
            for rec in r.json().get("records", []):
                for v in rec.get("values", []):
                    if v.get("ip"): ips.add(v["ip"])
        except Exception as e: print(f"[!] securitytrails: {e}")
    if VIRUSTOTAL_KEY:
        try:
            r = httpx.get(f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions",
                          headers={"x-apikey": VIRUSTOTAL_KEY}, timeout=30)
            for item in r.json().get("data", []):
                ip = item["attributes"].get("ip_address")
                if ip: ips.add(ip)
        except Exception as e: print(f"[!] virustotal: {e}")
    return ips
def censys_search(domain):
    if not (CENSYS_ID and CENSYS_SECRET): return set()
    ips = set()
    try:
        r = httpx.post("https://search.censys.io/api/v2/hosts/search",
                       auth=(CENSYS_ID, CENSYS_SECRET),
                       json={"q": f"services.tls.certificates.leaf.names: {domain}", "per_page": 50}, timeout=30)
        for hit in r.json().get("result", {}).get("hits", []):
            if hit.get("ip"): ips.add(hit["ip"])
    except Exception as e: print(f"[!] censys: {e}")
    return ips
def dns_records(domain):
    out = {"A": [], "MX": [], "TXT": []}
    for t in out:
        try:
            for a in dns.resolver.resolve(domain, t, lifetime=10): out[t].append(a.to_text())
        except Exception: pass
    return out
def spf_hosts(txts):
    ips, hosts = set(), set()
    for t in txts:
        if "v=spf1" in t:
            for tok in t.split():
                tok = tok.lstrip("+-~?").replace("include:","").replace("a:","").replace("ip4:","").replace("ip6:","")
                if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", tok): ips.add(tok)
                elif "." in tok: hosts.add(tok)
    return ips, hosts
def sub_ips(domain):
    found = {}
    for s in COMMON_SUBS:
        try:
            for a in dns.resolver.resolve(f"{s}.{domain}", "A", lifetime=6):
                found.setdefault(a.to_text(), []).append(f"{s}.{domain}")
        except Exception: continue
    return found
def shodan_enrich(ip):
    if not SHODAN_KEY: return None
    try:
        j = httpx.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}", timeout=30).json()
        return {"org": j.get("org"), "ports": j.get("ports"), "hostnames": j.get("hostnames")}
    except Exception: return None
def run(domain, confirm=True):
    domain = domain.replace("https://","").replace("http://","").strip("/")
    print(f"[*] target: {domain}\n")
    print(f"[*] CT names: {len({domain} | crt_sh(domain))}")
    rec = dns_records(domain); spf_ips, hosts = spf_hosts(rec["TXT"])
    print(f"[*] MX: {rec['MX']}"); print(f"[*] SPF ips: {spf_ips}  hosts: {hosts}")
    subs = sub_ips(domain); print(f"[*] subdomain A: {subs}")
    candidates = set(spf_ips) | set(subs.keys()) | passive_dns(domain) | censys_search(domain)
    for h in hosts:
        try:
            for a in dns.resolver.resolve(h, "A", lifetime=6): candidates.add(a.to_text())
        except Exception: pass
    if not candidates:
        print("[-] no candidates"); return set()
    ref = fp.profile(f"https://{domain}") if confirm else None
    if confirm: print(f"[*] ref: favicon={ref['favicon']} jarm={ref['jarm']} san={ref['cert']['san'][:3]}")
    print("\n[+] candidates:")
    confirmed = set()
    for ip in sorted(candidates):
        line = f"    {ip}"
        if confirm:
            score, reasons = fp.matches(ref, fp.profile(f"https://{ip}"))
            line += f"  score={score} {reasons}"
            if score >= 2: confirmed.add(ip)
        enr = shodan_enrich(ip)
        if enr: line += f"  {enr}"
        print(line)
    return confirmed or candidates
if __name__ == "__main__":
    run(sys.argv[1])
