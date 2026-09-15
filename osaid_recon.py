#!/usr/bin/env python3
"""osaid-recon — unified deep reconnaissance console (final)."""
import sys, asyncio, ipaddress, datetime, re, httpx
import waf_detect, origin_finder, origin_scan, evade_client, f5_origin
import assets, diff_engine, deep_discovery
from config import HIGH_VALUE_PORTS, SCAN_CONC

S = {"domain":None,"url":None,"candidates":[],"waf":None,"open_ports":{},"log":[]}
ASM_PAYLOADS = {
 "clean":"/","sqli":"/?id=1 UNION SELECT 1,2,3--","xss":"/?q=<script>alert(1)</script>",
 "traversal":"/../../etc/passwd","cmd":"/?cmd=;id","ssti":"/?name={{7*7}}",
 "log4j":"/?x=${jndi:ldap://x/a}","unicode":"/?id=1%u0027%20OR%201=1",
}
def norm(raw):
    r=raw.strip().replace("https://","").replace("http://","").strip("/")
    return r.split("/")[0], f"https://{r}"
def header(t): print("\n"+"="*62+f"\n  {t}\n"+"="*62)
def ask(p,d=None): v=input(p).strip(); return v if v else d
def note(m): S["log"].append(f"{datetime.datetime.now().isoformat(timespec='seconds')}  {m}")
def parse_ports(s):
    o=[]
    for p in s.split(","):
        if "-" in p:
            a,b=map(int,p.split("-")); o+=list(range(a,b+1))
        else: o.append(int(p))
    return o
def f5_decode(v):
    a,b,c=v.split("."); a=int(a)
    ip=".".join(str((a>>(8*i))&0xFF) for i in range(4))
    port=int.from_bytes(int(b).to_bytes(2,"big"),"little")
    return ip,port
def p_waf():
    header("WAF fingerprint")
    base,hits,px = waf_detect.detect(S["url"]); S["waf"]=sorted(hits)
    print(f"[*] {base.status_code} len={len(base.content)} server={base.headers.get('server','-')}")
    print(f"[*] signals: {', '.join(S['waf']) or 'none'}"); note(f"WAF {S['waf']}")
def p_origin():
    header("Origin discovery (ranked)")
    c=set(origin_finder.run(S["domain"])) | set(f5_origin.find(S["domain"]))
    S["candidates"]=sorted(c); print(f"[+] candidates: {S['candidates'] or 'none'}"); note(f"candidates {S['candidates']}")
def p_assets():
    header("Asset inventory")
    rows=assets.analyze(S["domain"]); assets.print_inventory(S["domain"], rows); note(f"assets {len(rows)}")
def p_deep():
    header("Deep discovery"); deep_discovery.run(S["url"])
def p_diff():
    header("HTTP differential")
    base=diff_engine.baseline(S["url"])
    for r in diff_engine.probe(base, S["url"], ASM_PAYLOADS):
        print(f"  {r['label']:12} {r['status']} sim={r['similarity']:.2%} {r['conclusion']}")
def p_scan():
    header("Port scan")
    if S["candidates"]:
        for i,c in enumerate(S["candidates"],1): print(f"    {i}) {c}")
        pk=ask("[?] number / IP: "); ip=S["candidates"][int(pk)-1] if pk.isdigit() else pk
    else: ip=ask("[?] IP: ")
    try: ipaddress.ip_address(ip)
    except ValueError: print("[!] invalid IP"); return
    sp=ask(f"[?] ports [{HIGH_VALUE_PORTS}]: ", HIGH_VALUE_PORTS)
    S["open_ports"][ip]=asyncio.run(origin_scan.main(ip, parse_ports(sp), SCAN_CONC)); note(f"scan {ip}: {S['open_ports'][ip]}")
def p_evade():
    header("Evasion / direct-origin")
    path=ask("[?] path [/]: ","/"); via=None
    if S["candidates"]:
        for i,c in enumerate(S["candidates"],1): print(f"    {i}) {c}")
        pk=ask("[?] route via (number/IP/empty=front): ")
        via=S["candidates"][int(pk)-1] if pk.isdigit() else (pk or None)
    r=evade_client.send(S["url"], path, via=via, host=S["domain"] if via else None)
    print("\n[+] body head:\n", r.text[:500]) if r is not None else print("[-] blocked")
    note(f"evade via {via}: {'OK' if r else 'BLK'}")
def p_asm():
    header("ASM policy map")
    with httpx.Client(verify=False,timeout=20,follow_redirects=True,headers={"User-Agent":"Mozilla/5.0"}) as c:
        for n,p in ASM_PAYLOADS.items():
            try:
                r=c.get(S["url"].rstrip("/")+p); print(f"  {n:11} {r.status_code} len={len(r.content)}")
            except Exception as e: print(f"  {n:11} ERR {e}")
def p_api():
    header("API / JS endpoints"); seen=set()
    with httpx.Client(verify=False,timeout=25,follow_redirects=True,headers={"User-Agent":"Mozilla/5.0"}) as c:
        try: html=c.get(S["url"]).text
        except Exception as e: print(f"[!] {e}"); return
        for s in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']',html):
            u=s if s.startswith("http") else S["url"].rstrip("/")+(s if s.startswith("/") else "/"+s)
            try: js=c.get(u).text
            except Exception: continue
            for p in re.findall(r'["\'`](/[a-zA-Z0-9._\-/]{2,60})["\'`]',js):
                if any(k in p.lower() for k in ("api","v1","v2","graphql","rest","login","auth","user","admin","token","config")) and p not in seen:
                    seen.add(p); print("   ",p)
def p_decode():
    header("F5 cookie decode"); v=ask("[?] cookie value: ")
    if not v: return
    if not re.fullmatch(r"\d+\.\d+\.\d+", v): print("[!] bad format. example: 687871404.47873.0000"); return
    ip,po=f5_decode(v); print(f"[+] internal backend: {ip}:{po}"); note(f"decode {v} -> {ip}:{po}")
def p_report():
    ts=datetime.datetime.now().strftime("%Y%m%d-%H%M%S"); fn=f"report_{S['domain']}_{ts}.md"
    with open(fn,"w") as f:
        f.write(f"# Recon — {S['domain']}\n\n- {datetime.datetime.now().isoformat(timespec='seconds')}\n")
        f.write(f"- WAF: {S['waf']}\n- candidates: {S['candidates']}\n\n## ports\n")
        for ip,ps in S["open_ports"].items(): f.write(f"- {ip}: {ps}\n")
        f.write("\n## log\n"+"\n".join("- "+l for l in S["log"])+"\n")
    print(f"[+] {fn}")
def p_auto():
    p_waf(); p_origin(); p_assets()
    if S["candidates"]:
        top=S["candidates"][0]; header(f"auto scan {top}")
        S["open_ports"][top]=asyncio.run(origin_scan.main(top, parse_ports("80,443,8080,8443,22,3306,3389"), SCAN_CONC))
        header(f"auto direct-origin via {top}")
        r=evade_client.send(S["url"],"/",via=top,host=S["domain"])
        note(f"auto top={top} evade={'OK' if r else 'BLK'}")
    p_report()
def selftest():
    ip,po=f5_decode("1677787402.36895.0000")
    assert (ip,po)==("10.1.1.100",8080), f"decode FAIL {ip}:{po}"
    assert norm("https://a.b/c/d")==("a.b","https://a.b/c/d"), "norm FAIL"
    import stealth
    print("[selftest] PASS — decode OK, norm OK, stealth OK, modules OK")
MENU = """
  1) WAF fingerprint
  2) Origin discovery
  3) Asset inventory
  4) Deep discovery
  5) HTTP differential
  6) Port scan
  7) Evasion / direct-origin
  8) ASM policy map
  9) API / JS endpoints
 10) Decode F5 cookie
 11) AUTO full chain
 12) Export report
 13) Change target
  0) Exit
"""
def main():
    if "--selftest" in sys.argv: selftest(); return
    print("osaid-recon")
    while not S["domain"]:
        raw=ask("[?] target: ")
        if raw: S["domain"],S["url"]=norm(raw)
    print(f"[*] target {S['domain']}")
    while True:
        print(MENU); c=ask("  choose> ")
        try:
            if c=="1": p_waf()
            elif c=="2": p_origin()
            elif c=="3": p_assets()
            elif c=="4": p_deep()
            elif c=="5": p_diff()
            elif c=="6": p_scan()
            elif c=="7": p_evade()
            elif c=="8": p_asm()
            elif c=="9": p_api()
            elif c=="10": p_decode()
            elif c=="11": p_auto()
            elif c=="12": p_report()
            elif c=="13":
                raw=ask("[?] new target: ")
                if raw:
                    S.update({"domain":None,"url":None,"candidates":[],"waf":None,"open_ports":{},"log":[]})
                    S["domain"],S["url"]=norm(raw); print(f"[*] target {S['domain']}")
            elif c=="0": print("[*] bye."); break
            else: print("[!] unknown")
        except KeyboardInterrupt: print("\n[*] cancelled"); continue
        except Exception as e: print(f"[!] {e}")
if __name__ == "__main__":
    main()
