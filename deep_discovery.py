#!/usr/bin/env python3
"""Deep discovery v3."""
import re, time, httpx
from collections import Counter
from urllib.parse import urljoin, urlparse
from uuid import uuid4

SENSITIVE = [
 "/.env","/.git/HEAD","/.git/config","/.svn/entries","/backup.zip","/backup.tar.gz",
 "/db.sql","/swagger.json","/openapi.json","/api-docs","/v2/api-docs","/swagger-ui.html",
 "/server-status","/server-info","/phpinfo.php","/info.php","/.DS_Store","/web.config",
 "/.htaccess","/config.json","/appsettings.json","/actuator","/actuator/env",
 "/actuator/health","/metrics","/admin/","/console","/debug","/trace",
 "/.well-known/security.txt","/robots.txt","/sitemap.xml","/package.json","/composer.json",
]
UA = {"User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
NOISE = {"-1","null","onload","render","fi","fs","hs","ts","aa","ja","zs","width","hl",
         "version","13","229","data-insight","invariant","features","originalsubdomain"}

def wayback(domain):
    urls=set()
    try:
        r=httpx.get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=5000",timeout=60)
        for row in r.json()[1:]:
            if row: urls.add(row[0])
    except Exception: pass
    return urls

def otx_urls(domain):
    urls=set()
    try:
        r=httpx.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500",timeout=30)
        for rec in r.json().get("url_list",[]):
            if rec.get("url"): urls.add(rec["url"])
    except Exception: pass
    return urls

def urlscan_urls(domain):
    urls=set()
    try:
        r=httpx.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100",timeout=30)
        for res in r.json().get("results",[]):
            u=res.get("page",{}).get("url")
            if u: urls.add(u)
    except Exception: pass
    return urls

def clean_urls(urls):
    out=set()
    for u in urls:
        if "/..." in u or "%E2%80%8E" in u or u.rstrip("/").endswith("&") or u.endswith("="): continue
        out.add(u)
    return out

def mine_js(base):
    routes=set(); params=set(); maps=set()
    with httpx.Client(verify=False,timeout=25,follow_redirects=True,headers=UA) as c:
        try: html=c.get(base).text
        except Exception: return routes,params,maps
        blobs=[(base,html)]
        for s in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']',html):
            u=urljoin(base,s)
            try: blobs.append((u,c.get(u).text))
            except Exception: pass
        for src,b in blobs:
            routes |= set(re.findall(r'["\'`](/[a-zA-Z0-9_\-/]{2,80})["\'`]',b))
            params |= set(re.findall(r'[?&]([a-zA-Z0-9_\-]{2,30})=',b))
            for m in re.findall(r'sourceMappingURL=([^\s*]+)',b): maps.add(urljoin(src,m))
            for m in re.findall(r'["\']([a-zA-Z0-9_\-./]+\.js\.map)["\']',b): maps.add(urljoin(src,m))
    params={p for p in params if p.lower() not in NOISE and len(p)>2}
    return routes,params,maps

def fetch_maps(maps):
    out=[]
    for u in maps:
        try:
            r=httpx.get(u,verify=False,timeout=30,headers=UA)
            if r.status_code==200 and r.content:
                try: srcs=r.json().get("sources",[])
                except Exception: srcs=re.findall(r'"([^"]+\.(?:js|ts|tsx|jsx|vue|css))"',r.text)
                out.append({"url":u,"size":len(r.content),"sources":len(srcs),"sample":srcs[:10]})
        except Exception: pass
    return out


def probe_sensitive(base):
    hits=[]
    with httpx.Client(verify=False,timeout=12,follow_redirects=False,headers=UA) as c:
        sigs=set()
        for _ in range(2):
            try:
                b=c.get(base.rstrip("/")+"/"+uuid4().hex); sigs.add((b.status_code,len(b.content)))
            except Exception: pass
        for p in SENSITIVE:
            time.sleep(0.15)
            try:
                r=c.get(base.rstrip("/")+p)
                if r.status_code==404: continue
                if (r.status_code,len(r.content)) in sigs: continue
                hits.append([p,r.status_code,len(r.content)])
            except Exception: pass
    cnt=Counter((s,l) for _,s,l in hits); out=[]
    for p,s,l in hits:
        n=cnt[(s,l)]; tag=""
        if s==403 and n>=4: tag="  [WAF block — uniform]"
        elif s==200 and n>=4: tag="  [SPA soft-404 — uniform]"
        elif n>=4: tag=f"  [uniform x{n}]"
        out.append((p,s,l,tag))
    return out

def crawl(url,depth=2,max_pages=50):
    host=urlparse(url).netloc; seen=set(); queue=[(url,0)]
    with httpx.Client(verify=False,timeout=15,follow_redirects=True,headers=UA) as c:
        while queue and len(seen)<max_pages:
            u,d=queue.pop(0)
            if u in seen: continue
            seen.add(u); time.sleep(0.15)
            try: r=c.get(u)
            except Exception: continue
            if d<depth and "text/html" in r.headers.get("content-type",""):
                for link in re.findall(r'href=["\']([^"\'#]+)',r.text):
                    full=urljoin(u,link)
                    if urlparse(full).netloc==host and full not in seen: queue.append((full,d+1))
    return seen

def run(url):
    domain=urlparse(url).netloc
    print(f"\n=== Deep Discovery — {domain} ===")
    hist=clean_urls(wayback(domain)|otx_urls(domain)|urlscan_urls(domain))
    print(f"[1/5] historical URLs: {len(hist)}")
    routes,params,maps=mine_js(url)
    print(f"[2/5] JS mining: routes={len(routes)} params={len(params)} maps={len(maps)}")
    mi=fetch_maps(maps)
    print(f"[3/5] source maps fetched: {len(mi)}")
    for m in mi: print(f"      {m['url']}  {m['size']}B  sources={m['sources']}")
    sens=probe_sensitive(url)
    print(f"[4/5] sensitive hits: {len(sens)}")
    crawled=crawl(url,2,50)
    print(f"[5/5] crawl: {len(crawled)}")
    def show(t,items,n=60):
        print(f"\n-- {t} ({len(items)}) --")
        for x in sorted(items)[:n]: print("   ",x)
    show("Historical URLs",hist); show("JS routes",routes); show("Parameters",params,40)
    print(f"\n-- Source maps ({len(mi)}) --")
    for m in mi: print(f"    {m['url']}  {m['size']}B  sources={m['sources']}")
    print(f"\n-- Sensitive ({len(sens)}) --")
    for p,s,l,tag in sens: print(f"    {s}  {l:>7}  {p}{tag}")
    show("Crawled",crawled)
    return {"hist":hist,"routes":routes,"params":params,"maps":mi,"sens":sens,"crawl":crawled}
