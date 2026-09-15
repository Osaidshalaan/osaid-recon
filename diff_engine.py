#!/usr/bin/env python3
"""HTTP differential engine: baseline vs candidate -> similarity + conclusion."""
import hashlib, re, time, httpx

def _title(t):
    tl = t.lower()
    return tl.split("<title",1)[1].split(">",1)[1].split("</title",1)[0].strip()[:80] if "<title" in tl else ""

def _sim(a, b):
    ta = set(re.findall(r"\w+", a.lower())); tb = set(re.findall(r"\w+", b.lower()))
    return len(ta & tb)/len(ta | tb) if ta and tb else 0.0

def fetch(url, headers=None, timeout=15):
    t0 = time.time()
    try:
        r = httpx.get(url, headers=headers or {"User-Agent":"Mozilla/5.0"},
                      verify=False, timeout=timeout, follow_redirects=True)
        return {"status":r.status_code,"len":len(r.content),
                "hash":hashlib.sha256(r.content).hexdigest()[:16],
                "title":_title(r.text),"time":(time.time()-t0)*1000,
                "body":r.text[:20000]}
    except Exception as e:
        return {"error":str(e)}

def compare(base, cand, label=""):
    if "error" in cand:
        return {"label":label,"status":None,"similarity":0.0,"conclusion":"no response","confidence":"n/a"}
    sim = _sim(base.get("body",""), cand.get("body",""))
    same_status = base.get("status")==cand.get("status")
    same_len = base.get("len")==cand.get("len")
    same_hash = base.get("hash")==cand.get("hash")
    score = 0.4*sim + 0.2*same_status + 0.2*same_len + 0.2*same_hash
    if same_hash: concl="identical response"
    elif score>=0.95: concl="no behavioral difference"
    elif score>=0.7: concl="minor differences"
    else: concl="material difference"
    conf = "high" if same_hash or score>=0.95 or score<0.5 else "medium"
    return {"label":label,"status":cand["status"],"similarity":score,"conclusion":concl,
            "confidence":conf,"delta_len":cand["len"]-base["len"],"delta_time":cand["time"]-base["time"]}

def baseline(url, path="/"):
    return fetch(url.rstrip("/")+path)

def probe(base, url, paths):
    out = []
    for name,p in paths.items():
        out.append(compare(base, fetch(url.rstrip("/")+p), name))
    return out

if __name__ == "__main__":
    import sys
    b = baseline(sys.argv[1])
    print(f"baseline: {b.get('status')} len={b.get('len')}")
