#!/usr/bin/env python3
import ssl, socket, hashlib, base64, httpx
try:
    import mmh3
except ImportError:
    mmh3 = None
def favicon_hash(base_url):
    for path in ("/favicon.ico", "/favicon.png", "/apple-touch-icon.png"):
        try:
            r = httpx.get(base_url.rstrip("/") + path, verify=False, timeout=12,
                          headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200 and r.content:
                if mmh3: return mmh3.hash(base64.encodebytes(r.content))
                return hashlib.md5(r.content).hexdigest()
        except Exception: continue
    return None
def cert_san(host, port=443, timeout=10):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss: cert = ss.getpeercert()
        san = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
        issuer = dict(x[0] for x in cert.get("issuer", []))
        return {"san": san, "issuer": issuer.get("organizationName", "")}
    except Exception as e:
        return {"san": [], "issuer": "", "error": str(e)}
def jarm(host, port=443):
    try:
        from pyjarm import jarm as _jarm
        return _jarm(host, port)
    except Exception: return None
def title_hash(base_url):
    try:
        r = httpx.get(base_url, verify=False, timeout=12,
                      headers={"User-Agent": "Mozilla/5.0"}, follow_redirects=True)
        t = ""
        if "<title" in r.text.lower():
            t = r.text.lower().split("<title", 1)[1].split(">", 1)[1].split("</title", 1)[0].strip()
        return hashlib.sha1(t.encode()).hexdigest()[:12], t[:80]
    except Exception: return None, None
def profile(url):
    host = url.split("//")[-1].split("/")[0]
    return {"favicon": favicon_hash(url), "cert": cert_san(host), "jarm": jarm(host), "title": title_hash(url)}
def matches(a, b, strict=False):
    score, reasons = 0, []
    if a.get("favicon") and a["favicon"] == b.get("favicon"): score += 2; reasons.append("favicon match")
    if a.get("title") and a["title"][0] == b.get("title", (None,))[0]: score += 1; reasons.append("title hash match")
    sa, sb = set(a.get("cert", {}).get("san", [])), set(b.get("cert", {}).get("san", []))
    if sa and sb and sa & sb: score += 2; reasons.append(f"cert SAN overlap: {sa & sb}")
    if a.get("jarm") and a["jarm"] == b.get("jarm"): score += 3; reasons.append("JARM match")
    return score, reasons
