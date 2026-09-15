# osaid-recon

Stealthy web-recon console for **authorized** pentesting.

## Features
- WAF fingerprint (CloudFront, Cloudflare, Akamai, F5, Imperva, ModSecurity)
- Origin discovery: keyless passive DNS (OTX, HackerTarget, urlscan, RapidDNS, certspotter, crt.sh)
- Multi-signature origin confirmation (F5/ASM cookies, title, favicon)
- F5 BIG-IP cookie decode -> internal backend IP
- ASM policy map, API/JS endpoint dump
- Quiet async port scan, vuln-hint engine
- Stealth: rate limit, proxy rotation, header randomization
- Console + AUTO chain + Markdown report

## Install
    git clone https://github.com/<USER>/vanta-recon.git
    cd vanta-recon
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    cp config.example.py config.py

## Usage
    python osaid_recon.py --selftest
    python osaid_recon.py

Menu: 1 WAF | 2 Origin | 3 AUTO | 4 Decode | 5 Scan | 6 Evade
      7 ASM | 8 API/JS | 9 Report | 10 Target | 12 Vuln | 0 Exit

## Config (config.py)
- API keys (optional): SecurityTrails, VirusTotal, Shodan, Censys
- PROXY_POOL: rotate egress IPs
- MAX_RPS, SCAN_CONC, STEALTH

## Disclaimer
Authorized testing only. Use only on systems you own or have
written permission to test.
