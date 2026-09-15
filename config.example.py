# cp config.example.py config.py
SECURITYTRAILS_KEY = ""
VIRUSTOTAL_KEY     = ""
SHODAN_KEY         = ""
CENSYS_ID          = ""
CENSYS_SECRET      = ""
PROXY_POOL = [
    # "socks5://user:pass@host:1080",
]
MAX_RPS            = 2.0
SCAN_CONC          = 40
JITTER_MIN         = 0.6
JITTER_MAX         = 2.4
STEALTH            = True
ROTATE_PROXY_EVERY = 1
COMMON_SUBS = ["direct","origin","origin-www","backend","internal","dev",
               "staging","ftp","mail","smtp","vpn","api","admin","test","portal"]
HIGH_VALUE_PORTS = "21,22,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,9000,27017"
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
]
