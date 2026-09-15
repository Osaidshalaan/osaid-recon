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
