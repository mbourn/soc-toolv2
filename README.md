# soc-toolv2

Terminal tool to quickly show OSINT reputation info about a provided IP, file hash, or domain.
This is an updated version of soc-tool.  As an exercise to learn how AI coding works and how
AIs think, I used one to clean up the code, remove dead modules, add new modules, and make 
tweaks that I had wanted to add for years but couldn't justify the time.
![Terminal output](https://github.com/mbourn/soc-toolv2/blob/main/soc-02.png)

## Setup

```bash
cd /path/to/soc-tool
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Copy the example config and fill in API keys
cp socVars.example.py socVars.py
vim socVars.py  # because real ones use vim
```

Provider signup links:

| Provider | Docs / signup |
|---|---|
| IOC Lists | https://www.ioclists.com/#api |
| PhishTank | https://www.phishtank.com/developer_info.php |
| CheckPhish | https://bolster.ai/kbarticles/scan-apis-for-checkphish-users |
| urlscan.io | https://docs.urlscan.io/apis/urlscan-openapi/search/searchdatasource |
| IP Quality Score | https://www.ipqualityscore.com/documentation/overview |
| GetIPIntel | https://getipintel.net/ (email contact param only) |
| Malware Bazaar | https://bazaar.abuse.ch/api/ |
| MalShare | https://malshare.com/doc.php |
| VirusTotal | https://developers.virustotal.com/v3.0/reference |
| Project HoneyPot | https://www.projecthoneypot.org/httpbl_api.php |
| Hybrid Analysis | https://www.hybrid-analysis.com/docs/api/v2 |
| TOR / Onionoo | https://onionoo.torproject.org (no signup) |
| ThreatFox | https://threatfox.abuse.ch/api/ |
| CIRCL PDNS | https://www.circl.lu/services/passive-dns/ |
| AlienVault OTX | https://otx.alienvault.com/ |

## Usage

Exactly one of `-i` / `-d` / `-H` / `-f` is required:

```bash
python3 soc.py -i 8.8.8.8
python3 soc.py -d example.com
python3 soc.py -d https://example.com/path   # scheme/path retained for providers who want it
python3 soc.py -H e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
python3 soc.py -f /path/to/sample.bin        # Makes a SHA-1 of the file, then looks it up
```

## Layout

| File | Role |
|---|---|
| `soc.py` | Main CLI entry point |
| `common.py` | Shared errors, colors re-exports, HTTP helpers, domain normalize |
| `socFuncsIPs.py` | IP-oriented providers |
| `socFuncsDoms.py` | Domain-oriented providers (+ shared IOC Lists) |
| `socFuncsHashs.py` | Hash-oriented providers |
| `socLists.py` | Static lookup tables (HoneyPot codes, etc.) |
| `socVars.py` | **Local secrets** (gitignored) |
| `socVars.example.py` | Secret-free template |
| `ir-ips.py` | Minimal IP-API geolocation CLI |

## Notes

- Hash mode (`-H`) expects **MD5**, **SHA-1**, or **SHA-256**. 
- File mode (`-f`) always uses **SHA-1** of the local file.
- Project HoneyPot HTTPBL is **IPv4 only**.
- Most HTTP calls use a **15s timeout** and soft-fail per provider so one outage does not kill the run.

## License

GNU GPLv3 — copy, modify, share; give me a nod. Don't sell.
