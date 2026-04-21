# 🦅 Basilic — Advanced Subdomain Intelligence Tool

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0.0-brightgreen?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Author-Pr0fessor__Snape-purple?style=for-the-badge"/>
</p>

```
██████╗  █████╗ ███████╗██╗██╗     ██╗ ██████╗
██╔══██╗██╔══██╗██╔════╝██║██║     ██║██╔════╝
██████╔╝███████║███████╗██║██║     ██║██║
██╔══██╗██╔══██║╚════██║██║██║     ██║██║
██████╔╝██║  ██║███████║██║███████╗██║╚██████╗
╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝╚══════╝╚═╝ ╚═════╝

        [ Advanced Subdomain Intelligence Tool ]
        [ by Pr0fessor_Snape ]  v1.0.0
        [ Takeover | WAF | ZoneXfer | CORS | Tech | Screenshots ]
```

---

## 📌 What is Basilic?

**Basilic** is a powerful, all-in-one subdomain intelligence and reconnaissance framework built from scratch in Python. It goes far beyond simple subdomain enumeration — it actively fingerprints technologies, detects WAFs, checks for CORS misconfigurations, tests for subdomain takeover vulnerabilities, attempts DNS zone transfers, and even captures screenshots of live hosts.

Built for penetration testers, bug bounty hunters, and cybersecurity researchers.

> ⚠️ **Legal Disclaimer:** Use Basilic only on domains you own or have **explicit written permission** to test. Unauthorized scanning is illegal. The author takes no responsibility for misuse.

---

## ✨ Features

| Module | Description |
|--------|-------------|
| 🔍 **CT Log Enumeration** | Queries crt.sh Certificate Transparency logs for passive subdomain discovery |
| 💣 **Brute Force Enumeration** | DNS brute force using built-in wordlist or custom wordlist |
| 🔄 **DNS Zone Transfer (AXFR)** | Tests all nameservers for zone transfer misconfiguration — critical finding |
| ⚠️ **Subdomain Takeover Detection** | Checks 35+ services (GitHub Pages, Heroku, AWS S3, Azure, Shopify, etc.) |
| 🛡️ **WAF / CDN Detection** | Identifies Cloudflare, Akamai, Fastly, Sucuri, Imperva, F5, ModSecurity & more |
| 🌐 **CORS Misconfiguration Check** | Detects wildcard origins, origin reflection, null origin with exploit guidance |
| 🔬 **Technology Fingerprinting** | Detects 25+ technologies: WordPress, Laravel, Django, React, Angular, Next.js & more |
| 📸 **Screenshot Capture** | Headless Chromium screenshots of live hosts (falls back to HTML save) |
| 🌍 **HTTP Status Checking** | Live/dead detection, status codes, page title extraction |
| 🔌 **Port Scanning** | Common port scan on discovered IPs |
| 🧠 **IP Intelligence** | ASN, ISP, country, region via ip-api.com |
| 📄 **Report Export** | JSON, CSV, and beautiful HTML report with all findings |

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/Pr0fessor-Snape/Basilic.git
cd Basilic

# Install dependencies
pip install -r requirements.txt
```

### Dependencies
```
requests
dnspython
colorama
urllib3
```

---

## 🛠️ Usage

### Basic subdomain scan
```bash
python basilic.py -d example.com
```

### Full scan with port scanning and screenshots
```bash
python basilic.py -d example.com --ports --screenshots
```

### Use a custom wordlist
```bash
python basilic.py -d example.com -w /usr/share/wordlists/subdomains.txt
```

### Custom thread count and output directory
```bash
python basilic.py -d example.com -t 100 -o results/
```

### Skip HTTP checking (faster)
```bash
python basilic.py -d example.com --no-http
```

---

## ⚙️ Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `-d, --domain` | Target domain **(required)** | — |
| `-w, --wordlist` | Custom wordlist file path | Built-in list |
| `-t, --threads` | Number of threads | `50` |
| `-o, --output` | Output directory name | Auto-generated |
| `--ports` | Enable port scanning on discovered IPs | Disabled |
| `--screenshots` | Capture screenshots of live hosts | Disabled |
| `--no-http` | Skip HTTP status checking | Disabled |

---

## 📋 Example Output

```
──────────────────────────────────────────────────
  Target: example.com
──────────────────────────────────────────────────
[*] Threads        : 50
[*] Port scan      : Yes
[*] Screenshots    : Yes

──────────────────────────────────────────────────
  DNS Zone Transfer (AXFR)
──────────────────────────────────────────────────
[*] Found 2 nameserver(s): ns1.example.com, ns2.example.com
[+]   ns1.example.com — AXFR refused (secure)

──────────────────────────────────────────────────
  Certificate Transparency Logs
──────────────────────────────────────────────────
[+] Found 14 subdomains from CT logs

──────────────────────────────────────────────────
  Brute Force Enumeration
──────────────────────────────────────────────────
[CT] api.example.com                              93.184.216.34
[BF] admin.example.com                            93.184.216.34
[BF] dev.example.com                              93.184.216.34

──────────────────────────────────────────────────
  WAF / CDN Detection
──────────────────────────────────────────────────
[+] api.example.com                               🛡  Cloudflare
[+] admin.example.com                             🛡  AWS WAF / CloudFront

──────────────────────────────────────────────────
  Technology Fingerprinting
──────────────────────────────────────────────────
[+] admin.example.com     → WordPress, jQuery, Google Analytics
[+] api.example.com       → Laravel, Nginx

──────────────────────────────────────────────────
  CORS Misconfiguration Check
──────────────────────────────────────────────────
[VULN] dev.example.com — [HIGH] Origin Reflection
  Origin 'https://evil.com' reflected. Credentials: true

──────────────────────────────────────────────────
  Subdomain Takeover Detection
──────────────────────────────────────────────────
[VULN] old.example.com — TAKEOVER POSSIBLE
  CNAME → example.github.io

──────────────────────────────────────────────────
  FINAL SUMMARY
──────────────────────────────────────────────────
[+] Subdomains found  : 17
[+] Live hosts        : 12
[VULN] Takeover risks : 1
[!]  CORS issues      : 1
```

---

## 📁 Output Files

After a scan, Basilic creates an output directory containing:

```
basilic_example.com_20240101/
├── basilic_results.json       # Full JSON data
├── basilic_results.csv        # Spreadsheet-friendly CSV
├── basilic_results.html       # Beautiful HTML report
└── screenshots/               # Screenshots of live hosts
    ├── api_example_com.png
    └── admin_example_com.png
```

---

## 🗂️ Architecture

```
basilic.py
├── DNS Records Enumeration
├── Zone Transfer (AXFR) Testing
├── Certificate Transparency (crt.sh)
├── Brute Force DNS Enumeration
├── HTTP Status Checking
├── Port Scanning
├── IP / ASN Intelligence
├── WAF / CDN Detection          ← 10 WAF signatures
├── Technology Fingerprinting    ← 25+ tech signatures
├── CORS Misconfiguration Check  ← 3 attack vectors
├── Subdomain Takeover Detection ← 35+ service fingerprints
├── Screenshot Capture
└── Report Generator (JSON / CSV / HTML)
```

---

## 🔮 Roadmap

- [ ] Wayback Machine URL harvesting
- [ ] Shodan API integration
- [ ] SSL/TLS misconfiguration checks
- [ ] Email security checks (SPF, DMARC, DKIM)
- [ ] Subdomain permutation engine
- [ ] Interactive HTML dashboard
- [ ] Slack/Discord notification support

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Pr0fessor_Snape**
Cybersecurity Researcher & Student

> *"Know your target before your target knows you."*

---

## ⭐ Support

If you found Basilic useful, give it a **star ⭐** on GitHub — it means a lot!

---

<p align="center">Made with 🦅 and pure Python by Pr0fessor_Snape</p>
