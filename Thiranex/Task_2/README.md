# VulnProbe 🔍

> **A web & network vulnerability scanner built for penetration testing and security assessment.**  
> Internship Project — Cybersecurity / Penetration Testing Track

```
 __   __      _       ____            _
 \ \ / /     | |     |  _ \          | |
  \ V / _   _| |_ __ | |_) |_ __ ___ | |__   ___
   > < | | | | | '_ \|  __/| '__/ _ \| '_ \ / _ \
  / . \| |_| | | | | | |   | | | (_) | |_) |  __/
 /_/ \_\\__,_|_|_| |_|_|   |_|  \___/|_.__/ \___|

  Vulnerability Scanner v1.0  |  For Authorized Use Only
```

---

## ⚠️ Legal Disclaimer

> **This tool is for authorized security testing only.**  
> Scanning systems without explicit written permission is illegal under the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, India's IT Act, and equivalent laws worldwide.  
> **The author is not responsible for any misuse of this tool.**  
> Always obtain written authorization before scanning any target.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Scanning Modules](#scanning-modules)
- [Sample Output](#sample-output)
- [Report Types](#report-types)
- [CVE Coverage](#cve-coverage)
- [Risk Scoring](#risk-scoring)
- [Safe Targets for Testing](#safe-targets-for-testing)
- [What I Learned](#what-i-learned)
- [Future Improvements](#future-improvements)

---

## Overview

VulnProbe is a Python-based vulnerability scanner that automates the early stages of a web application and network security assessment. It combines five scanning modules — port scanning, HTTP header analysis, SSL/TLS inspection, sensitive path discovery, and DNS configuration checks — into a single tool that generates professional reports.

This project was developed as part of a penetration testing internship to gain hands-on experience with real vulnerability assessment techniques.

---

## Features

- **5 independent scanning modules** that can be enabled or disabled individually
- **Concurrent scanning** using `ThreadPoolExecutor` for fast port and path probing
- **CVE database** — matches detected software versions against known vulnerabilities
- **CVSS-inspired risk scoring** — produces a 0–100 risk score with severity label
- **3 report formats** — color-coded console output, PDF, and JSON
- **Interactive HTML dashboard** — filterable, searchable, animated results viewer
- **Cookie security analysis** — checks for missing `Secure`, `HttpOnly`, `SameSite` flags
- **DNS security checks** — zone transfer (AXFR) attempt, SPF and DMARC record validation

---

## Project Structure

```
vulnprobe/
├── vulnprobe.py          # CLI entry point — argument parsing, orchestration
├── scanner_core.py       # All 5 scanner modules + risk scoring engine
├── report_generator.py   # Console, PDF, and JSON report generation
├── vulnprobe_dashboard.html  # Standalone interactive HTML report viewer
└── README.md
```

---

## Installation

**Requirements:** Python 3.8+

```bash
# Clone or download the project
git clone https://github.com/yourusername/vulnprobe.git
cd vulnprobe

# Install dependencies
pip install requests reportlab dnspython colorama cryptography python-whois
```

**Dependency overview:**

| Package | Purpose |
|---------|---------|
| `requests` | HTTP scanning, header analysis, path probing |
| `reportlab` | PDF report generation |
| `dnspython` | DNS zone transfer and record queries |
| `colorama` | Cross-platform colored terminal output |
| `cryptography` | SSL/TLS cipher and certificate analysis |
| `python-whois` | Domain registration lookup |

All standard library modules used (`socket`, `ssl`, `subprocess`, `concurrent.futures`, `urllib`) require no installation.

---

## Usage

### Basic scan

```bash
python vulnprobe.py example.com
```

### Scan with PDF report

```bash
python vulnprobe.py https://example.com --pdf
```

### Custom output filename

```bash
python vulnprobe.py example.com --output my_report --pdf
```

### Scan an IP address

```bash
python vulnprobe.py 192.168.1.1 --no-dns
```

### Skip specific modules

```bash
python vulnprobe.py example.com --no-ports --no-dns
```

### All available flags

```
usage: vulnprobe.py [-h] [--output OUTPUT] [--pdf] [--json]
                    [--no-ports] [--no-http] [--no-ssl]
                    [--no-paths] [--no-dns] [--all]
                    target

positional arguments:
  target                Target URL, hostname, or IP address

optional arguments:
  -h, --help            Show this help message and exit
  --output, -o OUTPUT   Output filename prefix (default: vulnprobe_report)
  --pdf                 Generate PDF report
  --json                Save JSON report (always saved by default)
  --no-ports            Skip port scanning
  --no-http             Skip HTTP security header scan
  --no-ssl              Skip SSL/TLS certificate scan
  --no-paths            Skip sensitive path scan
  --no-dns              Skip DNS configuration scan
  --all                 Enable all modules (default behavior)
```

---

## Scanning Modules

### Module 1 — Port Scanner

Performs a concurrent TCP connect scan across 23 commonly used service ports.

- Uses `ThreadPoolExecutor` with up to 100 workers for fast parallel scanning
- Identifies open ports and maps them to service names
- Flags high-risk services (Telnet, SMB, RDP, Redis, MongoDB, etc.) as `HIGH` severity

**Ports scanned:**

| Port | Service | Risk |
|------|---------|------|
| 21 | FTP | Medium |
| 22 | SSH | Info |
| 23 | Telnet | **High** |
| 80/443 | HTTP/HTTPS | Info |
| 445 | SMB (EternalBlue) | **High** |
| 1433 | MSSQL | **High** |
| 3306 | MySQL | **High** |
| 3389 | RDP | **High** |
| 6379 | Redis | **High** |
| 27017 | MongoDB | **High** |

---

### Module 2 — HTTP Security Scanner

Analyzes HTTP responses for missing security headers, information disclosure, and insecure cookie configurations.

**Security headers checked (OWASP recommended):**

| Header | Missing = Severity | Attack Prevented |
|--------|-------------------|-----------------|
| `Strict-Transport-Security` | HIGH | HTTPS downgrade / MITM |
| `Content-Security-Policy` | HIGH | Cross-Site Scripting (XSS) |
| `X-Frame-Options` | MEDIUM | Clickjacking |
| `X-Content-Type-Options` | MEDIUM | MIME-type sniffing |
| `Referrer-Policy` | LOW | Referrer info leakage |
| `Permissions-Policy` | LOW | Browser feature abuse |

**Information disclosure headers detected:**

- `X-Powered-By` — reveals backend language (PHP, ASP.NET, etc.)
- `X-AspNet-Version` — reveals .NET framework version
- `X-AspNetMvc-Version` — reveals MVC version
- `Server` header version strings matched against CVE database

**Cookie security checks:**

- Missing `Secure` flag (cookie sent over HTTP)
- Missing `HttpOnly` flag (accessible to JavaScript → XSS risk)
- Missing `SameSite` attribute (CSRF risk)

---

### Module 3 — SSL/TLS Scanner

Inspects the SSL/TLS configuration by directly negotiating with the server.

- **Certificate expiry** — warns at < 30 days, critical if already expired
- **Self-signed certificate** detection
- **TLS version** — flags TLSv1.0 and TLSv1.1 as deprecated (RFC 8996)
- **Weak cipher suites** — detects RC4, DES, 3DES, NULL, EXPORT, MD5 ciphers
- **No HTTPS redirect** — checks if HTTP automatically redirects to HTTPS

---

### Module 4 — Sensitive Path Scanner

Concurrently probes 16 commonly exposed paths using HTTP GET requests.

| Path | Vulnerability | Severity |
|------|--------------|----------|
| `/.git/config` | Git repository exposed | CRITICAL |
| `/.env` | Environment config exposed | CRITICAL |
| `/wp-config.php.bak` | WordPress config backup | CRITICAL |
| `/backup.zip` | Backup archive exposed | CRITICAL |
| `/phpinfo.php` | PHP configuration info | HIGH |
| `/adminer.php` | Database admin panel | HIGH |
| `/phpmyadmin` | phpMyAdmin panel | HIGH |
| `/manager/html` | Tomcat manager panel | HIGH |
| `/api/v1/users` | Unauthenticated API endpoint | HIGH |
| `/debug` | Debug endpoint | HIGH |
| `/config.json` | Config file exposed | HIGH |
| `/server-status` | Apache server-status | MEDIUM |
| `/.htaccess` | Apache config exposed | MEDIUM |
| `/robots.txt` | Hidden path disclosure | INFO |
| `/wp-login.php` | WordPress login detected | INFO |
| `/admin` | Admin panel detected | INFO |

Paths returning HTTP 200 are validated to filter out custom 404 pages disguised as 200 responses. Paths returning 401/403 are recorded as "protected" to note they exist but are access-controlled.

---

### Module 5 — DNS Scanner

Tests DNS security configurations that are often misconfigured.

- **Zone Transfer (AXFR)** — attempts a full DNS zone transfer against each nameserver. A successful transfer reveals the entire DNS infrastructure including internal subdomains and IP addresses.
- **SPF record** — checks for a valid Sender Policy Framework TXT record. Without SPF, attackers can spoof emails from your domain.
- **DMARC record** — checks for a `_dmarc` TXT record. Without DMARC, there is no policy for handling spoofed emails.

---

## Sample Output

```
============================================================
  VulnProbe - Vulnerability Scanner
  Target : http://testphp.vulnweb.com
  Host   : testphp.vulnweb.com (44.228.249.3)
  Time   : 2026-05-07 06:36:13 UTC
============================================================

[MODULE 1/5] Port Scanner
  [*] Scanning 23 ports on 44.228.249.3...
  [+] Found 2 open ports

[MODULE 2/5] HTTP Security Scanner
  [*] Scanning HTTP headers and configuration...
  [+] Found 7 HTTP issues

[MODULE 3/5] SSL/TLS Scanner
  [*] Scanning SSL/TLS configuration on testphp.vulnweb.com:443...
  [+] Found 0 SSL/TLS issues

[MODULE 4/5] Sensitive Path Scanner
  [*] Scanning 16 sensitive paths...
  [+] Found 11 path exposures

[MODULE 5/5] DNS Scanner
  [*] Scanning DNS configuration for testphp.vulnweb.com...
  [+] Found 0 DNS issues

  RISK SCORE
  ███░░░░░░░░░░░░░░░░░  16/100 – MINIMAL

  FINDINGS SUMMARY  (20 total)
  CRITICAL   0
  HIGH       3
  MEDIUM     2
  LOW        2
  INFO       13
```

---

## Report Types

### Console Report
Color-coded terminal output with severity-grouped findings, evidence strings, CVE references, and remediation advice. Printed automatically after every scan.

### JSON Report
Saved automatically as `vulnprobe_report_<timestamp>.json`. Contains the full structured scan result including all finding metadata, open ports, severity counts, risk score, and timestamps. Suitable for importing into other tools or dashboards.

```json
{
  "target": "http://example.com",
  "risk_score": 62,
  "risk_label": "HIGH",
  "severity_counts": { "CRITICAL": 1, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 8 },
  "findings": [
    {
      "vuln_id": "MISSING_HSTS",
      "severity": "HIGH",
      "title": "Missing Header: Strict-Transport-Security",
      "cve": "",
      "recommendation": "Add 'Strict-Transport-Security' header to all HTTP responses."
    }
  ]
}
```

### PDF Report
Generated with `--pdf`. Produces a multi-page professional report including:
- Target summary and scan metadata
- Animated risk score gauge
- Severity summary cards
- Individual finding cards with evidence and remediation
- Remediation priority matrix (sorted by severity)

### HTML Dashboard
`vulnprobe_dashboard.html` — a standalone interactive report viewer. Open in any browser, no server needed.
- Filter findings by severity (Critical / High / Medium / Low / Info)
- Full-text search across all findings, CVEs, and categories
- Animated risk gauge
- Category breakdown bar chart
- Port status panel with pulse animations

---

## CVE Coverage

VulnProbe checks the `Server` HTTP response header against a built-in CVE reference database:

| Software | Version | CVE | Severity | Description |
|---------|---------|-----|----------|-------------|
| Apache | 2.4.49 | CVE-2021-41773 | CRITICAL | Path traversal & RCE |
| Apache | 2.4.50 | CVE-2021-42013 | CRITICAL | Path traversal bypass |
| nginx | 1.3.9 / 1.4.0 | CVE-2013-2028 | CRITICAL | Stack buffer overflow |
| OpenSSL | 1.0.1 | CVE-2014-0160 | CRITICAL | Heartbleed memory disclosure |
| OpenSSL | 1.0.2 | CVE-2016-0800 | HIGH | DROWN attack |
| PHP | 5.x | CVE-2019-11043 | CRITICAL | RCE via FPM/FastCGI |
| WordPress | 5.6 | CVE-2021-29447 | HIGH | XXE in media library |
| IIS | 6.0 | CVE-2017-7269 | CRITICAL | WebDAV buffer overflow RCE |

---

## Risk Scoring

VulnProbe uses a CVSS-inspired scoring model to calculate an overall risk score (0–100):

```
Base score = (sum of finding weights / max possible) × 100
Bonus      = +5 per CRITICAL finding (capped at 100)
```

Finding weights by severity:

| Severity | Score |
|----------|-------|
| CRITICAL | 10 |
| HIGH | 7 |
| MEDIUM | 4 |
| LOW | 2 |
| INFO | 0 |

Risk labels:

| Score Range | Label |
|-------------|-------|
| 80–100 | CRITICAL |
| 60–79 | HIGH |
| 40–59 | MEDIUM |
| 20–39 | LOW |
| 0–19 | MINIMAL |

---

## Safe Targets for Testing

These are intentionally vulnerable systems you are **authorized to scan freely** for practice:

| Target | Description |
|--------|------------|
| `http://testphp.vulnweb.com` | Acunetix's deliberately vulnerable PHP app |
| `http://testasp.vulnweb.com` | Acunetix's ASP test site |
| `http://testaspnet.vulnweb.com` | Acunetix's ASP.NET test site |
| `http://vulnweb.com` | Acunetix main test server |
| Your own local VM | Set up DVWA, Metasploitable, or Vulnhub machines |

**Never scan:** production systems, sites you don't own, cloud instances you haven't authorized, or systems belonging to others without explicit written permission.

---

## What I Learned

Working on this project provided practical experience with:

- **Network fundamentals** — TCP handshake mechanics, how port scanning works at the socket level
- **HTTP security** — the purpose and configuration of every major security response header
- **SSL/TLS internals** — certificate chains, cipher negotiation, protocol version deprecation
- **OWASP Top 10** — how information disclosure, security misconfiguration, and vulnerable components map to real checks
- **CVE research** — how to find, interpret, and programmatically apply CVE data
- **Python concurrency** — using `ThreadPoolExecutor` for parallel I/O-bound tasks
- **DNS security** — zone transfer attacks, SPF/DMARC email authentication
- **Report writing** — structuring vulnerability findings with evidence, severity, and remediation

---

## Future Improvements

- [ ] SQL injection detection (GET/POST parameter fuzzing)
- [ ] XSS reflection detection
- [ ] Subdomain enumeration via brute-force and certificate transparency logs
- [ ] FTP anonymous login check
- [ ] SSH banner grabbing and version detection
- [ ] Nikto integration for broader web vulnerability coverage
- [ ] Shodan API integration for passive reconnaissance
- [ ] HTML report export directly from scanner (no separate dashboard file)
- [ ] YAML config file support for scan profiles
- [ ] CI/CD pipeline integration mode (exit code based on risk threshold)

---

## Tech Stack

- **Language:** Python 3.8+
- **Key Libraries:** `requests`, `ssl`, `socket`, `reportlab`, `dnspython`, `concurrent.futures`
- **Report Frontend:** Vanilla HTML/CSS/JS (zero dependencies, single file)
- **Fonts:** JetBrains Mono, Syne (Google Fonts)

---

## Author

Built as an internship project for hands-on learning in penetration testing and vulnerability assessment.

---

*For authorized security testing only. Scan responsibly.*
