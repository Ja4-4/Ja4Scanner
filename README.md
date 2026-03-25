# Ja4Scanner — Bug Bounty Hunter's Toolkit

A Python CLI tool for security researchers to calculate CVSS v3.1 scores, generate professional bug bounty reports, get PoC payload suggestions, and run active recon + vulnerability scans on target URLs.

---

## Features

| Feature | Description |
|---------|-------------|
| **CVSS v3.1 Calculator** | Interactive metric prompts → precise base score + severity |
| **Report Generator** | Fills a professional Markdown report with auto-embedded CVSS & PoC |
| **PoC Suggester** | Common payloads + reproduction steps for 10 vuln types |
| **All-in-One Mode** | CVSS → Report in one flow, score auto-filled |
| **Color-coded output** | Severity displayed with rich terminal colors |
| **Active Scanner** | Full recon + vuln scan on any target URL |
| **Security Headers** | Checks 6 critical HTTP security headers (present / missing / misconfigured) |
| **SSL Certificate** | Validates cert, expiry date, issuer, days remaining — warns if < 30 days |
| **Port Scanner** | Scans 12 common ports with threading (1 s timeout per port) |
| **Subdomain Enum** | Tests 55 subdomains via DNS resolution, tracks NXDOMAIN vs timeout |
| **Directory Bruteforce** | Probes 56 sensitive paths, filters SPA/catch-all false positives via body-hash |
| **XSS Scanner** | Canary-token reflection detection on URL params and form fields |
| **SQLi Scanner** | Error-based + time-based with adaptive RTT baseline (threshold = baseline + 2.5 s) |

### Supported Vulnerability Types

PoC database: XSS · SQLi · IDOR · RCE · SSRF · LFI · Open Redirect · XXE · CSRF · Auth Bypass

Actively detected by scanner: XSS (reflected) · SQLi (error-based & time-based blind)

---

## Installation (Linux) — Recommended

```bash
git clone https://github.com/USERNAME/Ja4Scanner.git
cd Ja4Scanner
chmod +x install.sh
sudo ./install.sh
```

Then run from anywhere:

```bash
ja4scanner
```

The installer will:
- Verify Python 3.8+ is present
- Install all dependencies via pip automatically
- Copy the tool to `/opt/ja4scanner/`
- Create a global `/usr/local/bin/ja4scanner` launcher

> **Distro notes:**
> - Debian/Ubuntu: `sudo apt install python3 python3-pip` if not present
> - Fedora/RHEL: `sudo dnf install python3 python3-pip`
> - Arch: `sudo pacman -S python python-pip`

---

## Installation (Manual / Windows)

```bash
cd Ja4Scanner
pip install requests colorama rich dnspython
```

Or install from the requirements file:

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
# After Linux install:
ja4scanner

# Manual / Windows:
python main.py
```

### Menu Options

```
[1] CVSS v3.1 Calculator          — compute base score interactively
[2] Bug Bounty Report Generator   — produce a Markdown report
[3] PoC Suggester                 — payloads & steps for a vuln type
[4] All-in-One                    — CVSS score → report in one flow
[5] Severity Reference Chart      — score ranges and action guidance
[6] Active Scanner                — full recon + vuln scan on a target URL
[Q] Quit
```

---

## Active Scanner

```
ja4scanner
Select [6] Active Scanner
Enter target URL: https://target.com/page?id=1
Bypass robots.txt? [y/n]: n
```

Runs 7 modules automatically in sequence:

```
[1/7] Security Headers      — checks HSTS, CSP, X-Frame-Options, and more
[2/7] SSL Certificate       — expiry, issuer, days remaining
[3/7] Port Scan             — 12 common ports via threading
[4/7] Subdomain Enumeration — 55 subdomains via DNS (shows NXDOMAIN/timeout stats)
[5/7] Directory Bruteforce  — 56 sensitive paths, false-positive filtered
[6/7] XSS Scanner           — canary-token reflection on all parameters
[7/7] SQLi Scanner          — error-based + time-based blind (adaptive threshold)
```

Then shows a full summary table sorted by severity (Critical → High → Medium → Info).

If High or Critical findings are detected, offers to auto-generate a bug bounty report with a pre-filled CVSS score.

### Scanner Design Notes

- **Base URL extraction:** always strips path and query string before appending dir wordlist paths — `https://target.com/app?x=1` → probes `https://target.com/.env`, not `https://target.com/app?x=1/.env`
- **False-positive filter:** fetches a random canary path first; if the site returns 200 for everything (SPA / catch-all routing), responses with identical body hashes are silently dropped
- **XSS canary tokens:** each request uses a unique `ja4xss_<random_hex>` token embedded in the payload — only flags if the exact token reflects back unencoded
- **SQLi time baseline:** measures average RTT over 3 baseline requests before injection; time-based SQLi only flagged if response time exceeds `baseline + 2.5 s`

---

## Example Workflow

### Option 1 — CVSS Calculator only

```
Select an option: 1

CVSS v3.1 Base Score Calculator

Attack Vector (AV)
  [1] Network   (N)
  [2] Adjacent  (A)
  [3] Local     (L)
  [4] Physical  (P)
  > 1

...

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
Base Score : 10.0  [Critical]
```

### Option 4 — All-in-One

```
Select an option: 4

Step 1: Calculate CVSS Score
...
CVSS Score locked in: 8.8 (High)

Step 2: Generate Report
Vulnerability Title: Reflected XSS in Search Parameter
Affected URL: https://target.com/search?q=test
...
Report saved: report_2026-03-25.md
```

### Option 6 — Active Scanner

```
Select an option: 6

Enter target URL: https://www.example.com/leaderboard?mode=game&tab=flight
Bypass robots.txt? [y/n]: n

Active Recon Scanner
  Input URL  : https://www.example.com/leaderboard?mode=game&tab=flight
  Scan origin: https://www.example.com

[1/7] Checking Security Headers...
[2/7] Checking SSL Certificate...
[3/7] Port Scanning...
[4/7] Enumerating Subdomains...
      Tested 55 | Found 3 | NXDOMAIN 49 | Timeout 3
[5/7] Directory & File Bruteforce...
      Scanning origin: https://www.example.com
[6/7] XSS Scanner...
[7/7] SQL Injection Scanner...
      Baseline RTT: 0.42s — time-based threshold: 2.92s

Scan Summary
+---------------------------+--------------------------------------------+----------+
| Finding Type              | Detail                                     | Risk     |
+---------------------------+--------------------------------------------+----------+
| SQL Injection             | param=mode [error] url=...                 | Critical |
| XSS Reflected             | param=tab url=...                          | High     |
| Missing Header            | Content-Security-Policy                    | Medium   |
| Open Port                 | 8080/HTTP-Alt                              | Medium   |
+---------------------------+--------------------------------------------+----------+

3 Critical/High findings detected.
Generate a bug bounty report? [y/n]: y
```

---

## Output — Sample Report Structure

```markdown
# Bug Bounty Report: Reflected XSS in Search Parameter

![High](https://img.shields.io/badge/Severity-High-orange)

| Field          | Value                         |
|----------------|-------------------------------|
| CVSS Score     | 8.8 / 10.0 (High)             |
| CVSS Vector    | CVSS:3.1/AV:N/AC:L/...        |
...

## Steps to Reproduce
## Proof of Concept (PoC)
## Remediation
## References
```

---

## File Structure

```
Ja4Scanner/
├── main.py               # Entry point & menu
├── scanner.py            # Active scanning engine (7 modules)
├── cvss_calculator.py    # CVSS v3.1 engine
├── report_generator.py   # Markdown report builder
├── poc_suggester.py      # PoC payloads database
├── install.sh            # Linux one-command installer
├── requirements.txt
└── README.md
```

---

## Disclaimer

This tool is intended for **authorized security testing and bug bounty programs only**. Always have explicit written permission before testing any system you do not own.


## Disclaimer

This tool is intended for **authorized security testing and bug bounty programs only**. Always have explicit written permission before testing any system you do not own.
