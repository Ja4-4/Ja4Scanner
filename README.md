# Ja4Scanner — Bug Bounty Hunter's Toolkit

A Python CLI tool for security researchers to calculate CVSS v3.1 scores, generate professional bug bounty reports, and get PoC payload suggestions.

---

## Features

| Feature | Description |
|---------|-------------|
| **CVSS v3.1 Calculator** | Interactive metric prompts → precise base score + severity |
| **Report Generator** | Fills a professional Markdown report with auto-embedded CVSS & PoC |
| **PoC Suggester** | Common payloads + reproduction steps for 10 vuln types |
| **All-in-One Mode** | CVSS → Report in one flow, score auto-filled |
| **Color-coded output** | Severity displayed with rich terminal colors |

### Supported Vulnerability Types

XSS · SQLi · IDOR · RCE · SSRF · LFI · Open Redirect · XXE · CSRF · Auth Bypass

---

## Installation (Linux) — Recommended

```bash
git clone https://github.com/Ja4-4/Ja4Scanner.git
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
- Install `colorama` and `rich` via pip automatically
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
[Q] Quit
```

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
