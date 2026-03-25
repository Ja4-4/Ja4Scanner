#!/usr/bin/env python3
"""
"""

import hashlib
import secrets
import socket
import ssl
import time
import urllib.parse
import urllib.robotparser
import re
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import requests
import urllib3
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt
from rich import box

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

console = Console()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Risk / confidence ordering helpers ───────────────────────────────────────

RISK_ORDER       = ["Critical", "High", "Medium", "Low", "Info"]
CONFIDENCE_ORDER = ["High", "Medium", "Low"]

RISK_COLOR = {
    "Critical": "bold bright_red",
    "High":     "bold red",
    "Medium":   "yellow",
    "Low":      "dim",
    "Info":     "white",
}
CONF_COLOR = {
    "High":   "bold green",
    "Medium": "yellow",
    "Low":    "dim",
}


# ── Constants ─────────────────────────────────────────────────────────────────

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080, 8443, 8888]

# (service_name, default_risk, context_note)
PORT_RISK = {
    21:   ("FTP",      "Critical", "Unencrypted file transfer — credentials sent in plaintext"),
    22:   ("SSH",      "Medium",   "Remote access — acceptable if managed, risky if publicly exposed"),
    23:   ("Telnet",   "Critical", "Unencrypted remote shell — should never be internet-facing"),
    25:   ("SMTP",     "Medium",   "Mail server — verify it is not an open relay"),
    53:   ("DNS",      "Low",      "DNS service — test for zone transfer (AXFR)"),
    80:   ("HTTP",     "Info",     "Standard HTTP — confirm HTTPS redirect exists"),
    443:  ("HTTPS",    "Info",     "Standard HTTPS"),
    3306: ("MySQL",    "Critical", "Database exposed to internet — direct query access risk"),
    3389: ("RDP",      "Critical", "Remote Desktop exposed — brute-force and exploitation target"),
    8080: ("HTTP-Alt", "Low",      "Common dev/proxy port — should not be internet-facing"),
    8443: ("HTTPS-Alt","Low",      "Common dev/proxy port — should not be internet-facing"),
    8888: ("HTTP-Dev", "Low",      "Development server — should not be internet-facing"),
}

SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "test", "staging", "beta",
    "portal", "vpn", "remote", "shop", "blog", "cdn", "static", "assets",
    "app", "mobile", "m", "secure", "login", "dashboard", "panel", "cpanel",
    "webmail", "smtp", "pop", "imap", "ns1", "ns2", "mx", "git", "gitlab",
    "jenkins", "jira", "confluence", "docs", "help", "support", "status",
    "monitor", "grafana", "kibana", "elasticsearch", "redis", "mysql",
    "phpmyadmin", "wp-admin", "backup", "old", "new", "v2", "api2", "dev2",
]

# Strings that indicate subdomain takeover potential
TAKEOVER_SIGNATURES = [
    ("There isn't a GitHub Pages site here",          "GitHub Pages"),
    ("NoSuchBucket",                                   "AWS S3"),
    ("The specified bucket does not exist",            "AWS S3"),
    ("This shop is currently unavailable",             "Shopify"),
    ("Fastly error: unknown domain",                   "Fastly CDN"),
    ("Repository not found",                           "Bitbucket"),
    ("This UserVoice subdomain is currently available","UserVoice"),
    ("project not found",                              "GitLab Pages"),
    ("We couldn't find the site you're looking for",  "Webflow"),
    ("Unrecognized domain",                            "Zendesk"),
    ("Sorry, We Couldn't Find That Page",             "HubSpot"),
]

DIR_WORDLIST = [
    "/admin", "/login", "/dashboard", "/panel", "/api", "/api/v1", "/api/v2",
    "/backup", "/config", "/.env", "/.git", "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/uploads", "/files", "/static", "/assets", "/images",
    "/robots.txt", "/sitemap.xml", "/.htaccess", "/web.config",
    "/server-status", "/server-info", "/elmah.axd", "/trace.axd",
    "/actuator", "/actuator/health", "/actuator/env", "/swagger",
    "/swagger-ui.html", "/api-docs", "/graphql", "/console",
    "/manager/html", "/admin/login", "/user/login", "/auth/login",
    "/reset-password", "/forgot-password", "/register",
    "/debug", "/test", "/temp", "/tmp", "/old", "/new", "/v1", "/v2",
    "/secret", "/private", "/internal", "/hidden", "/dump", "/sql",
]

HIGH_RISK_KEYWORDS = {".env", ".git", "backup", "config", "dump", "sql",
                      "secret", "private", "internal", "hidden", "web.config",
                      ".htaccess", "actuator", "console", "debug", "phpmyadmin"}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Permissions-Policy",
    "Referrer-Policy",
]

# Risk when header is MISSING
HEADER_MISSING_RISK = {
    "Strict-Transport-Security": ("High",   "Allows downgrade to HTTP; enables MITM attacks"),
    "Content-Security-Policy":   ("High",   "No CSP — inline scripts and XSS fully unrestricted"),
    "X-Frame-Options":           ("Medium", "Page can be embedded in iframes — clickjacking risk"),
    "X-Content-Type-Options":    ("Low",    "Browser may MIME-sniff responses"),
    "Permissions-Policy":        ("Low",    "Browser features (camera, mic) not restricted"),
    "Referrer-Policy":           ("Info",   "Referrer information may leak to third parties"),
}

# XSS payload templates — {canary} substituted per-request
XSS_PAYLOAD_TEMPLATES = [
    ('<script>alert("{canary}")</script>',       ["<script", "/script>"]),
    ('"><img src=x onerror=alert("{canary}")>',  ["onerror", "src=x"]),
    ('"><svg onload=alert("{canary}")>',          ["onload",  "<svg"]),
    ('<details open ontoggle=alert("{canary}")>', ["ontoggle","<details"]),
    ("'><{canary}>",                              []),          # bare reflection
]

SQLI_ERROR_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "1; DROP TABLE users--",
    "' UNION SELECT null--",
]

SQLI_TIME_PAYLOAD = "1' AND SLEEP(5)--"   # flagged only if elapsed > baseline+2.5 s

# True / False boolean pairs for boolean-based detection
SQLI_BOOLEAN_PAIRS = [
    ("' OR '1'='1'--",  "' OR '1'='2'--"),
    ("1 OR 1=1--",      "1 OR 1=2--"),
]

SQL_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql_fetch",
    r"ORA-\d{5}",
    r"syntax error.*sql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"sqlite3\.OperationalError",
    r"SQLSTATE\[",
    r"Warning.*mysql_",
    r"Microsoft OLE DB Provider for SQL Server",
    r"Incorrect syntax near",
    r"Division by zero in SQL",
    r"supplied argument is not a valid MySQL",
]

SESSION_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def _origin(url: str) -> str:
    """Return scheme+netloc only — no path, no query string."""
    p = urllib.parse.urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _extract_domain(url: str) -> str:
    return urllib.parse.urlparse(url).hostname or url


def _body_hash(content: bytes) -> str:
    return hashlib.md5(content).hexdigest()


def _significant_diff(a: str, b: str, threshold: float = 0.12) -> bool:
    """True if len(a) and len(b) differ by more than threshold fraction."""
    longer = max(len(a), len(b))
    if longer == 0:
        return False
    return abs(len(a) - len(b)) / longer > threshold


def _is_robots_allowed(origin_url: str, path: str) -> bool:
    try:
        rp = urllib.robotparser.RobotFileParser()
        rp.set_url(origin_url + "/robots.txt")
        rp.read()
        return rp.can_fetch("*", origin_url + path)
    except Exception:
        return True


def _make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(SESSION_HEADERS)
    return s


def _canary() -> str:
    """Unique 8-hex-char XSS canary token."""
    return "ja4xss_" + secrets.token_hex(4)


def _finding(ftype: str, detail: str, risk: str,
             confidence: str, reason: str) -> dict:
    return {"type": ftype, "detail": detail, "risk": risk,
            "confidence": confidence, "reason": reason}


# ── SSL helpers ───────────────────────────────────────────────────────────────

def _check_tls_weak_versions(domain: str, timeout: int) -> list[str]:
    """Return list of weak TLS versions accepted by the server."""
    weak = []
    candidates = []
    if hasattr(ssl, "TLSVersion"):
        if hasattr(ssl.TLSVersion, "TLSv1"):
            candidates.append(("TLS 1.0", ssl.TLSVersion.TLSv1))
        if hasattr(ssl.TLSVersion, "TLSv1_1"):
            candidates.append(("TLS 1.1", ssl.TLSVersion.TLSv1_1))

    for name, ver in candidates:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.maximum_version = ver
            ctx.minimum_version = ver
            with ctx.wrap_socket(
                socket.create_connection((domain, 443), timeout=timeout),
                server_hostname=domain,
            ):
                weak.append(name)
        except Exception:
            pass
    return weak


# ── XSS confidence helper ─────────────────────────────────────────────────────

def _xss_confidence(response_text: str, canary: str,
                    payload: str, high_indicators: list[str]) -> str:
    """
    High   — canary reflects AND structural payload syntax (e.g. <script>) also reflects
    Medium — canary reflects but payload structure is stripped
    none   — canary not found OR only HTML-encoded version found
    """
    if canary not in response_text:
        return "none"
    # Check that the canary is not only present in HTML-encoded form
    encoded = canary.replace("<", "&lt;").replace(">", "&gt;")
    # Find positions of unencoded vs encoded occurrences
    raw_idx = response_text.find(canary)
    if raw_idx == -1:
        return "none"

    surrounding = response_text[max(0, raw_idx - 120): raw_idx + 120]

    # High: structural indicator also present near the canary
    for indicator in high_indicators:
        if indicator.lower() in surrounding.lower():
            return "High"

    return "Medium"


# ── SQLi detection helpers ────────────────────────────────────────────────────

def _sqli_error_hit(text: str) -> Optional[str]:
    """Return the matching pattern string if a DB error is found, else None."""
    for pattern in SQL_ERROR_PATTERNS:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            return m.group(0)[:60]
    return None


def _measure_baseline_rtt(session: requests.Session, point: dict,
                           timeout: int, samples: int = 3) -> float:
    """Average RTT over N benign requests."""
    times = []
    for _ in range(samples):
        try:
            t0 = time.time()
            _inject(session, point, "baseline_test_ja4", timeout)
            times.append(time.time() - t0)
        except Exception:
            times.append(0.5)
    return sum(times) / max(len(times), 1)


# ── ReconScanner ──────────────────────────────────────────────────────────────

class ReconScanner:

    def __init__(self, target: str, respect_robots: bool = True, timeout: int = 5):
        self.raw_target     = target
        self.base_url       = _normalize_url(target)
        self.scan_origin    = _origin(self.base_url)
        self.domain         = _extract_domain(self.base_url)
        self.respect_robots = respect_robots
        self.timeout        = timeout
        self.session        = _make_session()

        self.results: dict = {
            "headers":    [],
            "ssl":        {},
            "ports":      [],
            "subdomains": [],
            "dirs":       [],
            "xss":        [],
            "sqli":       [],
            "findings":   [],   # unified list of finding dicts
        }

    # ── 1. Security Headers ───────────────────────────────────────────────────

    def check_headers(self) -> None:
        console.print("\n[bold cyan][1/7] Checking Security Headers...[/bold cyan]")
        try:
            r = self.session.get(self.base_url, timeout=self.timeout,
                                 verify=False, allow_redirects=True)
            hdrs = {k.lower(): v for k, v in r.headers.items()}

            for header in SECURITY_HEADERS:
                key     = header.lower()
                present = key in hdrs
                value   = hdrs.get(key, "")

                status     = "PRESENT"
                risk       = "Info"
                confidence = "High"
                reason     = f"Header is present with value: {value[:60]}" if value else ""

                if not present:
                    status = "MISSING"
                    risk, note = HEADER_MISSING_RISK[header]
                    reason = note
                    self.results["findings"].append(
                        _finding("Missing Header", header, risk, "High", reason))
                else:
                    # Value-level checks
                    issue = None

                    if header == "Strict-Transport-Security":
                        ma = re.search(r"max-age=(\d+)", value, re.IGNORECASE)
                        if ma and int(ma.group(1)) == 0:
                            issue = ("MISCONFIGURED", "High", "Medium",
                                     "max-age=0 disables HSTS entirely")
                        elif ma and int(ma.group(1)) < 31536000:
                            issue = ("MISCONFIGURED", "Medium", "High",
                                     f"max-age={ma.group(1)} is below recommended 31536000 (1 year)")

                    elif header == "X-Frame-Options":
                        if value.upper() not in ("DENY", "SAMEORIGIN"):
                            issue = ("MISCONFIGURED", "High", "High",
                                     f"Value '{value}' does not restrict framing — clickjacking possible")

                    elif header == "X-Content-Type-Options":
                        if value.lower() != "nosniff":
                            issue = ("MISCONFIGURED", "Low", "High",
                                     f"Value '{value}' should be 'nosniff'")

                    elif header == "Content-Security-Policy":
                        if "unsafe-inline" in value:
                            issue = ("MISCONFIGURED", "Medium", "High",
                                     "'unsafe-inline' in CSP allows inline script execution")
                        elif "unsafe-eval" in value:
                            issue = ("MISCONFIGURED", "Medium", "High",
                                     "'unsafe-eval' in CSP allows eval() — XSS escalation risk")

                    if issue:
                        status, risk, confidence, reason = issue
                        self.results["findings"].append(
                            _finding("Misconfigured Header",
                                     f"{header}: {value[:60]}", risk, confidence, reason))

                self.results["headers"].append({
                    "header": header, "status": status,
                    "value": value, "risk": risk, "reason": reason,
                })

            _print_headers_table(self.results["headers"])

        except Exception as e:
            console.print(f"  [red]Header check failed: {e}[/red]")

    # ── 2. SSL Certificate ────────────────────────────────────────────────────

    def check_ssl(self) -> None:
        console.print("\n[bold cyan][2/7] Checking SSL Certificate...[/bold cyan]")
        if not self.base_url.startswith("https://"):
            console.print("  [yellow]Target is HTTP — skipping SSL check.[/yellow]")
            self.results["ssl"] = {"skipped": True}
            return

        extra_findings = []
        info = {}

        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.create_connection((self.domain, 443), timeout=self.timeout),
                server_hostname=self.domain,
            ) as sock:
                cert       = sock.getpeercert()
                tls_proto  = sock.version()        # e.g. "TLSv1.3"

            not_after = datetime.strptime(
                cert.get("notAfter", ""), "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)
            days_left = (not_after - datetime.now(timezone.utc)).days

            issuer  = dict(x[0] for x in cert.get("issuer",  []))
            subject = dict(x[0] for x in cert.get("subject", []))

            # Self-signed: issuer == subject
            is_self_signed = cert.get("issuer") == cert.get("subject")

            # Domain mismatch
            cert_cn  = subject.get("commonName", "")
            san_list = []
            for ext in cert.get("subjectAltName", []):
                if ext[0] == "DNS":
                    san_list.append(ext[1].lstrip("*."))
            domain_match = (
                self.domain.endswith(cert_cn.lstrip("*.")) or
                any(self.domain.endswith(s) for s in san_list)
            )

            info = {
                "valid":          True,
                "subject":        cert_cn,
                "issuer":         issuer.get("organizationName",
                                             issuer.get("commonName", "Unknown")),
                "expires":        not_after.strftime("%Y-%m-%d"),
                "days_left":      days_left,
                "expired":        days_left < 0,
                "warning":        0 <= days_left < 30,
                "tls_version":    tls_proto,
                "is_self_signed": is_self_signed,
                "domain_match":   domain_match,
            }

            if info["expired"]:
                extra_findings.append(_finding(
                    "SSL Expired", info["expires"], "Critical", "High",
                    f"Certificate expired {abs(days_left)} days ago"))
            elif info["warning"]:
                extra_findings.append(_finding(
                    "SSL Expiring Soon", f"{days_left} days", "High", "High",
                    "Certificate expires in under 30 days — renew immediately"))

            if is_self_signed:
                extra_findings.append(_finding(
                    "Self-Signed Certificate", cert_cn, "High", "High",
                    "Certificate issued and signed by itself — not trusted by browsers"))

            if not domain_match:
                extra_findings.append(_finding(
                    "SSL Domain Mismatch",
                    f"cert={cert_cn}, scanning={self.domain}",
                    "High", "High",
                    "Certificate CN/SAN does not match the scanned domain"))

            # Weak TLS versions
            weak_tls = _check_tls_weak_versions(self.domain, self.timeout)
            for ver in weak_tls:
                extra_findings.append(_finding(
                    "Weak TLS Version", ver, "High", "High",
                    f"Server accepts {ver} which is deprecated and cryptographically broken"))
            info["weak_tls"] = weak_tls

        except ssl.SSLCertVerificationError as e:
            info = {"valid": False, "error": str(e)}
            extra_findings.append(_finding(
                "SSL Invalid", str(e)[:80], "Critical", "High",
                "TLS handshake failed — certificate is untrusted or misconfigured"))
        except Exception as e:
            info = {"valid": False, "error": str(e)}
            console.print(f"  [red]SSL check error: {e}[/red]")

        self.results["ssl"] = info
        self.results["findings"].extend(extra_findings)
        _print_ssl_table(info)

    # ── 3. Port Scan ──────────────────────────────────────────────────────────

    def port_scan(self) -> None:
        console.print("\n[bold cyan][3/7] Port Scanning...[/bold cyan]")

        def _scan(port: int) -> tuple[int, bool, str]:
            """Returns (port, is_open, banner)."""
            try:
                with socket.create_connection((self.domain, port), timeout=1) as s:
                    # Attempt banner grab
                    banner = ""
                    try:
                        s.settimeout(0.5)
                        raw = s.recv(256)
                        banner = raw.decode("utf-8", errors="replace").strip()[:80]
                    except Exception:
                        pass
                    return port, True, banner
            except Exception:
                return port, False, ""

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      BarColumn(), TextColumn("{task.completed}/{task.total}"),
                      TimeElapsedColumn(), console=console, transient=True) as pg:
            task = pg.add_task("Scanning ports...", total=len(COMMON_PORTS))
            with ThreadPoolExecutor(max_workers=12) as ex:
                futures = {ex.submit(_scan, p): p for p in COMMON_PORTS}
                for f in as_completed(futures):
                    port, is_open, banner = f.result()
                    service, risk, context = PORT_RISK.get(
                        port, ("Unknown", "Low", "Unrecognised port"))
                    self.results["ports"].append(
                        (port, service, is_open, risk, context, banner))
                    if is_open and port not in (80, 443):
                        self.results["findings"].append(_finding(
                            "Open Port",
                            f"{port}/{service}" + (f" [{banner[:40]}]" if banner else ""),
                            risk, "High", context,
                        ))
                    pg.advance(task)

        self.results["ports"].sort(key=lambda x: x[0])
        _print_ports_table(self.results["ports"])

    # ── 4. Subdomain Enumeration ──────────────────────────────────────────────

    def enum_subdomains(self) -> None:
        console.print("\n[bold cyan][4/7] Enumerating Subdomains...[/bold cyan]")

        if not DNS_AVAILABLE:
            console.print("  [yellow]dnspython not installed — skipping.[/yellow]")
            return

        found = []
        stats = {"nxdomain": 0, "timeout": 0}

        def _resolve_and_check(sub: str) -> tuple[Optional[dict], str]:
            fqdn = f"{sub}.{self.domain}"
            try:
                answers = dns.resolver.resolve(fqdn, "A", lifetime=2)
                ip = answers[0].address

                # HTTP probe for takeover + real-page check
                takeover_service = None
                is_live          = False
                http_status      = None
                try:
                    resp = self.session.get(
                        f"https://{fqdn}", timeout=3,
                        verify=False, allow_redirects=True,
                    )
                    http_status = resp.status_code
                    is_live     = http_status < 500
                    for sig, service in TAKEOVER_SIGNATURES:
                        if sig.lower() in resp.text.lower():
                            takeover_service = service
                            break
                except Exception:
                    try:
                        resp = self.session.get(
                            f"http://{fqdn}", timeout=3,
                            verify=False, allow_redirects=True,
                        )
                        http_status = resp.status_code
                        is_live     = http_status < 500
                        for sig, service in TAKEOVER_SIGNATURES:
                            if sig.lower() in resp.text.lower():
                                takeover_service = service
                                break
                    except Exception:
                        pass

                return {
                    "fqdn":             fqdn,
                    "ip":               ip,
                    "is_live":          is_live,
                    "http_status":      http_status,
                    "takeover_service": takeover_service,
                }, "found"

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return None, "nxdomain"
            except (dns.resolver.Timeout, dns.exception.Timeout):
                return None, "timeout"
            except Exception:
                return None, "nxdomain"

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      BarColumn(), TextColumn("{task.completed}/{task.total}"),
                      TimeElapsedColumn(), console=console, transient=True) as pg:
            task = pg.add_task("Resolving + probing subdomains...", total=len(SUBDOMAINS))
            with ThreadPoolExecutor(max_workers=20) as ex:
                futures = {ex.submit(_resolve_and_check, s): s for s in SUBDOMAINS}
                for f in as_completed(futures):
                    result, outcome = f.result()
                    if outcome == "found" and result:
                        found.append(result)
                        risk = "Info"
                        reason = f"Resolved to {result['ip']}"
                        if result["takeover_service"]:
                            risk = "Critical"
                            reason = (f"Takeover indicator detected: "
                                      f"'{result['takeover_service']}' page served")
                            self.results["findings"].append(_finding(
                                "Subdomain Takeover",
                                result["fqdn"],
                                "Critical", "High", reason,
                            ))
                        else:
                            self.results["findings"].append(_finding(
                                "Subdomain Found", result["fqdn"], "Info", "High", reason))
                    elif outcome == "timeout":
                        stats["timeout"] += 1
                    else:
                        stats["nxdomain"] += 1
                    pg.advance(task)

        self.results["subdomains"] = sorted(found, key=lambda x: x["fqdn"])
        console.print(
            f"  Tested [white]{len(SUBDOMAINS)}[/white]  |  "
            f"Found [green]{len(found)}[/green]  |  "
            f"NXDOMAIN [dim]{stats['nxdomain']}[/dim]  |  "
            f"Timeout [yellow]{stats['timeout']}[/yellow]"
        )
        _print_subdomains_table(self.results["subdomains"])

    # ── 5. Directory Bruteforce ───────────────────────────────────────────────

    def dir_bruteforce(self) -> None:
        console.print("\n[bold cyan][5/7] Directory & File Bruteforce...[/bold cyan]")

        origin = self.scan_origin
        console.print(f"  [dim]Scanning origin: {origin}[/dim]")

        # Catch-all / SPA baseline
        baseline_hash: Optional[str] = None
        baseline_len:  Optional[int] = None
        try:
            probe = self.session.get(
                origin + "/ja4scanner_probe_" + secrets.token_hex(6),
                timeout=self.timeout, verify=False, allow_redirects=True,
            )
            if probe.status_code == 200:
                baseline_hash = _body_hash(probe.content)
                baseline_len  = len(probe.content)
                console.print(
                    "  [yellow]Catch-all detected — false-positive filter active.[/yellow]")
        except Exception:
            pass

        wordlist = DIR_WORDLIST
        if self.respect_robots:
            wordlist = [p for p in wordlist if _is_robots_allowed(origin, p)]
            skipped  = len(DIR_WORDLIST) - len(wordlist)
            if skipped:
                console.print(f"  [dim]Skipped {skipped} paths blocked by robots.txt[/dim]")

        found = []

        def _probe(path: str) -> Optional[tuple]:
            try:
                r = self.session.get(
                    origin + path, timeout=self.timeout,
                    verify=False, allow_redirects=False,
                )
                if r.status_code not in (200, 301, 302, 403):
                    return None

                body     = r.content
                body_len = len(body)
                ct       = r.headers.get("Content-Type", "").lower()
                bh       = _body_hash(body)

                # Skip catch-all matches
                if r.status_code == 200 and baseline_hash:
                    if bh == baseline_hash:
                        return None
                    if baseline_len and abs(body_len - baseline_len) <= 5:
                        return None

                # Skip tiny bodies — likely empty error pages
                if r.status_code == 200 and body_len < 100:
                    return None

                # Determine confidence + risk based on content type and sensitivity
                is_sensitive = any(kw in path.lower() for kw in HIGH_RISK_KEYWORDS)
                is_json      = "application/json" in ct
                is_plain     = "text/plain" in ct
                is_html      = "text/html" in ct

                if is_sensitive:
                    if is_json or is_plain:
                        confidence, risk = "High",   "High"
                        reason = (f"Sensitive path with {ct.split(';')[0]} response "
                                  f"({body_len} bytes) — genuine content likely")
                    elif is_html:
                        confidence, risk = "Medium", "Medium"
                        reason = (f"Sensitive path returns HTML — may be real or "
                                  f"custom 403/404 page ({body_len} bytes)")
                    else:
                        confidence, risk = "Medium", "High"
                        reason = f"Sensitive path ({body_len} bytes, {ct.split(';')[0]})"
                else:
                    if is_json:
                        confidence, risk = "High",   "Medium"
                        reason = f"API endpoint discovered — JSON response ({body_len} bytes)"
                    else:
                        confidence, risk = "Low",    "Info"
                        reason = f"Path accessible ({r.status_code}, {body_len} bytes)"

                # 403 on sensitive paths: still worth noting
                if r.status_code == 403 and is_sensitive:
                    confidence, risk = "Medium", "Medium"
                    reason = "Sensitive path returns 403 — resource exists but access denied"

                return path, r.status_code, risk, confidence, reason, body_len, ct

            except Exception:
                return None

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      BarColumn(), TextColumn("{task.completed}/{task.total}"),
                      TimeElapsedColumn(), console=console, transient=True) as pg:
            task = pg.add_task("Probing paths...", total=len(wordlist))
            with ThreadPoolExecutor(max_workers=20) as ex:
                futures = {ex.submit(_probe, p): p for p in wordlist}
                for f in as_completed(futures):
                    result = f.result()
                    if result:
                        path, status, risk, confidence, reason, blen, ct = result
                        found.append((path, status, risk, confidence, reason, blen))
                        self.results["findings"].append(_finding(
                            "Path Found",
                            f"{origin}{path} [{status}]",
                            risk, confidence, reason,
                        ))
                    pg.advance(task)

        self.results["dirs"] = sorted(found, key=lambda x: x[0])
        _print_dirs_table(self.results["dirs"], origin)

    # ── 6. XSS Scanner ────────────────────────────────────────────────────────

    def scan_xss(self) -> None:
        console.print("\n[bold cyan][6/7] XSS Scanner...[/bold cyan]")
        vulnerable = []

        targets = _collect_injection_points(self.base_url, self.session, self.timeout)
        if not targets:
            console.print("  [dim]No injection points found for XSS testing.[/dim]")
            self.results["xss"] = []
            return

        total = len(targets) * len(XSS_PAYLOAD_TEMPLATES)

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      BarColumn(), TextColumn("{task.completed}/{task.total}"),
                      console=console, transient=True) as pg:
            task = pg.add_task("Testing XSS payloads...", total=total)

            for point in targets:
                for template, high_indicators in XSS_PAYLOAD_TEMPLATES:
                    token   = _canary()
                    payload = template.format(canary=token)

                    try:
                        r = _inject(self.session, point, payload, self.timeout)
                        if r:
                            conf = _xss_confidence(r.text, token, payload, high_indicators)
                            if conf in ("High", "Medium"):
                                reason = (
                                    f"Canary '{token}' reflects unencoded in response "
                                    f"({'dangerous execution context detected' if conf == 'High' else 'HTML context, structure may be stripped'})"
                                )
                                entry = (point["param"], payload, point["url"], conf, reason)
                                if entry not in vulnerable:
                                    vulnerable.append(entry)
                                    self.results["findings"].append(_finding(
                                        "XSS Reflected",
                                        f"param={point['param']} url={point['url']}",
                                        "High", conf, reason,
                                    ))
                    except Exception:
                        pass
                    pg.advance(task)

        self.results["xss"] = vulnerable
        _print_xss_table(vulnerable)

    # ── 7. SQLi Scanner ───────────────────────────────────────────────────────

    def scan_sqli(self) -> None:
        console.print("\n[bold cyan][7/7] SQL Injection Scanner...[/bold cyan]")
        vulnerable = []

        targets = _collect_injection_points(self.base_url, self.session, self.timeout)
        if not targets:
            console.print("  [dim]No injection points found for SQLi testing.[/dim]")
            self.results["sqli"] = []
            return

        # Baseline RTT for time-based detection
        baseline_rtt = _measure_baseline_rtt(self.session, targets[0], self.timeout)
        time_threshold = baseline_rtt + 2.5
        console.print(
            f"  [dim]Baseline RTT: {baseline_rtt:.2f}s  |  "
            f"Time threshold: {time_threshold:.2f}s[/dim]"
        )

        total = len(targets) * (
            len(SQLI_ERROR_PAYLOADS) + 1 + len(SQLI_BOOLEAN_PAIRS)
        )

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      BarColumn(), TextColumn("{task.completed}/{task.total}"),
                      console=console, transient=True) as pg:
            task = pg.add_task("Testing SQLi payloads...", total=total)

            for point in targets:
                # ── Baseline response for boolean comparison ──────────────────
                try:
                    b_resp = _inject(self.session, point, "safe_baseline", self.timeout)
                    baseline_text = b_resp.text if b_resp else ""
                except Exception:
                    baseline_text = ""

                error_found   = False
                boolean_found = False
                time_found    = False
                error_pattern = ""
                bool_diff_pct = 0.0

                # ── Error-based ───────────────────────────────────────────────
                for payload in SQLI_ERROR_PAYLOADS:
                    try:
                        r = _inject(self.session, point, payload, self.timeout)
                        if r:
                            hit = _sqli_error_hit(r.text)
                            if hit:
                                error_found   = True
                                error_pattern = hit
                                break
                    except Exception:
                        pass
                    pg.advance(task)

                # ── Boolean-based ─────────────────────────────────────────────
                for true_pl, false_pl in SQLI_BOOLEAN_PAIRS:
                    try:
                        r_true  = _inject(self.session, point, true_pl,  self.timeout)
                        r_false = _inject(self.session, point, false_pl, self.timeout)
                        if r_true and r_false:
                            t_text, f_text = r_true.text, r_false.text
                            # True and false differ from each other AND at least one
                            # differs from baseline → genuine conditional response
                            tf_diff = _significant_diff(t_text, f_text)
                            tb_diff = _significant_diff(t_text, baseline_text)
                            if tf_diff and tb_diff:
                                boolean_found = True
                                longer = max(len(t_text), len(f_text))
                                if longer:
                                    bool_diff_pct = (
                                        abs(len(t_text) - len(f_text)) / longer * 100
                                    )
                                break
                    except Exception:
                        pass
                    pg.advance(task)

                # ── Time-based ────────────────────────────────────────────────
                try:
                    t0      = time.time()
                    r       = _inject(self.session, point, SQLI_TIME_PAYLOAD, self.timeout)
                    elapsed = time.time() - t0
                    if r and elapsed >= time_threshold:
                        time_found = True
                except Exception:
                    pass
                pg.advance(task)

                # ── Confidence resolution ─────────────────────────────────────
                if not (error_found or boolean_found):
                    # time-only = Low confidence — skip
                    continue

                if error_found and boolean_found:
                    confidence = "High"
                    method     = "error-based + boolean-based"
                    reason     = (
                        f"DB error pattern '{error_pattern}' in response AND "
                        f"boolean payloads changed response by {bool_diff_pct:.0f}%"
                    )
                elif error_found:
                    confidence = "High"
                    method     = "error-based"
                    reason     = f"DB error pattern '{error_pattern}' found in response"
                else:   # boolean only
                    confidence = "Medium"
                    method     = "boolean-based"
                    reason     = (
                        f"True/false payloads caused {bool_diff_pct:.0f}% response "
                        f"length difference vs baseline"
                    )

                if time_found:
                    method += " + time-based"
                    if confidence != "High":
                        confidence = "High"
                        reason += f" AND time-based delay >= {time_threshold:.1f}s"

                entry = (point["param"], method, point["url"], confidence, reason)
                if entry not in vulnerable:
                    vulnerable.append(entry)
                    self.results["findings"].append(_finding(
                        "SQL Injection",
                        f"param={point['param']} [{method}] url={point['url']}",
                        "Critical", confidence, reason,
                    ))

        self.results["sqli"] = vulnerable
        _print_sqli_table(vulnerable)

    # ── Full Scan Orchestrator ─────────────────────────────────────────────────

    def run_full_scan(self, no_robots: bool = False) -> dict:
        if no_robots:
            self.respect_robots = False

        console.print(Panel(
            f"[bold cyan]Active Recon Scanner[/bold cyan]\n"
            f"[dim]Input URL  : {self.base_url}[/dim]\n"
            f"[dim]Scan origin: {self.scan_origin}[/dim]\n"
            f"[dim]robots.txt : {'ignored (--no-robots)' if no_robots else 'respected'}[/dim]",
            border_style="cyan",
        ))

        self.check_headers()
        self.check_ssl()
        self.port_scan()
        self.enum_subdomains()
        self.dir_bruteforce()
        self.scan_xss()
        self.scan_sqli()
        self._print_summary()
        return self.results

    # ── Summary ───────────────────────────────────────────────────────────────

    def _print_summary(self) -> None:
        console.print("\n")

        all_findings = self.results["findings"]
        high_crit    = [f for f in all_findings
                        if f["risk"] in ("Critical", "High")]
        low_info     = [f for f in all_findings
                        if f["risk"] not in ("Critical", "High")]

        console.print(Panel(
            f"[bold white]Scan Summary[/bold white]  "
            f"[dim]({len(all_findings)} total findings)[/dim]",
            border_style="cyan",
        ))

        def _make_table(findings: list, title: str) -> Table:
            t = Table(title=title, box=box.ROUNDED, border_style="cyan", show_lines=False)
            t.add_column("Finding Type",  style="bold white",  width=22)
            t.add_column("Detail",        style="white",        width=46)
            t.add_column("Risk",          style="bold",         width=10, justify="center")
            t.add_column("Confidence",    style="bold",         width=11, justify="center")
            t.add_column("Reason",        style="dim",          width=40)

            seen = set()
            for f in sorted(findings,
                            key=lambda x: RISK_ORDER.index(x["risk"])):
                key = (f["type"], f["detail"])
                if key in seen:
                    continue
                seen.add(key)
                rc = RISK_COLOR.get(f["risk"], "white")
                cc = CONF_COLOR.get(f.get("confidence", "High"), "white")
                t.add_row(
                    f["type"],
                    f["detail"][:46] + ("…" if len(f["detail"]) > 46 else ""),
                    f"[{rc}]{f['risk']}[/{rc}]",
                    f"[{cc}]{f.get('confidence','High')}[/{cc}]",
                    f.get("reason", "")[:40],
                )
            return t

        if high_crit:
            console.print(_make_table(high_crit, "High / Critical Findings"))
        else:
            console.print("  [green]No High or Critical findings.[/green]")

        c = sum(1 for f in all_findings if f["risk"] == "Critical")
        h = sum(1 for f in all_findings if f["risk"] == "High")
        m = sum(1 for f in all_findings if f["risk"] == "Medium")
        console.print(
            f"\n  [bold bright_red]{c} Critical[/bold bright_red]  "
            f"[bold red]{h} High[/bold red]  "
            f"[yellow]{m} Medium[/yellow]  "
            f"[dim]{len(low_info)} Low/Info[/dim]"
        )

        if low_info:
            show_all = Confirm.ask(
                "\n  [cyan]Show all findings including Low/Info?[/cyan]",
                default=False,
            )
            if show_all:
                console.print(_make_table(all_findings, "All Findings"))


# ── Injection Point Helpers ───────────────────────────────────────────────────

def _collect_injection_points(base_url: str, session: requests.Session,
                               timeout: int) -> list[dict]:
    points = []
    parsed = urllib.parse.urlparse(base_url)
    qs     = urllib.parse.parse_qs(parsed.query)

    for param in qs:
        points.append({
            "type":   "url",
            "url":    base_url,
            "method": "GET",
            "param":  param,
            "data":   {k: v[0] for k, v in qs.items()},
        })

    try:
        r = session.get(base_url, timeout=timeout, verify=False)
        for form in _parse_forms(r.text, base_url):
            for field in form["fields"]:
                points.append({
                    "type":   "form",
                    "url":    form["action"],
                    "method": form["method"],
                    "param":  field,
                    "data":   {f: "test" for f in form["fields"]},
                })
    except Exception:
        pass

    return points


def _parse_forms(html: str, base_url: str) -> list[dict]:
    forms       = []
    parsed_base = urllib.parse.urlparse(base_url)
    form_blocks = re.findall(r"<form[^>]*>(.*?)</form>", html, re.IGNORECASE | re.DOTALL)
    form_tags   = re.findall(r"<form([^>]*)>",           html, re.IGNORECASE)

    for tag_attrs, body in zip(form_tags, form_blocks):
        action_m = re.search(r'action=["\']([^"\']*)["\']', tag_attrs, re.IGNORECASE)
        method_m = re.search(r'method=["\']([^"\']*)["\']', tag_attrs, re.IGNORECASE)
        action   = action_m.group(1) if action_m else base_url
        method   = method_m.group(1).upper() if method_m else "GET"
        if action and not action.startswith("http"):
            action = urllib.parse.urljoin(
                f"{parsed_base.scheme}://{parsed_base.netloc}", action)
        fields = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE)
        ta     = re.findall(r'<textarea[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE)
        all_f  = list(set(fields + ta))
        if all_f:
            forms.append({"action": action, "method": method, "fields": all_f})
    return forms


def _inject(session: requests.Session, point: dict, payload: str,
            timeout: int) -> Optional[requests.Response]:
    data = dict(point["data"])
    data[point["param"]] = payload
    try:
        if point["method"] == "GET" or point["type"] == "url":
            return session.get(point["url"], params=data, timeout=timeout, verify=False)
        return session.post(point["url"], data=data, timeout=timeout, verify=False)
    except Exception:
        return None


# ── Print Helpers ─────────────────────────────────────────────────────────────

def _print_headers_table(headers: list[dict]) -> None:
    table = Table(title="Security Headers", box=box.ROUNDED, border_style="cyan")
    table.add_column("Header",       style="bold white", width=30)
    table.add_column("Status",       style="bold",       width=14, justify="center")
    table.add_column("Risk",         style="bold",       width=10, justify="center")
    table.add_column("Value / Reason", style="dim",      width=50)

    color_map = {"PRESENT": "green", "MISSING": "red", "MISCONFIGURED": "yellow"}
    for h in headers:
        sc  = color_map.get(h["status"], "white")
        rc  = RISK_COLOR.get(h["risk"], "white")
        val = h["value"] if h["value"] else h["reason"]
        table.add_row(
            h["header"],
            f"[{sc}]{h['status']}[/{sc}]",
            f"[{rc}]{h['risk']}[/{rc}]",
            val[:50],
        )
    console.print(table)


def _print_ssl_table(info: dict) -> None:
    table = Table(title="SSL Certificate", box=box.ROUNDED, border_style="cyan")
    table.add_column("Field", style="bold white", width=20)
    table.add_column("Value", style="white")

    if not info.get("valid", True) and "error" in info:
        table.add_row("Error", f"[red]{info['error'][:80]}[/red]")
        console.print(table)
        return

    days = info.get("days_left", 0)
    if info.get("expired"):
        days_str = f"[bold bright_red]EXPIRED ({abs(days)} days ago)[/bold bright_red]"
    elif info.get("warning"):
        days_str = f"[yellow]{days} days — renew soon[/yellow]"
    else:
        days_str = f"[green]{days} days[/green]"

    table.add_row("Subject",     info.get("subject",     "N/A"))
    table.add_row("Issuer",      info.get("issuer",      "N/A"))
    table.add_row("Expires",     info.get("expires",     "N/A"))
    table.add_row("Days Left",   days_str)
    table.add_row("Valid",       "[green]Yes[/green]" if info.get("valid") else "[red]No[/red]")
    table.add_row("TLS Version", info.get("tls_version", "N/A"))

    self_signed = info.get("is_self_signed")
    if self_signed is not None:
        table.add_row("Self-Signed",
                      "[bold red]Yes[/bold red]" if self_signed else "[green]No[/green]")

    domain_match = info.get("domain_match")
    if domain_match is not None:
        table.add_row("Domain Match",
                      "[green]Yes[/green]" if domain_match else "[bold red]No[/bold red]")

    weak_tls = info.get("weak_tls", [])
    if weak_tls:
        table.add_row("Weak TLS", f"[bold red]{', '.join(weak_tls)}[/bold red]")
    else:
        table.add_row("Weak TLS", "[green]None accepted[/green]")

    console.print(table)


def _print_ports_table(ports: list[tuple]) -> None:
    table = Table(title="Port Scan", box=box.ROUNDED, border_style="cyan")
    table.add_column("Port",    style="bold white", width=6)
    table.add_column("Service", style="white",      width=12)
    table.add_column("Status",  style="bold",       width=8,  justify="center")
    table.add_column("Risk",    style="bold",       width=10, justify="center")
    table.add_column("Banner / Context", style="dim", width=50)

    for port, service, is_open, risk, context, banner in ports:
        rc = RISK_COLOR.get(risk, "white")
        if is_open:
            status_str = "[green]OPEN[/green]"
            detail     = banner if banner else context
        else:
            status_str = "[dim]closed[/dim]"
            detail     = ""
            rc         = "white"
            risk       = ""
        table.add_row(str(port), service, status_str,
                      f"[{rc}]{risk}[/{rc}]" if risk else "",
                      detail[:50])
    console.print(table)


def _print_subdomains_table(subdomains: list[dict]) -> None:
    if not subdomains:
        console.print("  [dim]No subdomains resolved.[/dim]")
        return
    table = Table(title=f"Subdomains ({len(subdomains)})", box=box.ROUNDED, border_style="cyan")
    table.add_column("Subdomain",   style="bold cyan",   width=40)
    table.add_column("IP",          style="white",       width=16)
    table.add_column("HTTP",        style="white",       width=6,  justify="center")
    table.add_column("Takeover?",   style="bold",        width=12, justify="center")

    for s in subdomains:
        http_str = str(s["http_status"]) if s["http_status"] else "[dim]N/A[/dim]"
        tko      = s["takeover_service"]
        tko_str  = f"[bold bright_red]{tko}[/bold bright_red]" if tko else "[dim]No[/dim]"
        table.add_row(s["fqdn"], s["ip"], http_str, tko_str)
    console.print(table)


def _print_dirs_table(dirs: list[tuple], origin: str) -> None:
    if not dirs:
        console.print("  [dim]No interesting paths found.[/dim]")
        return
    table = Table(title=f"Paths Found ({len(dirs)})", box=box.ROUNDED, border_style="cyan")
    table.add_column("Path",       style="bold white",  width=42)
    table.add_column("Status",     style="bold",        width=8,  justify="center")
    table.add_column("Risk",       style="bold",        width=9,  justify="center")
    table.add_column("Confidence", style="bold",        width=11, justify="center")
    table.add_column("Bytes",      style="dim",         width=7,  justify="right")

    sc_map = {200: "green", 301: "yellow", 302: "yellow", 403: "dim"}
    for path, status, risk, confidence, reason, blen in sorted(
            dirs, key=lambda x: RISK_ORDER.index(x[2])):
        sc = sc_map.get(status, "white")
        rc = RISK_COLOR.get(risk, "white")
        cc = CONF_COLOR.get(confidence, "white")
        table.add_row(
            origin + path,
            f"[{sc}]{status}[/{sc}]",
            f"[{rc}]{risk}[/{rc}]",
            f"[{cc}]{confidence}[/{cc}]",
            str(blen),
        )
    console.print(table)


def _print_xss_table(vulns: list[tuple]) -> None:
    if not vulns:
        console.print("  [green]No reflected XSS found.[/green]")
        return
    table = Table(title=f"XSS Vulnerabilities ({len(vulns)})",
                  box=box.ROUNDED, border_style="red")
    table.add_column("Parameter",  style="bold red",   width=14)
    table.add_column("Confidence", style="bold",       width=11, justify="center")
    table.add_column("Payload",    style="yellow",     width=42)
    table.add_column("URL",        style="dim",        width=40)

    for param, payload, url, confidence, reason in vulns:
        cc = CONF_COLOR.get(confidence, "white")
        table.add_row(param, f"[{cc}]{confidence}[/{cc}]", payload[:42], url[:40])
    console.print(table)


def _print_sqli_table(vulns: list[tuple]) -> None:
    if not vulns:
        console.print("  [green]No SQL injection found.[/green]")
        return
    table = Table(title=f"SQL Injection ({len(vulns)})",
                  box=box.ROUNDED, border_style="magenta")
    table.add_column("Parameter",  style="bold magenta", width=14)
    table.add_column("Method",     style="bold",         width=30)
    table.add_column("Confidence", style="bold",         width=11, justify="center")
    table.add_column("URL",        style="dim",          width=40)

    for param, method, url, confidence, reason in vulns:
        cc = CONF_COLOR.get(confidence, "white")
        table.add_row(param, method, f"[{cc}]{confidence}[/{cc}]", url[:40])
    console.print(table)


# ── Entry Point ───────────────────────────────────────────────────────────────

def run_scanner() -> None:
    console.print(Panel(
        "[bold cyan]Active Recon Scanner[/bold cyan]\n"
        "[dim]Runs: headers · SSL · ports · subdomains · dirs · XSS · SQLi[/dim]\n"
        "[bold red]Only scan targets you have explicit written permission to test.[/bold red]",
        border_style="cyan",
    ))

    target = Prompt.ask("\n  [cyan]Enter target URL or domain[/cyan]").strip()
    if not target:
        console.print("[red]  No target provided.[/red]")
        return

    no_robots = Confirm.ask(
        "  [cyan]Bypass robots.txt restrictions?[/cyan]", default=False)

    scanner = ReconScanner(target, respect_robots=not no_robots)
    results = scanner.run_full_scan(no_robots=no_robots)

    critical = [f for f in results["findings"] if f["risk"] in ("Critical", "High")]
    if critical:
        console.print(f"\n  [bold red]{len(critical)} High/Critical findings.[/bold red]")
        if Confirm.ask(
            "  [cyan]Generate a bug bounty report for these findings?[/cyan]",
            default=True,
        ):
            from report_generator import run_report_generator
            sqli = any(f["type"] == "SQL Injection"  for f in critical)
            xss  = any(f["type"] == "XSS Reflected"  for f in critical)
            sslx = any(f["type"] == "SSL Expired"     for f in critical)
            tko  = any(f["type"] == "Subdomain Takeover" for f in critical)
            if sqli:
                score, sev, vuln = 9.8, "Critical", "SQLI"
            elif xss:
                score, sev, vuln = 8.8, "High",     "XSS"
            elif tko:
                score, sev, vuln = 9.1, "Critical", "IDOR"
            elif sslx:
                score, sev, vuln = 7.5, "High",     "AUTH_BYPASS"
            else:
                score, sev, vuln = 7.0, "High",     "AUTH_BYPASS"
            run_report_generator(prefill_score=score, prefill_severity=sev,
                                 prefill_vuln=vuln)
