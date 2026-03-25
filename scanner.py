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

# ── Constants ─────────────────────────────────────────────────────────────────

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080, 8443, 8888]

PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Dev",
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

HIGH_RISK_PATHS = {".env", ".git", "backup", "config", "dump", "sql",
                   "secret", "private", "internal", "hidden", "web.config",
                   ".htaccess"}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Permissions-Policy",
    "Referrer-Policy",
]

HEADER_NOTES = {
    "Strict-Transport-Security": "Forces HTTPS connections",
    "Content-Security-Policy":   "Prevents XSS and data injection",
    "X-Frame-Options":           "Prevents clickjacking",
    "X-Content-Type-Options":    "Prevents MIME-type sniffing",
    "Permissions-Policy":        "Controls browser feature access",
    "Referrer-Policy":           "Controls referrer information leakage",
}

# FIX-F3: payload templates with {canary} placeholder instead of literal values
XSS_PAYLOAD_TEMPLATES = [
    '<script>alert("{canary}")</script>',
    '"><img src=x onerror=alert("{canary}")>',
    '"><svg onload=alert("{canary}")>',
    '<details open ontoggle=alert("{canary}")>',
    "'><{canary}>",          # bare reflection check — HTML tag injection
]

SQLI_PAYLOADS = [
    ("' OR '1'='1",           "error"),
    ("' OR 1=1--",            "error"),
    ("1; DROP TABLE users--", "error"),
    ("' UNION SELECT null--", "error"),
    ("1' AND SLEEP(5)--",     "time"),   # 5 s sleep; flagged only if > baseline+2.5 s
]

SQL_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql_fetch",
    r"ORA-\d{5}",
    r"syntax error.*sql",
    r"unclosed quotation",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"sqlite3\.OperationalError",
    r"SQLSTATE\[",
    r"Warning.*mysql_",
    r"Microsoft OLE DB Provider for SQL Server",
    r"Incorrect syntax near",
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
    """FIX-F1: Return scheme+netloc only — no path, no query string.

    >>> _origin("https://www.thegitcity.com/leaderboard?mode=game&tab=flight")
    'https://www.thegitcity.com'
    """
    p = urllib.parse.urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _extract_domain(url: str) -> str:
    return urllib.parse.urlparse(url).hostname or url


def _body_hash(response: requests.Response) -> str:
    """MD5 of the response body — used for SPA false-positive detection."""
    return hashlib.md5(response.content).hexdigest()


def _is_robots_allowed(origin_url: str, path: str) -> bool:
    """Returns True if robots.txt allows the path."""
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
    """FIX-F3: Generate a unique 8-hex-char canary token."""
    return "ja4xss_" + secrets.token_hex(4)


# ── ReconScanner ──────────────────────────────────────────────────────────────

class ReconScanner:
    def __init__(self, target: str, respect_robots: bool = True, timeout: int = 5):
        self.raw_target   = target
        self.base_url     = _normalize_url(target)        # full URL, used for XSS/SQLi injection points
        self.scan_origin  = _origin(self.base_url)        # FIX-F1: scheme+netloc only, used for dir scan
        self.domain       = _extract_domain(self.base_url)
        self.respect_robots = respect_robots
        self.timeout      = timeout
        self.session      = _make_session()

        self.results: dict = {
            "headers":    [],
            "ssl":        {},
            "ports":      [],
            "subdomains": [],
            "dirs":       [],
            "xss":        [],
            "sqli":       [],
            "findings":   [],
        }

    # ── 1. Security Headers ───────────────────────────────────────────────────

    def check_headers(self) -> None:
        console.print("\n[bold cyan][1/7] Checking Security Headers...[/bold cyan]")
        try:
            r = self.session.get(self.base_url, timeout=self.timeout,
                                 verify=False, allow_redirects=True)
            resp_headers = {k.lower(): v for k, v in r.headers.items()}

            for header in SECURITY_HEADERS:
                key     = header.lower()
                present = key in resp_headers
                value   = resp_headers.get(key, "")

                misconfigured = False
                if present:
                    if header == "Strict-Transport-Security" and "max-age=0" in value:
                        misconfigured = True
                    if header == "X-Frame-Options" and value.upper() not in ("DENY", "SAMEORIGIN"):
                        misconfigured = True
                    if header == "X-Content-Type-Options" and value.lower() != "nosniff":
                        misconfigured = True

                status = "MISCONFIGURED" if misconfigured else ("PRESENT" if present else "MISSING")
                self.results["headers"].append({
                    "header": header, "status": status,
                    "value": value, "note": HEADER_NOTES.get(header, ""),
                })

                if status == "MISSING":
                    self.results["findings"].append(
                        {"type": "Missing Header", "detail": header, "risk": "Medium"})
                elif status == "MISCONFIGURED":
                    self.results["findings"].append(
                        {"type": "Misconfigured Header", "detail": f"{header}: {value}", "risk": "Medium"})

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
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.create_connection((self.domain, 443), timeout=self.timeout),
                server_hostname=self.domain,
            ) as sock:
                cert = sock.getpeercert()

            not_after = datetime.strptime(
                cert.get("notAfter", ""), "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)
            days_left = (not_after - datetime.now(timezone.utc)).days

            issuer  = dict(x[0] for x in cert.get("issuer",  []))
            subject = dict(x[0] for x in cert.get("subject", []))

            info = {
                "valid":     True,
                "subject":   subject.get("commonName", "Unknown"),
                "issuer":    issuer.get("organizationName", issuer.get("commonName", "Unknown")),
                "expires":   not_after.strftime("%Y-%m-%d"),
                "days_left": days_left,
                "expired":   days_left < 0,
                "warning":   0 <= days_left < 30,
            }
            self.results["ssl"] = info

            if info["expired"]:
                self.results["findings"].append(
                    {"type": "SSL Expired", "detail": info["expires"], "risk": "Critical"})
            elif info["warning"]:
                self.results["findings"].append(
                    {"type": "SSL Expiring Soon", "detail": f"{days_left} days", "risk": "High"})

            _print_ssl_table(info)

        except ssl.SSLCertVerificationError as e:
            console.print(f"  [red]SSL verification failed: {e}[/red]")
            self.results["ssl"] = {"valid": False, "error": str(e)}
            self.results["findings"].append(
                {"type": "SSL Invalid", "detail": str(e)[:80], "risk": "Critical"})
        except Exception as e:
            console.print(f"  [red]SSL check error: {e}[/red]")
            self.results["ssl"] = {"valid": False, "error": str(e)}

    # ── 3. Port Scan ──────────────────────────────────────────────────────────

    def port_scan(self) -> None:
        console.print("\n[bold cyan][3/7] Port Scanning...[/bold cyan]")

        def _scan(port: int) -> tuple[int, bool]:
            try:
                with socket.create_connection((self.domain, port), timeout=1):
                    return port, True
            except Exception:
                return port, False

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      BarColumn(), TextColumn("{task.completed}/{task.total}"),
                      TimeElapsedColumn(), console=console, transient=True) as pg:
            task = pg.add_task("Scanning ports...", total=len(COMMON_PORTS))
            with ThreadPoolExecutor(max_workers=12) as ex:
                futures = {ex.submit(_scan, p): p for p in COMMON_PORTS}
                for f in as_completed(futures):
                    port, is_open = f.result()
                    name = PORT_NAMES.get(port, "Unknown")
                    self.results["ports"].append((port, name, is_open))
                    if is_open and port not in (80, 443):
                        self.results["findings"].append({
                            "type": "Open Port",
                            "detail": f"{port}/{name}",
                            "risk": "High" if port in (22, 3389) else "Medium",
                        })
                    pg.advance(task)

        self.results["ports"].sort(key=lambda x: x[0])
        _print_ports_table(self.results["ports"])

    # ── 4. Subdomain Enumeration ──────────────────────────────────────────────

    def enum_subdomains(self) -> None:
        console.print("\n[bold cyan][4/7] Enumerating Subdomains...[/bold cyan]")

        if not DNS_AVAILABLE:
            console.print("  [yellow]dnspython not installed — skipping.[/yellow]")
            return

        found       = []
        # FIX-F4: track outcome categories
        stats = {"nxdomain": 0, "timeout": 0, "other_err": 0}

        def _resolve(sub: str) -> tuple[Optional[tuple[str, str]], str]:
            """Returns (result, outcome) where outcome is one of:
            'found', 'nxdomain', 'timeout', 'error'"""
            fqdn = f"{sub}.{self.domain}"
            try:
                answers = dns.resolver.resolve(fqdn, "A", lifetime=2)
                return (fqdn, answers[0].address), "found"
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return None, "nxdomain"
            except (dns.resolver.Timeout, dns.exception.Timeout):
                return None, "timeout"
            except Exception:
                return None, "error"

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      BarColumn(), TextColumn("{task.completed}/{task.total}"),
                      TimeElapsedColumn(), console=console, transient=True) as pg:
            task = pg.add_task("Resolving subdomains...", total=len(SUBDOMAINS))
            with ThreadPoolExecutor(max_workers=20) as ex:
                futures = {ex.submit(_resolve, s): s for s in SUBDOMAINS}
                for f in as_completed(futures):
                    result, outcome = f.result()
                    if outcome == "found" and result:
                        fqdn, ip = result
                        found.append((fqdn, ip))
                        self.results["findings"].append(
                            {"type": "Subdomain Found", "detail": f"{fqdn} → {ip}", "risk": "Info"})
                    elif outcome == "timeout":
                        stats["timeout"] += 1
                    elif outcome in ("nxdomain", "error"):
                        stats["nxdomain"] += 1
                    pg.advance(task)

        self.results["subdomains"] = sorted(found, key=lambda x: x[0])

        # FIX-F4: summary stats line
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

        # FIX-F1: always use origin (scheme+netloc), never the full input URL
        origin = self.scan_origin
        console.print(f"  [dim]Scanning origin: {origin}[/dim]")

        # FIX-F2: fetch baseline to detect catch-all / SPA false-positives
        baseline_hash: Optional[str] = None
        baseline_len:  Optional[int] = None
        try:
            probe_path = "/ja4scanner_canary_" + secrets.token_hex(6)
            bline = self.session.get(
                origin + probe_path, timeout=self.timeout,
                verify=False, allow_redirects=True,
            )
            if bline.status_code == 200:
                baseline_hash = _body_hash(bline)
                baseline_len  = len(bline.content)
                console.print(
                    f"  [yellow]Catch-all detected (canary path returned 200). "
                    f"False-positive filter active.[/yellow]"
                )
        except Exception:
            pass

        wordlist = DIR_WORDLIST
        if self.respect_robots:
            wordlist = [p for p in wordlist if _is_robots_allowed(origin, p)]
            skipped  = len(DIR_WORDLIST) - len(wordlist)
            if skipped:
                console.print(f"  [dim]Skipped {skipped} paths blocked by robots.txt[/dim]")

        found = []

        def _probe(path: str) -> Optional[tuple[str, int, str]]:
            try:
                r = self.session.get(
                    origin + path,          # FIX-F1: origin, not base_url
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False,
                )
                if r.status_code not in (200, 301, 302, 403):
                    return None

                # FIX-F2: skip if body matches catch-all baseline
                if r.status_code == 200 and baseline_hash is not None:
                    if _body_hash(r) == baseline_hash:
                        return None
                    # Also skip near-identical small variations (±5 bytes on tiny pages)
                    if baseline_len is not None and abs(len(r.content) - baseline_len) <= 5:
                        return None

                risk = "Info"
                for keyword in HIGH_RISK_PATHS:
                    if keyword in path.lower():
                        risk = "High"
                        break
                return path, r.status_code, risk
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
                        path, status, risk = result
                        found.append((path, status, risk))
                        self.results["findings"].append({
                            "type":   "Path Found",
                            "detail": f"{origin}{path} [{status}]",
                            "risk":   risk,
                        })
                    pg.advance(task)

        self.results["dirs"] = sorted(found, key=lambda x: x[0])
        _print_dirs_table(self.results["dirs"], origin)  # FIX-F1: pass origin

    # ── 6. XSS Scanner ────────────────────────────────────────────────────────

    def scan_xss(self) -> None:
        console.print("\n[bold cyan][6/7] XSS Scanner...[/bold cyan]")
        vulnerable = []

        # Collect injection points from the *original* URL (preserves query params)
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
                for template in XSS_PAYLOAD_TEMPLATES:
                    # FIX-F3: unique canary per request
                    token   = _canary()                          # e.g. ja4xss_a1b2c3d4
                    payload = template.format(canary=token)

                    try:
                        r = _inject(self.session, point, payload, self.timeout)
                        # Only flag if our exact canary reflects back unencoded
                        if r and token in r.text:
                            entry = (point["param"], payload, point["url"])
                            if entry not in vulnerable:
                                vulnerable.append(entry)
                                self.results["findings"].append({
                                    "type":   "XSS Reflected",
                                    "detail": f"param={point['param']} url={point['url']}",
                                    "risk":   "High",
                                })
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

        # FIX-F5: measure baseline RTT before injection
        baseline_rtt = _measure_baseline_rtt(
            self.session, targets[0], self.timeout
        )
        time_threshold = baseline_rtt + 2.5
        console.print(
            f"  [dim]Baseline RTT: {baseline_rtt:.2f}s — "
            f"time-based threshold: {time_threshold:.2f}s[/dim]"
        )

        total = len(targets) * len(SQLI_PAYLOADS)

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      BarColumn(), TextColumn("{task.completed}/{task.total}"),
                      console=console, transient=True) as pg:
            task = pg.add_task("Testing SQLi payloads...", total=total)

            for point in targets:
                for payload, kind in SQLI_PAYLOADS:
                    try:
                        t0      = time.time()
                        r       = _inject(self.session, point, payload, self.timeout)
                        elapsed = time.time() - t0

                        if r:
                            found = False
                            if kind == "error":
                                for pattern in SQL_ERROR_PATTERNS:
                                    if re.search(pattern, r.text, re.IGNORECASE):
                                        found = True
                                        break
                            elif kind == "time" and elapsed >= time_threshold:  # FIX-F5
                                found = True

                            if found:
                                entry = (point["param"], payload, kind, point["url"])
                                if entry not in vulnerable:
                                    vulnerable.append(entry)
                                    self.results["findings"].append({
                                        "type":   "SQL Injection",
                                        "detail": f"param={point['param']} [{kind}] url={point['url']}",
                                        "risk":   "Critical",
                                    })
                    except Exception:
                        pass
                    pg.advance(task)

        self.results["sqli"] = vulnerable
        _print_sqli_table(vulnerable)

    # ── Full Scan Orchestrator ─────────────────────────────────────────────────

    def run_full_scan(self, no_robots: bool = False) -> dict:
        if no_robots:
            self.respect_robots = False

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        console.print(Panel(
            f"[bold cyan]Active Recon Scanner[/bold cyan]\n"
            f"[dim]Input URL : {self.base_url}[/dim]\n"
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

    def _print_summary(self) -> None:
        console.print("\n")
        console.print(Panel("[bold white]Scan Summary[/bold white]", border_style="cyan"))

        table = Table(box=box.ROUNDED, border_style="cyan")
        table.add_column("Finding Type", style="bold white")
        table.add_column("Detail",       style="white")
        table.add_column("Risk",         style="bold", justify="center")

        risk_order = ["Critical", "High", "Medium", "Info"]
        risk_color = {"Critical": "magenta", "High": "red",
                      "Medium": "yellow", "Info": "cyan"}

        seen = set()
        for f in sorted(self.results["findings"],
                        key=lambda x: risk_order.index(x["risk"])):
            key = (f["type"], f["detail"])
            if key in seen:
                continue
            seen.add(key)
            color = risk_color.get(f["risk"], "white")
            table.add_row(
                f["type"],
                f["detail"][:80] + ("…" if len(f["detail"]) > 80 else ""),
                f"[{color}]{f['risk']}[/{color}]",
            )

        if not self.results["findings"]:
            table.add_row("[dim]No significant findings[/dim]", "", "")

        console.print(table)

        c = sum(1 for f in self.results["findings"] if f["risk"] == "Critical")
        h = sum(1 for f in self.results["findings"] if f["risk"] == "High")
        if c or h:
            console.print(
                f"\n  [bold magenta]{c} Critical[/bold magenta]  "
                f"[bold red]{h} High[/bold red] findings detected."
            )


# ── Injection Point Helpers ───────────────────────────────────────────────────

def _collect_injection_points(base_url: str, session: requests.Session,
                               timeout: int) -> list[dict]:
    """
    Collect injection points from:
    1. Query parameters present in base_url  (tested against the original URL)
    2. HTML form fields found on the page
    """
    points = []
    parsed = urllib.parse.urlparse(base_url)
    qs     = urllib.parse.parse_qs(parsed.query)

    # URL query params — keep original URL so the parameter context is preserved
    for param in qs:
        points.append({
            "type":   "url",
            "url":    base_url,
            "method": "GET",
            "param":  param,
            "data":   {k: v[0] for k, v in qs.items()},  # single value per param
        })

    # HTML forms
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
    """Lightweight regex-based form parser."""
    forms       = []
    parsed_base = urllib.parse.urlparse(base_url)
    form_blocks = re.findall(r"<form[^>]*>(.*?)</form>", html, re.IGNORECASE | re.DOTALL)
    form_tags   = re.findall(r"<form([^>]*)>",           html, re.IGNORECASE)

    for tag_attrs, body in zip(form_tags, form_blocks):
        action_m = re.search(r'action=["\']([^"\']*)["\']', tag_attrs, re.IGNORECASE)
        method_m = re.search(r'method=["\']([^"\']*)["\']', tag_attrs, re.IGNORECASE)

        action = action_m.group(1) if action_m else base_url
        method = method_m.group(1).upper() if method_m else "GET"

        if action and not action.startswith("http"):
            action = urllib.parse.urljoin(
                f"{parsed_base.scheme}://{parsed_base.netloc}", action
            )

        fields = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE)
        ta     = re.findall(r'<textarea[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE)
        all_fields = list(set(fields + ta))
        if all_fields:
            forms.append({"action": action, "method": method, "fields": all_fields})

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


def _measure_baseline_rtt(session: requests.Session, point: dict,
                           timeout: int, samples: int = 3) -> float:
    """FIX-F5: Measure average response time with a benign payload."""
    times = []
    for _ in range(samples):
        try:
            t0 = time.time()
            _inject(session, point, "baseline_test_ja4", timeout)
            times.append(time.time() - t0)
        except Exception:
            times.append(0.5)
    return sum(times) / len(times) if times else 0.5


# ── Print Helpers ─────────────────────────────────────────────────────────────

def _print_headers_table(headers: list[dict]) -> None:
    table = Table(title="Security Headers", box=box.ROUNDED, border_style="cyan")
    table.add_column("Header",       style="bold white", width=32)
    table.add_column("Status",       style="bold",       width=14, justify="center")
    table.add_column("Value / Note", style="dim",        width=50)
    color_map = {"PRESENT": "green", "MISSING": "red", "MISCONFIGURED": "yellow"}
    for h in headers:
        color = color_map.get(h["status"], "white")
        value = h["value"] if h["value"] else h["note"]
        table.add_row(h["header"], f"[{color}]{h['status']}[/{color}]", value[:50])
    console.print(table)


def _print_ssl_table(info: dict) -> None:
    table = Table(title="SSL Certificate", box=box.ROUNDED, border_style="cyan")
    table.add_column("Field", style="bold white", width=16)
    table.add_column("Value", style="white")
    days = info["days_left"]
    if info.get("expired"):
        days_str = f"[magenta]EXPIRED ({abs(days)} days ago)[/magenta]"
    elif info.get("warning"):
        days_str = f"[yellow]{days} days (expiring soon!)[/yellow]"
    else:
        days_str = f"[green]{days} days[/green]"
    table.add_row("Subject",   info.get("subject", "N/A"))
    table.add_row("Issuer",    info.get("issuer",  "N/A"))
    table.add_row("Expires",   info.get("expires", "N/A"))
    table.add_row("Days Left", days_str)
    table.add_row("Valid",     "[green]Yes[/green]" if info.get("valid") else "[red]No[/red]")
    console.print(table)


def _print_ports_table(ports: list[tuple]) -> None:
    table = Table(title="Port Scan", box=box.ROUNDED, border_style="cyan")
    table.add_column("Port",    style="bold white", width=8)
    table.add_column("Service", style="white",      width=14)
    table.add_column("Status",  style="bold",       width=10, justify="center")
    for port, name, is_open in ports:
        table.add_row(str(port), name,
                      "[green]OPEN[/green]" if is_open else "[dim]closed[/dim]")
    console.print(table)


def _print_subdomains_table(subdomains: list[tuple]) -> None:
    if not subdomains:
        console.print("  [dim]No subdomains resolved.[/dim]")
        return
    table = Table(title=f"Subdomains Found ({len(subdomains)})",
                  box=box.ROUNDED, border_style="cyan")
    table.add_column("Subdomain",  style="bold cyan")
    table.add_column("IP Address", style="white")
    for fqdn, ip in subdomains:
        table.add_row(fqdn, ip)
    console.print(table)


def _print_dirs_table(dirs: list[tuple], origin: str) -> None:
    if not dirs:
        console.print("  [dim]No interesting paths found.[/dim]")
        return
    table = Table(title=f"Paths Found ({len(dirs)})", box=box.ROUNDED, border_style="cyan")
    table.add_column("Path",   style="bold white")
    table.add_column("Status", style="bold", justify="center")
    table.add_column("Risk",   style="bold", justify="center")
    sc_map = {200: "green", 301: "yellow", 302: "yellow", 403: "dim"}
    rc_map = {"High": "red", "Info": "cyan"}
    for path, status, risk in sorted(dirs, key=lambda x: (x[2] != "High", x[1])):
        sc = sc_map.get(status, "white")
        rc = rc_map.get(risk,   "white")
        table.add_row(
            origin + path,
            f"[{sc}]{status}[/{sc}]",
            f"[{rc}]{risk}[/{rc}]",
        )
    console.print(table)


def _print_xss_table(vulns: list[tuple]) -> None:
    if not vulns:
        console.print("  [green]No reflected XSS found.[/green]")
        return
    table = Table(title=f"XSS Vulnerabilities ({len(vulns)})",
                  box=box.ROUNDED, border_style="red")
    table.add_column("Parameter", style="bold red")
    table.add_column("Payload",   style="yellow")
    table.add_column("URL",       style="dim")
    for param, payload, url in vulns:
        table.add_row(param, payload[:60], url[:60])
    console.print(table)


def _print_sqli_table(vulns: list[tuple]) -> None:
    if not vulns:
        console.print("  [green]No SQL injection found.[/green]")
        return
    table = Table(title=f"SQL Injection ({len(vulns)})",
                  box=box.ROUNDED, border_style="magenta")
    table.add_column("Parameter", style="bold magenta")
    table.add_column("Type",      style="bold", justify="center")
    table.add_column("Payload",   style="yellow")
    table.add_column("URL",       style="dim")
    for param, payload, kind, url in vulns:
        kind_str = ("[magenta]Time-Based Blind[/magenta]" if kind == "time"
                    else "[red]Error-Based[/red]")
        table.add_row(param, kind_str, payload[:50], url[:50])
    console.print(table)


# ── Entry Point ───────────────────────────────────────────────────────────────

def run_scanner() -> None:
    """Interactive entry point called from main.py."""
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
        "  [cyan]Bypass robots.txt restrictions?[/cyan]", default=False
    )

    scanner = ReconScanner(target, respect_robots=not no_robots)
    results = scanner.run_full_scan(no_robots=no_robots)

    critical = [f for f in results["findings"] if f["risk"] in ("Critical", "High")]
    if critical:
        console.print(f"\n  [bold red]{len(critical)} High/Critical findings.[/bold red]")
        if Confirm.ask(
            "  [cyan]Generate a bug bounty report for these findings?[/cyan]",
            default=True
        ):
            from report_generator import run_report_generator
            sqli = any(f["type"] == "SQL Injection"  for f in critical)
            xss  = any(f["type"] == "XSS Reflected"  for f in critical)
            sslx = any(f["type"] == "SSL Expired"     for f in critical)
            if sqli:
                score, sev, vuln = 9.8, "Critical", "SQLI"
            elif xss:
                score, sev, vuln = 8.8, "High",     "XSS"
            elif sslx:
                score, sev, vuln = 7.5, "High",     "AUTH_BYPASS"
            else:
                score, sev, vuln = 7.0, "High",     "AUTH_BYPASS"
            run_report_generator(prefill_score=score, prefill_severity=sev,
                                 prefill_vuln=vuln)
