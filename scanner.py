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


# ── WebCrawler ────────────────────────────────────────────────────────────────

class WebCrawler:
    """
    BFS web crawler that discovers injection points across an entire site.

    Collects:
      - URL query parameters  (?key=value)
      - HTML form fields      (<form action method input>)

    Returns a deduplicated list of injection-point dicts compatible with
    _inject() — the same format used by XSS and SQLi scanners.
    """

    MAX_DEPTH  = 3
    MAX_PAGES  = 50
    MAX_WORKERS = 5

    IGNORE_EXT = {
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp",
        ".css", ".js", ".mjs",
        ".pdf", ".zip", ".tar", ".gz", ".rar",
        ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot",
        ".mp4", ".mp3", ".avi", ".mov", ".wav",
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".xml",
    }

    def __init__(self, base_url: str, session: requests.Session, timeout: int = 5):
        self.base_url = base_url
        self.origin   = _origin(base_url)
        self.domain   = _extract_domain(base_url)
        self.session  = session
        self.timeout  = timeout

        self._visited:    set  = set()
        self._lock               = __import__("threading").Lock()
        self.pages_crawled: int = 0

        # Collected data
        self.crawled_urls: list[str]  = []
        self.all_forms:    list[dict] = []   # {action, method, fields, source_page}
        self.all_url_params: list[dict] = [] # {url, params{}}

    # ── Public entry point ────────────────────────────────────────────────────

    def crawl(self) -> list[dict]:
        """
        Crawl the site BFS up to MAX_DEPTH / MAX_PAGES.
        Returns deduplicated injection-point list for XSS/SQLi scanners.
        """
        console.print("\n[bold cyan][pre-scan] Web Crawler starting...[/bold cyan]")
        console.print(
            f"  [dim]Max pages: {self.MAX_PAGES}  |  "
            f"Max depth: {self.MAX_DEPTH}  |  "
            f"Workers: {self.MAX_WORKERS}[/dim]"
        )

        # BFS queue: list of (url, depth)
        queue:  list[tuple[str, int]] = [(self.base_url, 0)]
        self._mark_visited(self.base_url)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total} pages"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as pg:
            task = pg.add_task("Crawling...", total=self.MAX_PAGES)

            with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as ex:
                while queue and self.pages_crawled < self.MAX_PAGES:
                    # Take a batch of up to MAX_WORKERS URLs from the queue
                    batch, queue = (
                        queue[:self.MAX_WORKERS],
                        queue[self.MAX_WORKERS:],
                    )

                    futures = {
                        ex.submit(self._fetch_page, url, depth): (url, depth)
                        for url, depth in batch
                        if self.pages_crawled < self.MAX_PAGES
                    }

                    for f in as_completed(futures):
                        result = f.result()
                        if result is None:
                            continue

                        url, depth, links, forms, url_params = result

                        self.pages_crawled += 1
                        self.crawled_urls.append(url)

                        # Store forms and URL params
                        self.all_forms.extend(forms)
                        self.all_url_params.extend(url_params)

                        pg.update(task, description=f"Crawling: {url[:60]}",
                                  completed=self.pages_crawled)

                        # Enqueue new internal links at next depth
                        if depth < self.MAX_DEPTH:
                            for link in links:
                                if (self.pages_crawled + len(queue) < self.MAX_PAGES
                                        and not self._is_visited(link)):
                                    self._mark_visited(link)
                                    queue.append((link, depth + 1))

        console.print(
            f"  Crawled [green]{self.pages_crawled}[/green] pages  |  "
            f"Forms found [yellow]{len(self.all_forms)}[/yellow]  |  "
            f"URL params [yellow]{len(self.all_url_params)}[/yellow]"
        )

        return self._build_injection_points()

    # ── Per-page fetch ────────────────────────────────────────────────────────

    def _fetch_page(
        self, url: str, depth: int
    ) -> Optional[tuple[str, int, list, list, list]]:
        """
        Fetch one page and extract links, forms, URL params.
        Returns (url, depth, links, forms, url_params) or None on error.
        """
        try:
            r = self.session.get(
                url, timeout=self.timeout, verify=False,
                allow_redirects=True,
            )
            if r.status_code >= 400:
                return None
            ct = r.headers.get("Content-Type", "")
            if "text/html" not in ct and "text/plain" not in ct:
                return None

            html       = r.text
            links      = self._extract_links(html, url)
            forms      = self._extract_forms(html, url)
            url_params = self._extract_url_params(url)
            return url, depth, links, forms, url_params

        except Exception:
            return None

    # ── Link extraction ───────────────────────────────────────────────────────

    def _extract_links(self, html: str, current_url: str) -> list[str]:
        """Return internal links found on the page, normalised and filtered."""
        raw_hrefs = re.findall(r'<a[^>]+href=["\']([^"\'#][^"\']*)["\']',
                               html, re.IGNORECASE)
        links = []
        for href in raw_hrefs:
            href = href.strip()
            if not href or href.startswith(("mailto:", "tel:", "javascript:")):
                continue

            # Resolve relative URLs
            abs_url = urllib.parse.urljoin(current_url, href)

            # Strip fragment
            abs_url = abs_url.split("#")[0].rstrip("/") or abs_url

            # Internal only
            parsed = urllib.parse.urlparse(abs_url)
            if parsed.hostname != self.domain:
                continue

            # Ignore unwanted extensions
            path = parsed.path.lower()
            if any(path.endswith(ext) for ext in self.IGNORE_EXT):
                continue

            links.append(abs_url)

        return list(dict.fromkeys(links))  # deduplicate, preserve order

    # ── Form extraction ───────────────────────────────────────────────────────

    def _extract_forms(self, html: str, page_url: str) -> list[dict]:
        """Extract forms from HTML, return list of form dicts."""
        forms = _parse_forms(html, page_url)   # reuse existing helper
        # Attach source_page to each
        for f in forms:
            f["source_page"] = page_url
        return forms

    # ── URL param extraction ──────────────────────────────────────────────────

    def _extract_url_params(self, url: str) -> list[dict]:
        """Return list of {url, params} dicts for each URL query string."""
        parsed = urllib.parse.urlparse(url)
        qs     = urllib.parse.parse_qs(parsed.query)
        if not qs:
            return []
        return [{"url": url, "params": {k: v[0] for k, v in qs.items()}}]

    # ── Visited tracking (thread-safe) ────────────────────────────────────────

    def _mark_visited(self, url: str) -> None:
        # Normalise: strip trailing slash and fragment
        key = url.split("#")[0].rstrip("/")
        with self._lock:
            self._visited.add(key)

    def _is_visited(self, url: str) -> bool:
        key = url.split("#")[0].rstrip("/")
        with self._lock:
            return key in self._visited

    # ── Build injection point list ────────────────────────────────────────────

    def _build_injection_points(self) -> list[dict]:
        """
        Convert collected forms + URL params into the injection-point dict
        format expected by _inject() and the XSS/SQLi scanners.

        Each point:  {type, url, method, param, data, source_page}
        """
        points: list[dict] = []
        seen:   set        = set()

        # URL parameters
        for entry in self.all_url_params:
            url    = entry["url"]
            params = entry["params"]
            for param in params:
                key = ("url", url, param)
                if key in seen:
                    continue
                seen.add(key)
                points.append({
                    "type":        "url",
                    "url":         url,
                    "method":      "GET",
                    "param":       param,
                    "data":        dict(params),
                    "source_page": url,
                })

        # Form fields
        for form in self.all_forms:
            action      = form["action"]
            method      = form["method"]
            source_page = form.get("source_page", action)
            for field in form["fields"]:
                key = ("form", action, field)
                if key in seen:
                    continue
                seen.add(key)
                points.append({
                    "type":        "form",
                    "url":         action,
                    "method":      method,
                    "param":       field,
                    "data":        {f: "test" for f in form["fields"]},
                    "source_page": source_page,
                })

        return points

    # ── Summary table ─────────────────────────────────────────────────────────

    def print_crawl_summary(self) -> None:
        if not self.crawled_urls:
            return
        table = Table(
            title=f"Crawled Pages ({len(self.crawled_urls)})",
            box=box.ROUNDED, border_style="cyan",
        )
        table.add_column("Page URL", style="dim", overflow="fold")
        for url in self.crawled_urls[:30]:   # cap display at 30
            table.add_row(url)
        if len(self.crawled_urls) > 30:
            table.add_row(f"[dim]... and {len(self.crawled_urls)-30} more[/dim]")
        console.print(table)


# ── Form parser ───────────────────────────────────────────────────────────────

def _parse_forms(html: str, page_url: str) -> list[dict]:
    """
    Extract all <form> elements from HTML.
    Returns list of {action, method, fields} dicts.
    """
    forms   = []
    # Find every <form ...> ... </form> block
    for form_html in re.findall(r'<form[^>]*>.*?</form>', html,
                                re.IGNORECASE | re.DOTALL):
        # action
        action_m = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        action   = action_m.group(1).strip() if action_m else page_url
        action   = urllib.parse.urljoin(page_url, action)

        # method
        method_m = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        method   = (method_m.group(1).upper() if method_m else "GET")

        # input / textarea / select names
        fields = re.findall(
            r'<(?:input|textarea|select)[^>]+name=["\']([^"\']+)["\']',
            form_html, re.IGNORECASE,
        )
        # filter out submit / button / hidden inputs (keep text, search, password, etc.)
        skip_types = {"submit", "button", "image", "reset", "file", "checkbox", "radio"}
        final_fields = []
        for name in fields:
            type_m = re.search(
                r'name=["\']' + re.escape(name) + r'["\'][^>]*type=["\']([^"\']+)["\']|'
                r'type=["\']([^"\']+)["\'][^>]*name=["\']' + re.escape(name) + r'["\']',
                form_html, re.IGNORECASE,
            )
            if type_m:
                t = (type_m.group(1) or type_m.group(2) or "text").lower()
                if t in skip_types:
                    continue
            final_fields.append(name)

        if final_fields:
            forms.append({"action": action, "method": method, "fields": final_fields})
    return forms


# ── Injection helper ──────────────────────────────────────────────────────────

def _inject(session: requests.Session, point: dict,
            payload: str, timeout: int) -> Optional[requests.Response]:
    """
    Send one injection request for the given injection point.
    Supports both URL-parameter (GET) and form (GET/POST) points.
    """
    url    = point["url"]
    method = point.get("method", "GET").upper()
    param  = point["param"]
    data   = dict(point.get("data", {}))
    data[param] = payload

    try:
        if method == "POST":
            return session.post(url, data=data, timeout=timeout,
                                verify=False, allow_redirects=True)
        else:
            parsed = urllib.parse.urlparse(url)
            qs     = urllib.parse.parse_qs(parsed.query)
            qs[param] = [payload]
            new_qs  = urllib.parse.urlencode(qs, doseq=True)
            new_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
            return session.get(new_url, timeout=timeout,
                               verify=False, allow_redirects=True)
    except Exception:
        return None


# ── Single-page injection-point collector (fallback) ─────────────────────────

def _collect_injection_points(base_url: str, session: requests.Session,
                               timeout: int) -> list[dict]:
    """
    Fallback: collect injection points from just the homepage
    (used when the crawler is not available).
    """
    points: list[dict] = []
    try:
        r = session.get(base_url, timeout=timeout, verify=False, allow_redirects=True)
    except Exception:
        return points

    html = r.text

    # URL parameters on the landing URL
    parsed = urllib.parse.urlparse(base_url)
    qs     = urllib.parse.parse_qs(parsed.query)
    for param, values in qs.items():
        points.append({
            "type":        "url",
            "url":         base_url,
            "method":      "GET",
            "param":       param,
            "data":        {param: values[0]},
            "source_page": base_url,
        })

    # Forms on the page
    for form in _parse_forms(html, base_url):
        for field in form["fields"]:
            points.append({
                "type":        "form",
                "url":         form["action"],
                "method":      form["method"],
                "param":       field,
                "data":        {f: "test" for f in form["fields"]},
                "source_page": base_url,
            })

    return points


# ── Print helpers ─────────────────────────────────────────────────────────────

def _print_headers_table(headers: list) -> None:
    table = Table(title="Security Headers", box=box.ROUNDED, border_style="cyan")
    table.add_column("Header",      style="bold white", overflow="fold")
    table.add_column("Status",      justify="center")
    table.add_column("Risk",        justify="center")
    table.add_column("Value / Reason", style="dim", overflow="fold")
    for h in headers:
        status_color = "green" if h["status"] == "PRESENT" else "red"
        risk_color   = RISK_COLOR.get(h["risk"], "white")
        table.add_row(
            h["header"],
            f"[{status_color}]{h['status']}[/{status_color}]",
            f"[{risk_color}]{h['risk']}[/{risk_color}]",
            h.get("reason") or h.get("value", ""),
        )
    console.print(table)


def _print_ssl_table(info: dict) -> None:
    if not info or info.get("skipped"):
        return
    table = Table(title="SSL Certificate", box=box.ROUNDED, border_style="cyan")
    table.add_column("Field", style="bold white")
    table.add_column("Value", overflow="fold")
    if not info.get("valid", True) and "error" in info:
        table.add_row("Status", "[red]INVALID[/red]")
        table.add_row("Error",  info["error"])
    else:
        days  = info.get("days_left", "?")
        dcolor = "red" if isinstance(days, int) and days < 0 else (
                  "yellow" if isinstance(days, int) and days < 30 else "green")
        table.add_row("Subject",      info.get("subject", "?"))
        table.add_row("Issuer",       info.get("issuer",  "?"))
        table.add_row("Expires",      info.get("expires", "?"))
        table.add_row("Days Left",    f"[{dcolor}]{days}[/{dcolor}]")
        table.add_row("TLS Version",  info.get("tls_version", "?"))
        table.add_row("Self-Signed",  "[red]YES[/red]" if info.get("is_self_signed") else "[green]No[/green]")
        table.add_row("Domain Match", "[green]Yes[/green]" if info.get("domain_match") else "[red]NO[/red]")
        if info.get("weak_tls"):
            table.add_row("Weak TLS",    "[red]" + ", ".join(info["weak_tls"]) + "[/red]")
    console.print(table)


def _print_ports_table(ports: list) -> None:
    table = Table(title="Port Scan", box=box.ROUNDED, border_style="cyan")
    table.add_column("Port",    justify="right")
    table.add_column("Service", style="bold white")
    table.add_column("Status",  justify="center")
    table.add_column("Risk",    justify="center")
    table.add_column("Context", style="dim", overflow="fold")
    for port, service, is_open, risk, context, banner in ports:
        status_str  = "[green]OPEN[/green]" if is_open else "[dim]closed[/dim]"
        risk_color  = RISK_COLOR.get(risk, "white")
        detail      = context + (f" | Banner: {banner}" if banner else "")
        table.add_row(str(port), service, status_str,
                      f"[{risk_color}]{risk}[/{risk_color}]", detail)
    console.print(table)


def _print_subdomains_table(subdomains: list) -> None:
    if not subdomains:
        console.print("  [dim]No subdomains found.[/dim]")
        return
    table = Table(title=f"Subdomains ({len(subdomains)})", box=box.ROUNDED, border_style="cyan")
    table.add_column("FQDN",        style="bold white", overflow="fold")
    table.add_column("IP",          style="dim")
    table.add_column("HTTP Status", justify="center")
    table.add_column("Live",        justify="center")
    table.add_column("Takeover?",   justify="center")
    for s in subdomains:
        live_str     = "[green]Yes[/green]" if s.get("is_live") else "[dim]No[/dim]"
        takeover_str = f"[red]{s['takeover_service']}[/red]" if s.get("takeover_service") else "[dim]-[/dim]"
        table.add_row(s["fqdn"], s.get("ip","?"),
                      str(s.get("http_status","?")), live_str, takeover_str)
    console.print(table)


def _print_dirs_table(dirs: list, origin: str) -> None:
    if not dirs:
        console.print("  [dim]No interesting paths found.[/dim]")
        return
    table = Table(title=f"Paths Found ({len(dirs)})", box=box.ROUNDED, border_style="cyan")
    table.add_column("Path",       style="bold white", overflow="fold")
    table.add_column("Status",     justify="center")
    table.add_column("Size",       justify="right", style="dim")
    table.add_column("Risk",       justify="center")
    table.add_column("Confidence", justify="center")
    for path, status, risk, confidence, reason, blen in dirs:
        risk_color = RISK_COLOR.get(risk, "white")
        conf_color = CONF_COLOR.get(confidence, "white")
        table.add_row(
            origin + path, str(status), f"{blen} B",
            f"[{risk_color}]{risk}[/{risk_color}]",
            f"[{conf_color}]{confidence}[/{conf_color}]",
        )
    console.print(table)


def _print_xss_table(vulnerable: list) -> None:
    if not vulnerable:
        console.print("  [green]No XSS vulnerabilities found.[/green]")
        return
    table = Table(title=f"XSS Findings ({len(vulnerable)})", box=box.ROUNDED,
                  border_style="red")
    table.add_column("Param",      style="bold red")
    table.add_column("URL",        style="dim", overflow="fold")
    table.add_column("Confidence", justify="center")
    table.add_column("Source Page",style="dim", overflow="fold")
    for param, payload, url, conf, reason, source in vulnerable:
        conf_color = CONF_COLOR.get(conf, "white")
        table.add_row(param, url, f"[{conf_color}]{conf}[/{conf_color}]", source)
    console.print(table)


def _print_sqli_table(vulnerable: list) -> None:
    if not vulnerable:
        console.print("  [green]No SQL Injection vulnerabilities found.[/green]")
        return
    table = Table(title=f"SQLi Findings ({len(vulnerable)})", box=box.ROUNDED,
                  border_style="red")
    table.add_column("Param",      style="bold red")
    table.add_column("Method",     style="yellow")
    table.add_column("URL",        style="dim", overflow="fold")
    table.add_column("Confidence", justify="center")
    table.add_column("Source Page",style="dim", overflow="fold")
    for param, method, url, conf, reason, source in vulnerable:
        conf_color = CONF_COLOR.get(conf, "white")
        table.add_row(param, method, url, f"[{conf_color}]{conf}[/{conf_color}]", source)
    console.print(table)


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

    def scan_xss(self, points: Optional[list] = None) -> None:
        console.print("\n[bold cyan][6/7] XSS Scanner...[/bold cyan]")
        vulnerable = []

        # Use crawler-supplied points if available, else fall back to single-page
        targets = points if points else \
            _collect_injection_points(self.base_url, self.session, self.timeout)

        if not targets:
            console.print("  [dim]No injection points found for XSS testing.[/dim]")
            self.results["xss"] = []
            return

        console.print(
            f"  [dim]Testing {len(targets)} injection points "
            f"across {len({p['source_page'] for p in targets if 'source_page' in p} or {self.base_url})} pages[/dim]"
        )
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
                                source = point.get("source_page", point["url"])
                                reason = (
                                    f"Canary '{token}' reflects unencoded in response "
                                    f"({'dangerous execution context detected' if conf == 'High' else 'HTML context, structure may be stripped'})"
                                )
                                entry = (point["param"], payload, point["url"], conf, reason, source)
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

    def scan_sqli(self, points: Optional[list] = None) -> None:
        console.print("\n[bold cyan][7/7] SQL Injection Scanner...[/bold cyan]")
        vulnerable = []

        targets = points if points else \
            _collect_injection_points(self.base_url, self.session, self.timeout)
        if not targets:
            console.print("  [dim]No injection points found for SQLi testing.[/dim]")
            self.results["sqli"] = []
            return

        console.print(
            f"  [dim]Testing {len(targets)} injection points "
            f"across {len({p['source_page'] for p in targets if 'source_page' in p} or {self.base_url})} pages[/dim]"
        )

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

                source = point.get("source_page", point["url"])
                entry = (point["param"], method, point["url"], confidence, reason, source)
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
        # -- Web crawler --
        crawler = WebCrawler(self.base_url, self.session, self.timeout)
        crawl_points = crawler.crawl()
        self.results["crawl"] = {
            "pages":      crawler.pages_crawled,
            "forms":      len(crawler.all_forms),
            "url_params": len(crawler.all_url_params),
            "points":     len(crawl_points),
        }

        self.scan_xss(points=crawl_points)
        self.scan_sqli(points=crawl_points)

        # ── Final summary ─────────────────────────────────────────────────────
        findings = self.results["findings"]
        highs    = [f for f in findings if f["risk"] in ("Critical", "High")]

        console.print(Panel(
            f"[bold cyan]Scan Complete[/bold cyan]\n"
            f"[dim]Pages crawled : {crawler.pages_crawled}[/dim]\n"
            f"[dim]Injection pts : {len(crawl_points)}[/dim]\n"
            f"[dim]Total findings: {len(findings)}  "
            f"(High/Critical: {len(highs)})[/dim]",
            border_style="cyan",
        ))

        if highs:
            table = Table(title="High / Critical Findings", box=box.ROUNDED,
                          border_style="red")
            table.add_column("Type",       style="bold white")
            table.add_column("Detail",     overflow="fold")
            table.add_column("Risk",       justify="center")
            table.add_column("Confidence", justify="center")
            for f in sorted(highs,
                            key=lambda x: RISK_ORDER.index(x["risk"])):
                rc = RISK_COLOR.get(f["risk"], "white")
                cc = CONF_COLOR.get(f["confidence"], "white")
                table.add_row(
                    f["type"], f["detail"],
                    f"[{rc}]{f['risk']}[/{rc}]",
                    f"[{cc}]{f['confidence']}[/{cc}]",
                )
            console.print(table)

        return self.results


# ── Entry point ───────────────────────────────────────────────────────────────

def run_scanner() -> None:
    """Interactive entry point called from main.py."""
    console.print(Panel(
        "[bold cyan]Active Recon Scanner[/bold cyan]\n"
        "[dim]Crawls the full site, then tests every parameter for XSS and SQLi.[/dim]",
        border_style="cyan",
    ))

    target = Prompt.ask("\n  [bold cyan]Target URL[/bold cyan]").strip()
    if not target:
        console.print("[red]No target supplied. Aborting.[/red]")
        return

    no_robots = Confirm.ask("  Ignore robots.txt?", default=False)

    scanner = ReconScanner(target, respect_robots=not no_robots)
    scanner.run_full_scan(no_robots=no_robots)
