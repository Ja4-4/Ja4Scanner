"""
Bug Bounty Report Generator
Produces a professional Markdown report and saves it to disk.
"""

import os
from datetime import date
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

from cvss_calculator import interactive_cvss, build_vector_string, score_to_severity
from poc_suggester import select_vuln_type, get_poc_steps_text, POC_DATABASE

console = Console()

REMEDIATION_MAP = {
    "XSS":          "Encode all user-controlled output server-side. Implement a strict Content-Security-Policy. Avoid using innerHTML.",
    "SQLI":         "Use parameterized queries (prepared statements) for all database interactions. Never concatenate user input into SQL strings.",
    "IDOR":         "Enforce server-side authorization checks on every resource access. Do not rely on obscuring IDs.",
    "RCE":          "Avoid passing user-controlled data to shell commands. Use language-native APIs. Apply least-privilege principles.",
    "SSRF":         "Whitelist allowed outbound destinations. Block RFC-1918 and metadata IP ranges. Use a SSRF-safe HTTP client library.",
    "LFI":          "Use an allowlist of permitted file paths. Never pass user input directly to file-inclusion functions.",
    "OPEN_REDIRECT":"Whitelist allowed redirect URLs. Validate the destination on the server side before redirecting.",
    "XXE":          "Disable external entity processing in the XML parser. Prefer JSON APIs where possible.",
    "CSRF":         "Implement CSRF tokens on all state-changing requests. Use SameSite=Strict cookies. Validate Origin/Referer headers.",
    "AUTH_BYPASS":  "Enforce authentication and authorization on every protected route. Use vetted session management libraries.",
}


def _ask(prompt: str, default: str = "") -> str:
    val = Prompt.ask(f"  [cyan]{prompt}[/cyan]", default=default)
    return val.strip()


def collect_report_data(
    prefill_score: float = None,
    prefill_severity: str = None,
    prefill_metrics: dict = None,
    prefill_vuln: str = None,
) -> dict:
    """Interactively collect all fields needed for a bug bounty report."""
    console.print(Panel(
        "[bold cyan]Bug Bounty Report Generator[/bold cyan]\n"
        "[dim]Fill in the details below. Press Enter to accept defaults.[/dim]",
        border_style="cyan"
    ))

    data = {}

    data["title"] = _ask("Vulnerability Title", "Untitled Vulnerability")
    data["researcher"] = _ask("Researcher Name / Handle", "Anonymous")
    data["program"] = _ask("Bug Bounty Program / Target", "Target Program")
    data["date"] = str(date.today())

    # Vuln type
    if prefill_vuln:
        console.print(f"  [dim]Vuln type pre-selected: {prefill_vuln}[/dim]")
        data["vuln_type"] = prefill_vuln
    else:
        console.print("\n  [cyan]Select Vulnerability Type[/cyan]")
        data["vuln_type"] = select_vuln_type()

    vuln_info = POC_DATABASE.get(data["vuln_type"], {})
    data["vuln_full_name"] = vuln_info.get("full_name", data["vuln_type"])

    data["affected_url"] = _ask("Affected URL / Endpoint", "https://target.com/vulnerable-endpoint")
    data["description"] = _ask(
        "Description (brief overview of the issue)",
        f"A {data['vuln_full_name']} vulnerability was found at the specified endpoint."
    )
    data["impact"] = _ask(
        "Impact (what an attacker can achieve)",
        "An attacker could exploit this to compromise user data or server integrity."
    )

    # CVSS
    if prefill_score is not None:
        data["cvss_score"] = prefill_score
        data["severity"] = prefill_severity
        data["cvss_vector"] = build_vector_string(prefill_metrics) if prefill_metrics else "N/A"
        console.print(f"  [dim]CVSS Score pre-filled: {prefill_score} ({prefill_severity})[/dim]")
    else:
        run_cvss = Confirm.ask("\n  [cyan]Run CVSS calculator now?[/cyan]", default=True)
        if run_cvss:
            metrics, score, severity = interactive_cvss()
            data["cvss_score"] = score
            data["severity"] = severity
            data["cvss_vector"] = build_vector_string(metrics)
        else:
            try:
                score_input = float(_ask("Enter CVSS score manually (0.0–10.0)", "5.0"))
                score_input = max(0.0, min(10.0, score_input))
            except ValueError:
                score_input = 5.0
            data["cvss_score"] = score_input
            data["severity"] = score_to_severity(score_input)
            data["cvss_vector"] = _ask("CVSS Vector string (optional)", "N/A")

    data["steps_to_reproduce"] = _ask(
        "Steps to Reproduce (brief — PoC suggestions will be auto-appended)",
        "1. Navigate to the affected URL.\n2. Observe the vulnerable parameter.\n3. Inject the payload below."
    )

    data["remediation"] = _ask(
        "Remediation Recommendation",
        REMEDIATION_MAP.get(data["vuln_type"], "Apply secure coding best practices.")
    )

    data["poc_text"] = get_poc_steps_text(data["vuln_type"])

    return data


def build_markdown(data: dict) -> str:
    severity_badge = {
        "None":     "![None](https://img.shields.io/badge/Severity-None-lightgrey)",
        "Low":      "![Low](https://img.shields.io/badge/Severity-Low-blue)",
        "Medium":   "![Medium](https://img.shields.io/badge/Severity-Medium-yellow)",
        "High":     "![High](https://img.shields.io/badge/Severity-High-orange)",
        "Critical": "![Critical](https://img.shields.io/badge/Severity-Critical-red)",
    }.get(data["severity"], "")

    md = f"""# Bug Bounty Report: {data['title']}

{severity_badge}

| Field            | Value                         |
|------------------|-------------------------------|
| **Researcher**   | {data['researcher']}          |
| **Program**      | {data['program']}             |
| **Date**         | {data['date']}                |
| **Vuln Type**    | {data['vuln_full_name']}      |
| **CVSS Score**   | {data['cvss_score']:.1f} / 10.0 ({data['severity']}) |
| **CVSS Vector**  | `{data['cvss_vector']}`       |

---

## 1. Vulnerability Summary

**Type:** {data['vuln_full_name']}
**Affected Endpoint:** `{data['affected_url']}`

{data['description']}

---

## 2. Impact

{data['impact']}

---

## 3. CVSS v3.1 Score

| Metric  | Value |
|---------|-------|
| Score   | **{data['cvss_score']:.1f}** |
| Severity | **{data['severity']}** |
| Vector  | `{data['cvss_vector']}` |

---

## 4. Steps to Reproduce

{data['steps_to_reproduce']}

---

## 5. Proof of Concept (PoC)

{data['poc_text']}

---

## 6. Remediation

{data['remediation']}

---

## 7. References

- [OWASP — {data['vuln_full_name']}](https://owasp.org/www-community/attacks/)
- [FIRST CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [HackerOne Disclosure Guidelines](https://www.hackerone.com/disclosure-guidelines)

---

*Report generated by [Ja4Scanner](https://github.com/ja4scanner) on {data['date']}*
"""
    return md


def save_report(md_content: str, output_dir: str = ".") -> str:
    filename = f"report_{date.today().strftime('%Y-%m-%d')}.md"
    filepath = os.path.join(output_dir, filename)

    # Avoid overwriting — append suffix if file exists
    counter = 1
    base = filepath
    while os.path.exists(filepath):
        name, ext = os.path.splitext(base)
        filepath = f"{name}_{counter}{ext}"
        counter += 1

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(md_content)

    return filepath


def run_report_generator(
    prefill_score: float = None,
    prefill_severity: str = None,
    prefill_metrics: dict = None,
    prefill_vuln: str = None,
) -> str:
    """Full report generation flow. Returns path to saved report."""
    data = collect_report_data(
        prefill_score=prefill_score,
        prefill_severity=prefill_severity,
        prefill_metrics=prefill_metrics,
        prefill_vuln=prefill_vuln,
    )
    md = build_markdown(data)

    # Show preview
    preview_lines = md.splitlines()[:30]
    console.print(Panel(
        "\n".join(preview_lines) + "\n...",
        title="[bold]Report Preview (first 30 lines)[/bold]",
        border_style="dim"
    ))

    save = Confirm.ask("\n  [cyan]Save report to Markdown file?[/cyan]", default=True)
    if save:
        path = save_report(md)
        console.print(f"\n  [bold green]Report saved:[/bold green] [white]{path}[/white]")
        return path
    else:
        console.print("[yellow]  Report not saved.[/yellow]")
        return ""
