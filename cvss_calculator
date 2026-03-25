"""
CVSS v3.1 Base Score Calculator
Reference: https://www.first.org/cvss/v3.1/specification-document
"""

import math
from colorama import Fore, Style, init

init(autoreset=True, strip=False)  # strip=False ensures ANSI codes work on Linux/macOS

# Metric weights
AV_WEIGHTS = {
    "N": ("Network",   0.85),
    "A": ("Adjacent",  0.62),
    "L": ("Local",     0.55),
    "P": ("Physical",  0.20),
}

AC_WEIGHTS = {
    "L": ("Low",  0.77),
    "H": ("High", 0.44),
}

PR_WEIGHTS_UNCHANGED = {
    "N": ("None", 0.85),
    "L": ("Low",  0.62),
    "H": ("High", 0.27),
}

PR_WEIGHTS_CHANGED = {
    "N": ("None", 0.85),
    "L": ("Low",  0.68),
    "H": ("High", 0.50),
}

UI_WEIGHTS = {
    "N": ("None",     0.85),
    "R": ("Required", 0.62),
}

CIA_WEIGHTS = {
    "N": ("None", 0.00),
    "L": ("Low",  0.22),
    "H": ("High", 0.56),
}

SCOPE_OPTIONS = {
    "U": "Unchanged",
    "C": "Changed",
}


def _roundup(value: float) -> float:
    """CVSS 3.1 Roundup function: rounds up to 1 decimal place."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (math.floor(int_input / 10000) + 1) / 10.0


def calculate_cvss(metrics: dict) -> tuple[float, str]:
    """
    Calculate CVSS v3.1 Base Score from a metrics dict.
    Returns (score, severity_label).
    """
    scope = metrics["S"]

    av = AV_WEIGHTS[metrics["AV"]][1]
    ac = AC_WEIGHTS[metrics["AC"]][1]
    pr_table = PR_WEIGHTS_CHANGED if scope == "C" else PR_WEIGHTS_UNCHANGED
    pr = pr_table[metrics["PR"]][1]
    ui = UI_WEIGHTS[metrics["UI"]][1]

    conf = CIA_WEIGHTS[metrics["C"]][1]
    integ = CIA_WEIGHTS[metrics["I"]][1]
    avail = CIA_WEIGHTS[metrics["A"]][1]

    isc_base = 1 - (1 - conf) * (1 - integ) * (1 - avail)

    if isc_base == 0:
        return 0.0, "None"

    if scope == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    if scope == "U":
        base_score = _roundup(min(impact + exploitability, 10))
    else:
        base_score = _roundup(min(1.08 * (impact + exploitability), 10))

    severity = score_to_severity(base_score)
    return base_score, severity


def score_to_severity(score: float) -> str:
    if score == 0.0:
        return "None"
    elif score <= 3.9:
        return "Low"
    elif score <= 6.9:
        return "Medium"
    elif score <= 8.9:
        return "High"
    else:
        return "Critical"


def severity_color(severity: str) -> str:
    colors = {
        "None":     Fore.WHITE,
        "Low":      Fore.CYAN,
        "Medium":   Fore.YELLOW,
        "High":     Fore.RED,
        "Critical": Fore.MAGENTA,
    }
    return colors.get(severity, Fore.WHITE)


def _prompt_choice(prompt: str, options: dict) -> str:
    """Display numbered options and return the chosen key."""
    print(f"\n{Fore.CYAN}{prompt}{Style.RESET_ALL}")
    keys = list(options.keys())
    for i, key in enumerate(keys, 1):
        label = options[key] if isinstance(options[key], str) else options[key][0]
        print(f"  {Fore.WHITE}[{i}]{Style.RESET_ALL} {label}  ({key})")
    while True:
        choice = input(f"{Fore.GREEN}  > {Style.RESET_ALL}").strip()
        # Accept number or key letter
        if choice.isdigit() and 1 <= int(choice) <= len(keys):
            return keys[int(choice) - 1]
        if choice.upper() in keys:
            return choice.upper()
        print(f"{Fore.RED}  Invalid choice. Try again.{Style.RESET_ALL}")


def interactive_cvss() -> tuple[dict, float, str]:
    """Walk user through all CVSS metrics interactively. Returns (metrics, score, severity)."""
    from rich.console import Console
    from rich.panel import Panel
    console = Console()

    console.print(Panel(
        "[bold cyan]CVSS v3.1 Base Score Calculator[/bold cyan]\n"
        "[dim]Answer each metric to compute your vulnerability score[/dim]",
        border_style="cyan"
    ))

    metrics = {}
    metrics["AV"] = _prompt_choice("Attack Vector (AV)", AV_WEIGHTS)
    metrics["AC"] = _prompt_choice("Attack Complexity (AC)", AC_WEIGHTS)
    metrics["S"]  = _prompt_choice("Scope (S)", SCOPE_OPTIONS)
    metrics["PR"] = _prompt_choice("Privileges Required (PR)",
                                   PR_WEIGHTS_CHANGED if metrics["S"] == "C" else PR_WEIGHTS_UNCHANGED)
    metrics["UI"] = _prompt_choice("User Interaction (UI)", UI_WEIGHTS)
    metrics["C"]  = _prompt_choice("Confidentiality Impact (C)", CIA_WEIGHTS)
    metrics["I"]  = _prompt_choice("Integrity Impact (I)", CIA_WEIGHTS)
    metrics["A"]  = _prompt_choice("Availability Impact (A)", CIA_WEIGHTS)

    score, severity = calculate_cvss(metrics)

    color = severity_color(severity)
    vector = build_vector_string(metrics)

    console.print(f"\n[bold]CVSS Vector:[/bold] [dim]{vector}[/dim]")
    console.print(f"[bold]Base Score :[/bold] "
                  f"{color}{score:.1f}{Style.RESET_ALL}  "
                  f"{color}[{severity}]{Style.RESET_ALL}")

    return metrics, score, severity


def build_vector_string(metrics: dict) -> str:
    return (
        f"CVSS:3.1/AV:{metrics['AV']}/AC:{metrics['AC']}/PR:{metrics['PR']}"
        f"/UI:{metrics['UI']}/S:{metrics['S']}/C:{metrics['C']}/I:{metrics['I']}/A:{metrics['A']}"
    )
