#!/usr/bin/env python3

import sys
import os

# Ensure we can import sibling modules when run from any directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from colorama import init as colorama_init
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

colorama_init(autoreset=True, strip=False)  # strip=False ensures ANSI codes work on Linux/macOS
console = Console()

BANNER = r"""
     _            _  _   ____
    | | __ _   _ | || | / ___|  ___ __ _ _ __  _ __   ___ _ __
 _  | |/ _` | | || || | \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
| |_| | (_| |_  __  _|  ___) | (_| (_| | | | | | | |  __/ |
 \___/ \__,_| |_||_||_| |____/ \___\__,_|_| |_|_| |_|\___|_|

              Author: DEV Ja4_       Telegram: tnst7
              
              
"""


def print_banner() -> None:
    console.print(Panel(
        Text(BANNER, style="bold cyan"),
        border_style="bright_cyan",
        padding=(0, 2),
    ))


def print_menu() -> None:
    table = Table(box=box.ROUNDED, border_style="cyan", show_header=False, padding=(0, 2))
    table.add_column("Key",  style="bold yellow", width=6)
    table.add_column("Option", style="white")

    table.add_row("[1]", "CVSS v3.1 Calculator")
    table.add_row("[2]", "Bug Bounty Report Generator")
    table.add_row("[3]", "PoC Suggester")
    table.add_row("[4]", "All-in-One  (CVSS → Report with auto-filled score)")
    table.add_row("[5]", "Severity Reference Chart")
    table.add_row("[Q]", "Quit")

    console.print("\n")
    console.print(table)
    console.print()


def severity_chart() -> None:
    table = Table(title="CVSS v3.1 Severity Reference", box=box.ROUNDED, border_style="cyan")
    table.add_column("Score Range", style="bold white", justify="center")
    table.add_column("Severity",    style="bold",       justify="center")
    table.add_column("Action",      style="dim")

    table.add_row("0.0",       "[white]None[/white]",     "Informational only")
    table.add_row("0.1 – 3.9", "[cyan]Low[/cyan]",        "Low priority; fix in next release cycle")
    table.add_row("4.0 – 6.9", "[yellow]Medium[/yellow]", "Moderate risk; schedule remediation soon")
    table.add_row("7.0 – 8.9", "[red]High[/red]",         "High risk; prioritize immediate fix")
    table.add_row("9.0 – 10.0","[magenta]Critical[/magenta]", "Critical; emergency patch required")

    console.print(table)


def run_cvss_only() -> tuple:
    from cvss_calculator import interactive_cvss
    metrics, score, severity = interactive_cvss()
    return metrics, score, severity


def run_report_only() -> None:
    from report_generator import run_report_generator
    run_report_generator()


def run_poc_only() -> None:
    from poc_suggester import run_poc_suggester
    run_poc_suggester()


def run_all_in_one() -> None:
    """CVSS → Report with score pre-filled, optional PoC view."""
    console.print(Panel(
        "[bold cyan]All-in-One Mode[/bold cyan]\n"
        "[dim]Step 1: Calculate CVSS Score → Step 2: Generate Report[/dim]",
        border_style="cyan"
    ))
    from cvss_calculator import interactive_cvss
    from report_generator import run_report_generator

    metrics, score, severity = interactive_cvss()

    console.print(f"\n  [bold green]CVSS Score locked in:[/bold green] {score:.1f} ({severity})")
    console.print("  [dim]Proceeding to report generation...[/dim]\n")

    run_report_generator(
        prefill_score=score,
        prefill_severity=severity,
        prefill_metrics=metrics,
    )


def main() -> None:
    print_banner()

    while True:
        print_menu()
        choice = input("  Select an option: ").strip().upper()

        if choice == "1":
            run_cvss_only()
        elif choice == "2":
            run_report_only()
        elif choice == "3":
            run_poc_only()
        elif choice == "4":
            run_all_in_one()
        elif choice == "5":
            severity_chart()
        elif choice in ("Q", "QUIT", "EXIT"):
            console.print("\n[bold cyan]  Stay safe and hack ethically. Goodbye![/bold cyan]\n")
            sys.exit(0)
        else:
            console.print("[red]  Invalid option. Choose 1–5 or Q.[/red]")

        input("\n  [Press Enter to return to menu]")


if __name__ == "__main__":
    main()
