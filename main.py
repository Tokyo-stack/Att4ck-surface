# main.py
import sys
import os
import shutil
import tempfile
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt

from attack_surface.banner import print_banner
from attack_surface.rules import RULES
from attack_surface.scanner import SurfaceScanner
from attack_surface.exporter import export_results

console = Console()

# ----------------------------
# FEATURE MAPPING
# ----------------------------
FEATURE_MAPPING = {
    "1": {
        "name": "Endpoint Discovery & Admin Portals",
        "categories": ["admin-portals"]
    },
    "2": {
        "name": "Secret Detection & Credentials",
        "categories": ["secrets", "authentication"]
    },
    "3": {
        "name": "File Upload & Download Analysis",
        "categories": ["file-uploads", "file-downloads"]
    },
    "4": {
        "name": "API & GraphQL Enumeration",
        "categories": ["api", "graphql"]
    },
    "5": {
        "name": "Security Misconfigurations",
        "categories": ["misconfig", "debug-endpoints"]
    },
    "6": {
        "name": "Parameter & XSS Mapping",
        "categories": ["xss", "user-input"]
    },
    "7": {
        "name": "Full Source Code Review (All Categories)",
        "categories": None
    }
}


# ----------------------------
# MENU UI
# ----------------------------
def display_interactive_menu():
    menu_text = (
        "[bold cyan]1.[/bold cyan] Endpoint Discovery & Admin\n"
        "[bold cyan]2.[/bold cyan] Secrets Detection\n"
        "[bold cyan]3.[/bold cyan] File Analysis\n"
        "[bold cyan]4.[/bold cyan] API & GraphQL\n"
        "[bold cyan]5.[/bold cyan] Misconfigurations\n"
        "[bold cyan]6.[/bold cyan] XSS & Parameters\n"
        "[bold cyan]7.[/bold cyan] Full Scan"
    )

    console.print(
        Panel(menu_text,
              title="[bold yellow]ATT&CK Surface Scanner[/bold yellow]",
              border_style="cyan")
    )

    choice = Prompt.ask(
        "Select scan mode",
        choices=["1", "2", "3", "4", "5", "6", "7"],
        default="7"
    )

    return FEATURE_MAPPING[choice]


# ----------------------------
# RULE FILTERING
# ----------------------------
def filter_rules(selected_feature):
    if selected_feature["categories"] is None:
        return RULES

    filtered = [
        r for r in RULES
        if getattr(r, "category", "").lower() in selected_feature["categories"]
    ]

    return filtered if filtered else RULES


# ----------------------------
# TARGET DETECTORS
# ----------------------------
def is_remote_git_link(token):
    return bool(re.match(
        r'^(https?://|git@)[\w.-]+[:/][\w.-]+/[\w.-]+(\.git)?/?$',
        token.strip()
    ))


def is_standard_web_url(token):
    return token.startswith(("http://", "https://")) and not is_remote_git_link(token)


# ----------------------------
# GIT SCAN
# ----------------------------
def scan_git_link(git_url, active_rules):
    console.print(Panel(f"[cyan]Git Target[/cyan]: {git_url}", title="Git Scanner"))

    try:
        from git import Repo
    except ImportError:
        console.print("[red]Missing GitPython: pip install GitPython[/red]")
        sys.exit(1)

    temp_dir = tempfile.mkdtemp(prefix="attck_git_")

    try:
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as p:
            p.add_task("Cloning repository...", total=None)
            Repo.clone_from(git_url, temp_dir, depth=1)

        scanner = SurfaceScanner(temp_dir, active_rules)
        results = scanner.scan()

        export_results(results, os.getcwd())
        render_dashboard(results)

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ----------------------------
# WEB SCAN
# ----------------------------
def scan_web_url(web_url, active_rules):
    console.print(Panel(f"[magenta]Web Target[/magenta]: {web_url}", title="Web Scanner"))

    temp_dir = tempfile.mkdtemp(prefix="attck_web_")
    headers = {"User-Agent": "ATT4ck-Surface-Scanner/1.0"}

    try:
        response = requests.get(web_url, headers=headers, timeout=10)
        html = response.text

        html_path = os.path.join(temp_dir, "index.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)

        soup = BeautifulSoup(html, "html.parser")

        js_count = 0
        for script in soup.find_all("script"):
            src = script.get("src")
            if not src:
                continue

            full_url = urljoin(web_url, src)

            try:
                js = requests.get(full_url, headers=headers, timeout=5).text
                js_count += 1

                js_path = os.path.join(temp_dir, f"script_{js_count}.js")
                with open(js_path, "w", encoding="utf-8") as f:
                    f.write(js)

            except Exception:
                pass

        console.print(f"[green]Fetched {js_count} JS files[/green]")

        scanner = SurfaceScanner(temp_dir, active_rules)
        results = scanner.scan()

        export_results(results, os.getcwd())
        render_dashboard(results)

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ----------------------------
# DASHBOARD
# ----------------------------
def render_dashboard(results):
    vulns = [r for r in results if r["status"] == "VULNERABLE"]
    safe = [r for r in results if r["status"] == "SANITIZED"]

    if vulns:
        table = Table(title="VULNERABILITIES", show_lines=True)
        table.add_column("Severity")
        table.add_column("Category")
        table.add_column("File:Line")
        table.add_column("Snippet")

        for v in vulns:
            table.add_row(
                v["severity"],
                v["category"],
                f'{v["file"]}:{v["line"]}',
                v["snippet"]
            )

        console.print(table)

    if safe:
        table = Table(title="SANITIZED", show_lines=True)
        table.add_column("Category")
        table.add_column("File:Line")
        table.add_column("Snippet")

        for s in safe:
            table.add_row(
                s["category"],
                f'{s["file"]}:{s["line"]}',
                s["snippet"]
            )

        console.print(table)

    console.print(Panel(
        f"[green]Scan Complete[/green]\nResults saved in current directory",
        title="Summary"
    ))


# ----------------------------
# MAIN
# ----------------------------
def main():
    print_banner()

    if len(sys.argv) < 2:
        target = Prompt.ask("Enter path, Git URL, or Web URL")
    else:
        target = sys.argv[1]

    selected = display_interactive_menu()
    active_rules = filter_rules(selected)

    console.print(f"[cyan]Mode:[/cyan] {selected['name']}")

    if is_remote_git_link(target):
        scan_git_link(target, active_rules)

    elif is_standard_web_url(target):
        scan_web_url(target, active_rules)

    else:
        if not os.path.exists(target):
            console.print("[red]Invalid local path[/red]")
            sys.exit(1)

        scanner = SurfaceScanner(target, active_rules)
        results = scanner.scan()

        export_results(results, os.getcwd())
        render_dashboard(results)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Stopped by user[/red]")
        sys.exit(0)