import sys
import os
import shutil
import tempfile
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

from attack_surface.banner import print_banner, print_startup, print_environment
from attack_surface.rules import RULES
from attack_surface.scanner import SurfaceScanner
from attack_surface.exporter import export_results

console = Console()

# ----------------------------
# FEATURE MAP
# ----------------------------
FEATURE_MAPPING = {
    "1": {"name": "Endpoint Discovery", "tags": ["admin", "endpoint"]},
    "2": {"name": "Secrets Detection", "tags": ["secret", "auth", "credential"]},
    "3": {"name": "File Analysis", "tags": ["file", "upload", "download"]},
    "4": {"name": "API Enumeration", "tags": ["api", "graphql"]},
    "5": {"name": "Misconfigurations", "tags": ["debug", "config"]},
    "6": {"name": "XSS & Parameters", "tags": ["xss", "input", "param"]},
    "7": {"name": "Full Scan", "tags": None}
}

# ----------------------------
# MENU
# ----------------------------
def display_interactive_menu():
    console.print(Panel(
        "[cyan]1.[/cyan] Endpoint Discovery\n"
        "[cyan]2.[/cyan] Secrets Detection\n"
        "[cyan]3.[/cyan] File Analysis\n"
        "[cyan]4.[/cyan] API Enumeration\n"
        "[cyan]5.[/cyan] Misconfigurations\n"
        "[cyan]6.[/cyan] XSS & Parameters\n"
        "[cyan]7.[/cyan] Full Scan",
        title="ATT&CK Surface Scanner"
    ))

    choice = Prompt.ask(
        "Select scan mode",
        choices=["1", "2", "3", "4", "5", "6", "7"],
        default="7"
    )

    return FEATURE_MAPPING[choice]

# ----------------------------
# RULE FILTERING
# ----------------------------
def rule_matches(rule, tags):
    if not tags:
        return True

    category = str(getattr(rule, "category", "")).lower()
    return any(tag in category for tag in tags)


def filter_rules(selected_feature):
    if selected_feature["tags"] is None:
        return RULES

    filtered = [r for r in RULES if rule_matches(r, selected_feature["tags"])]
    return filtered if filtered else RULES

# ----------------------------
# TARGET DETECTION
# ----------------------------
def is_git(url):
    git_patterns = [".git", "github.com", "gitlab.com", "bitbucket.org"]
    return any(p in url.lower() for p in git_patterns)


def is_web(url):
    return url.startswith("http://") or url.startswith("https://")

# ----------------------------
# GIT SCAN
# ----------------------------
def scan_git_link(git_url, rules):
    console.print(Panel(f"[cyan]Git Target[/cyan] {git_url}"))

    try:
        from git import Repo
    except ImportError:
        console.print("[red]Install GitPython first[/red]")
        sys.exit(1)

    temp_dir = tempfile.mkdtemp()

    try:
        # Clone repo
        Repo.clone_from(git_url, temp_dir, depth=1)

        scanner = SurfaceScanner(temp_dir, rules)
        results = scanner.scan()

        save_output(results)

    except Exception as e:
        console.print(f"[red][!] Clone Failed:[/red] {e}")
        console.print("[yellow][!] Switching to web scan mode...[/yellow]")

        scan_web_url(git_url, rules)

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ----------------------------
# WEB SCAN
# ----------------------------
def scan_web_url(url, rules):
    console.print(Panel(f"[magenta]Web Target[/magenta] {url}"))

    temp_dir = tempfile.mkdtemp()
    headers = {"User-Agent": "ATT&CK Surface Scanner"}

    try:
        html = requests.get(url, headers=headers, timeout=10).text

        with open(os.path.join(temp_dir, "index.html"), "w", encoding="utf-8") as f:
            f.write(html)

        soup = BeautifulSoup(html, "html.parser")

        count = 0
        for script in soup.find_all("script"):
            src = script.get("src")
            if not src:
                continue

            full = urljoin(url, src)

            try:
                js = requests.get(full, headers=headers, timeout=5).text
                count += 1

                with open(os.path.join(temp_dir, f"script_{count}.js"), "w", encoding="utf-8") as f:
                    f.write(js)
            except:
                pass

        console.print(f"[green]JS files fetched: {count}[/green]")

        scanner = SurfaceScanner(temp_dir, rules)
        results = scanner.scan()

        save_output(results)

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ----------------------------
# OUTPUT
# ----------------------------
def save_output(results):
    output_dir = os.path.join(os.getcwd(), "output")
    os.makedirs(output_dir, exist_ok=True)

    export_results(results, output_dir)

    console.print(Panel(
        f"[green]Scan Complete[/green]\n"
        f"Findings: {len(results)}\n"
        f"Saved → output/findings.json",
        title="RESULTS"
    ))

    render(results)

# ----------------------------
# DASHBOARD
# ----------------------------
def render(results):
    vulns = [r for r in results if r.get("status") == "VULNERABLE"]

    if not vulns:
        return

    table = Table(title="VULNERABILITIES")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("File")
    table.add_column("Snippet")

    for v in vulns:
        table.add_row(
            v.get("severity", "N/A"),
            v.get("category", "N/A"),
            f"{v.get('file')}:{v.get('line')}",
            v.get("snippet", "")
        )

    console.print(table)

# ----------------------------
# MAIN
# ----------------------------
def main():
    print_banner()
    print_startup()
    print_environment()

    target = sys.argv[1] if len(sys.argv) > 1 else Prompt.ask("Target")

    selected = display_interactive_menu()
    rules = filter_rules(selected)

    console.print(f"[cyan]Mode:[/cyan] {selected['name']}")
    console.print(f"[yellow]Rules Loaded:[/yellow] {len(rules)}")

    if is_git(target):
        scan_git_link(target, rules)

    elif is_web(target):
        scan_web_url(target, rules)

    else:
        if not os.path.exists(target):
            console.print("[red]Invalid path[/red]")
            return

        scanner = SurfaceScanner(target, rules)
        results = scanner.scan()

        save_output(results)

# ----------------------------
# RUN
# ----------------------------
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Stopped[/red]")
        sys.exit(0)