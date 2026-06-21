#!/usr/bin/env python3
"""
ATT4ck Surface - Attack Surface Scanner
Main entry point
"""

import sys
import os
import tempfile
import shutil
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from attack_surface.banner import print_banner, print_startup, print_environment
from attack_surface.rules import RULES, get_rule_count
from attack_surface.scanner import SurfaceScanner
from attack_surface.web_crawler import WebCrawler
from attack_surface.exporter import export_results
from attack_surface.risk_engine import filter_by_severity, get_risk

console = Console()

# Feature mapping
FEATURE_MAPPING = {
    "1": {"name": "Endpoint Discovery", "categories": ["APPLICATION", "NETWORK"]},
    "2": {"name": "Secrets Detection", "categories": ["SECRETS"]},
    "3": {"name": "File Analysis", "categories": ["APPLICATION"]},
    "4": {"name": "API Enumeration", "categories": ["NETWORK"]},
    "5": {"name": "Security Misconfigurations", "categories": ["NETWORK", "OPERATIONS"]},
    "6": {"name": "XSS & Parameter Mapping", "categories": ["APPLICATION"]},
    "7": {"name": "Full Scan", "categories": None},
}


def display_interactive_menu():
    """Display interactive menu"""
    console.print(Panel(
        "[cyan]1.[/cyan] Endpoint Discovery\n"
        "[cyan]2.[/cyan] Secrets Detection\n"
        "[cyan]3.[/cyan] File Analysis\n"
        "[cyan]4.[/cyan] API Enumeration\n"
        "[cyan]5.[/cyan] Security Misconfigurations\n"
        "[cyan]6.[/cyan] XSS & Parameter Mapping\n"
        "[cyan]7.[/cyan] Full Scan",
        title="ATT&CK Surface Scanner"
    ))

    choice = Prompt.ask(
        "Select scan mode",
        choices=["1", "2", "3", "4", "5", "6", "7"],
        default="7"
    )

    return FEATURE_MAPPING[choice]


def filter_rules(selected_feature):
    """Filter rules based on selected feature"""
    if selected_feature["categories"] is None:
        return RULES

    filtered = []
    for rule in RULES:
        if hasattr(rule, 'category'):
            for cat in selected_feature["categories"]:
                if cat.lower() in rule.category.lower():
                    filtered.append(rule)
                    break

    return filtered if filtered else RULES


def is_git_url(url):
    """Check if URL is a git repository"""
    git_patterns = [".git", "github.com", "gitlab.com", "bitbucket.org"]
    return any(p in url.lower() for p in git_patterns)


def is_web_url(url):
    """Check if URL is a web URL"""
    return url.startswith("http://") or url.startswith("https://")


def scan_git_url(git_url, rules):
    """Scan a git repository"""
    console.print(Panel(f"[cyan]Git Target[/cyan] {git_url}"))

    try:
        from git import Repo
    except ImportError:
        console.print("[red]GitPython not installed. Install with: pip install GitPython[/red]")
        return []

    temp_dir = tempfile.mkdtemp()

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Cloning repository...", total=None)
            Repo.clone_from(git_url, temp_dir, depth=1)
            progress.update(task, completed=True)

        scanner = SurfaceScanner(temp_dir, rules)
        results = scanner.scan()
        scanner.export_findings("output")

        return results

    except Exception as e:
        console.print(f"[red]Clone failed: {e}[/red]")
        console.print("[yellow]Switching to web scan mode...[/yellow]")
        return scan_web_url(git_url, rules)

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def scan_web_url(url, rules):
    """Scan a web application"""
    console.print(Panel(f"[magenta]Web Target[/magenta] {url}"))

    temp_dir = tempfile.mkdtemp()

    try:
        # Crawl the website
        crawler = WebCrawler(url, max_depth=2, max_pages=50)
        crawled_data = crawler.crawl()

        if not crawled_data['js_files']:
            console.print("[yellow]No JavaScript files found to scan[/yellow]")
            return []

        # Download JS files
        js_output_dir = os.path.join(temp_dir, "js_files")
        os.makedirs(js_output_dir, exist_ok=True)
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Downloading JS files...", total=len(crawled_data['js_files']))
            downloaded = crawler.download_js_files(js_output_dir)
            progress.update(task, completed=len(crawled_data['js_files']))

        console.print(f"[green]Downloaded {len(downloaded)} JS files[/green]")

        # Scan the downloaded files
        scanner = SurfaceScanner(js_output_dir, rules)
        results = scanner.scan()

        # Export results
        scanner.export_findings("output")

        return results

    except Exception as e:
        console.print(f"[red]Web scan failed: {e}[/red]")
        return []

    finally:
        # Keep temp dir for debugging
        console.print(f"[dim]Temp dir: {temp_dir}[/dim]")


def render_results(results):
    """Render scan results in a table"""
    if not results:
        console.print("[yellow]No findings found[/yellow]")
        return

    # Filter to show only vulnerable findings
    vulns = [r for r in results if r.get("status") == "VULNERABLE"]

    if not vulns:
        console.print("[green]No vulnerabilities found[/green]")
        return

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    vulns.sort(key=lambda x: severity_order.get(x.get("severity", "MEDIUM"), 5))

    # Create table
    table = Table(title="Vulnerabilities Found", show_header=True, header_style="bold magenta")
    table.add_column("Severity", style="cyan", no_wrap=True)
    table.add_column("Category", style="green")
    table.add_column("Name", style="white")
    table.add_column("File", style="dim")
    table.add_column("Line", style="yellow", justify="right")

    for v in vulns[:50]:  # Limit to 50 for readability
        severity = v.get("severity", "MEDIUM")
        severity_color = {
            "CRITICAL": "red",
            "HIGH": "orange1",
            "MEDIUM": "yellow",
            "LOW": "green",
            "INFO": "blue"
        }.get(severity, "white")

        table.add_row(
            f"[{severity_color}]{severity}[/{severity_color}]",
            v.get("category", "N/A"),
            v.get("name", "N/A")[:30],
            v.get("file", "N/A")[:40],
            str(v.get("line", "N/A"))
        )

    console.print(table)

    # Summary
    console.print("\n[bold]Summary:[/bold]")
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = len([v for v in vulns if v.get("severity") == severity])
        if count:
            color = {
                "CRITICAL": "red",
                "HIGH": "orange1",
                "MEDIUM": "yellow",
                "LOW": "green",
                "INFO": "blue"
            }.get(severity, "white")
            console.print(f"  [{color}]{severity}[/{color}]: {count}")


def main():
    """Main entry point"""
    print_banner()
    print_startup()
    print_environment()

    # Get target
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = Prompt.ask("Target (URL, git URL, or directory path)")

    # Select mode
    selected = display_interactive_menu()
    rules = filter_rules(selected)

    console.print(f"[cyan]Mode:[/cyan] {selected['name']}")
    console.print(f"[yellow]Rules Loaded:[/yellow] {len(rules)}")
    console.print("-" * 80)

    # Determine scan type and execute
    results = []

    if is_git_url(target):
        results = scan_git_url(target, rules)

    elif is_web_url(target):
        results = scan_web_url(target, rules)

    else:
        # Local directory
        if not os.path.exists(target):
            console.print(f"[red]Invalid path: {target}[/red]")
            sys.exit(1)

        console.print(f"[cyan]Scanning directory: {target}[/cyan]")
        scanner = SurfaceScanner(target, rules)
        results = scanner.scan()
        scanner.export_findings("output")

    # Render results
    render_results(results)

    # Export summary
    export_dir = "output"
    if os.path.exists(export_dir):
        files = os.listdir(export_dir)
        console.print(f"\n[green]Results saved to {export_dir}/[/green]")
        for f in files:
            if f in ["findings.json", "findings.db", "findings.csv", "report.html"]:
                console.print(f"  • {f}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Scan interrupted by user[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)