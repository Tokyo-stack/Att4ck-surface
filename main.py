# main.py
import sys
import os
import shutil
import tempfile
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# Modern CLI Visual Interface Dependencies
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

# Mapping Menu Choices directly to framework categories in rules.py
FEATURE_MAPPING = {
    "1": {
        "name": "Endpoint Discovery & Admin Portals",
        "categories": ["api-endpoints", "admin-portals", "redirects", "subdomains", "apiEndpoints", "adminPortals"]
    },
    "2": {
        "name": "Secret Detection & Credentials",
        "categories": ["authentication", "secrets-config", "environment-files", "ci-cd", "source-control", "secretsConfig", "environmentFiles", "ciCd", "sourceControl"]
    },
    "3": {
        "name": "File Upload & Download Analysis",
        "categories": ["file-uploads", "file-downloads", "backups", "fileUploads", "fileDownloads"]
    },
    "4": {
        "name": "API & GraphQL Enumeration",
        "categories": ["api-endpoints", "graphql", "webhooks", "third-party-integrations", "apiEndpoints", "thirdPartyIntegrations"]
    },
    "5": {
        "name": "Security Misconfigurations",
        "categories": ["server-config", "containers", "cloud-storage", "debug-endpoints", "monitoring", "serverConfig", "cloudStorage", "debugEndpoints"]
    },
    "6": {
        "name": "Parameter & XSS Mapping",
        "categories": ["user-inputs", "search-parameters", "id-parameters", "javascript-analysis", "userInputs", "searchParameters", "idParameters", "javascriptAnalysis"]
    },
    "7": {
        "name": "Full Source Code Review (All 40 Categories)",
        "categories": None
    }
}

def display_interactive_menu():
    """Renders the feature framework selector panel directly within the rich interface."""
    menu_text = (
        "[bold cyan]1.[/bold cyan] Endpoint Discovery      [bold cyan]2.[/bold cyan] Secret Detection      [bold cyan]3.[/bold cyan] File Upload Analysis\n"
        "[bold cyan]4.[/bold cyan] API Enumeration         [bold cyan]5.[/bold cyan] Security Misconfig    [bold cyan]6.[/bold cyan] Parameter Mapping\n"
        "[bold cyan]7.[/bold cyan] Full Source Code Review (Run All 40 Categories)"
    )
    console.print(Panel(menu_text, title="[bold yellow]Available Scan Options[/bold yellow]", border_style="cyan"))
    
    choice = Prompt.ask("[bold question_mark][?][/bold question_mark] Select an Attack Surface Feature to scan", choices=["1", "2", "3", "4", "5", "6", "7"], default="7")
    return FEATURE_MAPPING[choice]

def filter_rules(selected_feature):
    """Filters global RULES down to specific categories requested by the user choice."""
    if selected_feature["categories"] is None:
        return RULES
    
    filtered = [r for r in RULES if r.category in selected_feature["categories"]]
    # Fallback to prevent empty configurations if casing misalignments occur
    if not filtered:
        return RULES
    return filtered

def is_remote_git_link(token):
    url = token.strip()
    if not url.startswith(("http://", "https://", "git@")):
        return False
    git_pattern = r'^(https?://|git@)[a-zA-Z0-9.-]+[:/][a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+(\.git)?/?$'
    return bool(re.match(git_pattern, url))

def is_standard_web_url(token):
    url = token.strip()
    return url.startswith(("http://", "https://")) and not is_remote_git_link(url)

def scan_git_link(git_url, active_rules):
    console.print(Panel(f"[bold cyan][*][/bold cyan] Targeting Remote Repository: [underline]{git_url}[/underline]", title="Git Ingest Layer"))
    try:
        from git import Repo
    except ImportError:
        console.print("[bold red][-] Dependency Error: 'GitPython' package is missing. Run: pip install GitPython[/bold red]")
        sys.exit(1)

    temp_workspace = tempfile.mkdtemp(prefix="att4ck_git_")
    try:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            progress.add_task(description="Cloning remote repo snapshot (depth=1)...", total=None)
            Repo.clone_from(git_url, temp_workspace, depth=1)
        
        scanner = SurfaceScanner(temp_workspace, active_rules)
        results = scanner.scan()
        export_results(results, os.getcwd())
        _render_rich_summary_dashboard(results)
    except Exception as e:
        console.print(f"[bold red][-] Git Cloning Operation Aborted: {e}[/bold red]")
    finally:
        shutil.rmtree(temp_workspace, ignore_errors=True)

def scan_web_url(web_url, active_rules):
    console.print(Panel(f"[bold magenta][*][/bold magenta] Targeting Live Application: [underline]{web_url}[/underline]", title="Web Ingest Layer"))
    temp_workspace = tempfile.mkdtemp(prefix="att4ck_web_")
    headers = {"User-Agent": "ATT4ck-Surface-Scanner/1.0"}
    
    try:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            progress.add_task(description="Crawling index landing page assets...", total=None)
            response = requests.get(web_url, headers=headers, timeout=10)
            html_content = response.text
        
        with open(os.path.join(temp_workspace, "index.html"), "w", encoding="utf-8") as f:
            f.write(html_content)
            
        soup = BeautifulSoup(html_content, 'html.parser')
        script_tags = soup.find_all("script")
        js_count = 0
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            progress.add_task(description=f"Parsing external front-end source maps...", total=None)
            for script_tag in script_tags:
                src = script_tag.get("src")
                if src:
                    absolute_js_url = urljoin(web_url, src)
                    try:
                        js_res = requests.get(absolute_js_url, headers=headers, timeout=5)
                        js_count += 1
                        js_filename = f"script_{js_count}_{os.path.basename(urlparse(absolute_js_url).path)}"
                        if not js_filename.endswith(".js"): js_filename += ".js"
                        with open(os.path.join(temp_workspace, js_filename), "w", encoding="utf-8") as js_f:
                            js_f.write(js_res.text)
                    except Exception:
                        pass
                        
        console.print(f"[bold green][+][/bold green] Ingest mirrored layout: [bold]1[/bold] HTML file and [bold]{js_count}[/bold] scripts cached.")
        scanner = SurfaceScanner(temp_workspace, active_rules)
        results = scanner.scan()
        export_results(results, os.getcwd())
        _render_rich_summary_dashboard(results)
    except Exception as e:
        console.print(f"[bold red][-] Web Scraper Pipeline Stalled: {e}[/bold red]")
    finally:
        shutil.rmtree(temp_workspace, ignore_errors=True)

def _render_rich_summary_dashboard(results):
    """Builds a beautiful grid report framework instead of raw chaotic printing loops."""
    vulnerabilities = [r for r in results if r["status"] == "VULNERABLE"]
    sanitized = [r for r in results if r["status"] == "SANITIZED"]

    if vulnerabilities:
        table = Table(title="\n🚨 Identified Vulnerable Attack Surfaces", title_style="bold red", show_lines=True)
        table.add_column("Severity", style="bold", justify="center")
        table.add_column("Category", style="cyan")
        table.add_column("Location (File:Line)", style="green")
        table.add_column("Risk Snippet Highlight Context", style="white")

        for v in vulnerabilities:
            color = "red" if v["severity"] == "CRITICAL" else ("yellow" if v["severity"] == "HIGH" else "blue")
            table.add_row(f"[{color}]{v['severity']}[/{color}]", v["category"], f"{v['file']}:{v['line']}", v["snippet"].strip())
        console.print(table)

    if sanitized:
        s_table = Table(title="\n✅ Actively Defended / Sanitized Framework Layers", title_style="bold green", show_lines=True)
        s_table.add_column("Category", style="cyan")
        s_table.add_column("Location", style="green")
        s_table.add_column("Mitigation Snippet", style="dim white")

        for s in sanitized:
            s_table.add_row(s["category"], f"{s['file']}:{s['line']}", s["snippet"].strip())
        console.print(s_table)

    console.print(Panel.fit(
        f"Scan Completed Successfully.\n[bold green]Secure Artifacts Logged Globally:[/bold green]\n 📁 JSON Doc: {os.path.join(os.getcwd(), 'findings.json')}\n 💾 SQL DB:  {os.path.join(os.getcwd(), 'findings.db')}",
        title="Telemetry Persistence Complete"
    ))

def main():
    print_banner()

    # If no target arg was given, request input interactively
    if len(sys.argv) < 2:
        input_target = Prompt.ask("[bold question_mark][?][/bold question_mark] Enter folder path, Git URL, or live web page link").strip()
        if not input_target:
            console.print("[bold red][-] Input Error: Target path or URL cannot be empty.[/bold red]")
            sys.exit(1)
    else:
        input_target = sys.argv[1].strip()

    # Fire the visual option selector
    selected_feature = display_interactive_menu()
    active_rules = filter_rules(selected_feature)
    
    console.print(f"[*] [bold cyan]Active Scan Mode:[/bold cyan] {selected_feature['name']} ({len(active_rules)} Rules Active)\n")

        # Execution block mapping targets to their proper intake functions
    if is_remote_git_link(input_target):
        scan_git_link(input_target, active_rules)
    elif is_standard_web_url(input_target):
        scan_web_url(input_target, active_rules)
    else:
        if not os.path.exists(input_target):
            console.print(f"[bold red][-] Path Fault: Local target directory could not be resolved: {input_target}[/bold red]")
            sys.exit(1)
            
        console.print(Panel(f"[bold blue][*][/bold blue] Running Multi-Core Inspection Against Local Path: [underline]{input_target}[/underline]"))
        scanner = SurfaceScanner(input_target, active_rules)
        results = scanner.scan()
        export_results(results, os.getcwd())
        _render_rich_summary_dashboard(results)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red][-] Scan execution aborted by user.[/bold red]")
        sys.exit(0)
