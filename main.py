#!/usr/bin/env python3
"""
ATT4ck Surface - Attack Surface Scanner
Main entry point
"""

import sys
import os
import tempfile
import shutil
from typing import List, Dict
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from attack_surface.banner import print_banner, print_startup, print_environment
from attack_surface.rules import ALL_RULES, get_rules_by_category
from attack_surface.scanner import SurfaceScanner
from attack_surface.web_crawler import WebCrawler
from attack_surface.exporter import export_results

console = Console()

# Feature mapping
FEATURES = {
    "1": {
        "name": "Endpoint Discovery",
        "categories": ["admin-portals", "api-endpoints", "debug-endpoints", "monitoring", "documentation"],
        "desc": "Discover hidden endpoints: /admin, /users, /api, /config, /backup, etc."
    },
    "2": {
        "name": "Secrets Detection",
        "categories": ["secrets-config", "environment-files", "source-control"],
        "desc": "Find hardcoded secrets: API keys, tokens, passwords, credentials"
    },
    "3": {
        "name": "File Analysis",
        "categories": ["file-uploads", "file-downloads", "cloud-storage", "backups"],
        "desc": "Analyze file uploads, downloads, and sensitive file exposures"
    },
    "4": {
        "name": "API Enumeration",
        "categories": ["api-endpoints", "graphql", "webhooks"],
        "desc": "Discover API endpoints: REST, GraphQL, Swagger, documentation"
    },
    "5": {
        "name": "Security Misconfigurations",
        "categories": ["server-config", "dns", "cache-services", "logging", "monitoring", "debug-endpoints"],
        "desc": "Find misconfigurations: CORS, debug mode, missing headers"
    },
    "6": {
        "name": "XSS & Parameter Mapping",
        "categories": ["user-inputs", "search-parameters", "id-parameters", "javascript-analysis", "redirects"],
        "desc": "Find XSS vulnerabilities: DOM XSS, reflected XSS, parameter injection"
    },
    "7": {
        "name": "Full Scan",
        "categories": None,  # All categories
        "desc": "Comprehensive scan covering all attack surfaces"
    }
}

def display_menu():
    """Display interactive menu"""
    console.print("\n")
    console.print(Panel(
        "[cyan]1.[/cyan] Endpoint Discovery - Find hidden endpoints\n"
        "[cyan]2.[/cyan] Secrets Detection - Find hardcoded secrets\n"
        "[cyan]3.[/cyan] File Analysis - Analyze file operations\n"
        "[cyan]4.[/cyan] API Enumeration - Discover API endpoints\n"
        "[cyan]5.[/cyan] Security Misconfigurations - Find misconfigs\n"
        "[cyan]6.[/cyan] XSS & Parameter Mapping - Find XSS vectors\n"
        "[cyan]7.[/cyan] Full Scan - Comprehensive analysis",
        title="ATT&CK Surface Scanner",
        width=70
    ))
    
    choice = Prompt.ask(
        "Select scan mode",
        choices=["1", "2", "3", "4", "5", "6", "7"],
        default="7"
    )
    
    return choice

def filter_rules_by_categories(categories: List[str]):
    """Filter rules by categories"""
    if categories is None:
        return ALL_RULES
    
    filtered = []
    for rule in ALL_RULES:
        if rule.category in categories:
            filtered.append(rule)
    return filtered

def scan_web_url(url: str, rules) -> List[Dict]:
    """Scan a web application"""
    console.print(Panel(f"[magenta]Web Target[/magenta] {url}"))
    
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Crawl the website
        crawler = WebCrawler(url, max_pages=50)
        data = crawler.crawl()
        
        console.print(f"[green]Found: {len(data.get('js_files', []))} JS files, {len(data.get('endpoints', []))} endpoints[/green]")
        
        # Download JS files
        js_output_dir = os.path.join(temp_dir, "js_files")
        os.makedirs(js_output_dir, exist_ok=True)
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Downloading JS files...", total=len(data.get('js_files', [])))
            downloaded = crawler.download_js_files(js_output_dir)
            progress.update(task, completed=len(data.get('js_files', [])))
        
        console.print(f"[green]Downloaded {len(downloaded)} JS files[/green]")
        
        # Scan the downloaded files
        scanner = SurfaceScanner(js_output_dir, rules)
        results = scanner.scan()
        
        # Also add endpoint findings
        for endpoint in data.get('endpoints', []):
            for rule in rules:
                for pattern in rule.vuln_patterns:
                    if pattern.search(endpoint):
                        results.append({
                            "finding_id": f"EP-{len(results)}",
                            "category": rule.category,
                            "name": rule.name,
                            "file": url,
                            "line": 0,
                            "snippet": endpoint,
                            "status": "VULNERABLE",
                            "severity": rule.severity,
                            "description": f"{rule.vuln_desc}: {endpoint}",
                            "cwe": rule.cwe,
                            "confidence": rule.confidence
                        })
                        break
        
        # Export results
        export_results(results, "output")
        
        return results
        
    except Exception as e:
        console.print(f"[red]Web scan failed: {e}[/red]")
        import traceback
        traceback.print_exc()
        return []
    
    finally:
        # Keep temp dir for debugging
        console.print(f"[dim]Temp dir: {temp_dir}[/dim]")

def render_results(results: List[Dict], mode_name: str):
    """Render scan results"""
    if not results:
        console.print("\n[green]✅ No vulnerabilities found![/green]")
        return
    
    # Count by severity
    severity_count = {}
    category_count = {}
    for r in results:
        severity = r.get('severity', 'MEDIUM')
        severity_count[severity] = severity_count.get(severity, 0) + 1
        
        category = r.get('category', 'UNKNOWN')
        category_count[category] = category_count.get(category, 0) + 1
    
    # Create summary
    console.print(f"\n[bold cyan]📊 Scan Summary - {mode_name}[/bold cyan]")
    
    # Severity summary
    summary_table = Table(title="Findings by Severity")
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count", justify="right")
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        count = severity_count.get(severity, 0)
        if count > 0:
            color = {'CRITICAL': 'red', 'HIGH': 'orange1', 'MEDIUM': 'yellow'}.get(severity, 'white')
            summary_table.add_row(f'[{color}]{severity}[/{color}]', str(count))
    
    console.print(summary_table)
    
    # Category summary
    cat_table = Table(title="Findings by Category")
    cat_table.add_column("Category", style="cyan")
    cat_table.add_column("Count", justify="right")
    
    for category, count in sorted(category_count.items(), key=lambda x: -x[1]):
        cat_table.add_row(category, str(count))
    
    console.print(cat_table)
    
    # Show findings table
    console.print(f"\n[bold]📋 Detailed Findings ({len(results)})[/bold]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("ID", style="dim", width=10)
    table.add_column("Severity", width=10)
    table.add_column("Category", width=15)
    table.add_column("Name", width=25)
    table.add_column("Location", width=25)
    table.add_column("Description", width=35)
    
    for r in results[:50]:  # Limit to 50 for readability
        severity = r.get('severity', 'MEDIUM')
        color = {'CRITICAL': 'red', 'HIGH': 'orange1', 'MEDIUM': 'yellow'}.get(severity, 'white')
        
        location = r.get('file', '')
        if r.get('line', 0) > 0:
            location += f":{r.get('line')}"
        
        table.add_row(
            r.get('finding_id', 'N/A')[:8],
            f'[{color}]{severity}[/{color}]',
            r.get('category', 'N/A')[:13],
            r.get('name', 'N/A')[:23],
            location[:23],
            r.get('description', 'N/A')[:33]
        )
    
    console.print(table)
    
    # Export results
    export_results(results, "output")
    console.print(f"\n[green]✅ Results saved to output/findings.json[/green]")

def main():
    """Main entry point"""
    print_banner()
    print_startup()
    print_environment()
    
    # Get target
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = Prompt.ask("Target URL (e.g., https://example.com)")
    
    # Validate URL
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    # Show menu
    choice = display_menu()
    mode_info = FEATURES[choice]
    
    console.print(f"\n[bold cyan]Mode:[/bold cyan] {mode_info['name']}")
    console.print(f"[dim]{mode_info['desc']}[/dim]")
    
    # Filter rules
    if mode_info['categories'] is None:
        rules = ALL_RULES
        console.print(f"[yellow]Rules Loaded:[/yellow] {len(rules)} (All categories)")
    else:
        rules = filter_rules_by_categories(mode_info['categories'])
        console.print(f"[yellow]Rules Loaded:[/yellow] {len(rules)} categories: {', '.join(mode_info['categories'])}")
    
    console.print("-" * 80)
    
    # Run scan
    results = scan_web_url(target, rules)
    
    # Render results
    render_results(results, mode_info['name'])

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Scan interrupted by user[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)