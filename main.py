#!/usr/bin/env python3
"""
ATT4ck Surface - Attack Surface Scanner
The Deadliest Security Scanner - Zero False Positives
"""

import sys
import os
import tempfile
import re
import requests
from datetime import datetime
from typing import List, Dict, Optional
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from attack_surface.banner import print_banner, print_startup, print_environment
from attack_surface.scanner import SurfaceScanner, verify_endpoint, export_results
from attack_surface.xss_scanner import XSSScanner, XSS_PAYLOADS, XSS_PARAMETERS
from attack_surface.web_crawler import WebCrawler

console = Console()

# ============================================================================
# BUILD ARTIFACT FILTERS
# ============================================================================

BUILD_ARTIFACT_PATTERNS = [
    r'/_next/',
    r'/static/',
    r'/chunks/',
    r'/images/',
    r'/fonts/',
    r'/icons/',
    r'/favicon\.',
    r'/manifest\.',
    r'\.woff2?$',
    r'\.ttf$',
    r'\.eot$',
    r'\.svg$',
    r'\.png$',
    r'\.jpg$',
    r'\.jpeg$',
    r'\.gif$',
    r'\.ico$',
    r'\.webp$',
    r'\.css$',
    r'\.map$',
    r'__next',
    r'webpack',
    r'chunk-',
    r'framework-',
    r'polyfills',
    r'runtime',
    r'vendor',
]

# ============================================================================
# PATTERN DEFINITIONS
# ============================================================================

DISCOVERY_PATTERNS = [
    r'/login(?:/|$|\?|#)', r'/signin(?:/|$|\?|#)', r'/signup(?:/|$|\?|#)',
    r'/register(?:/|$|\?|#)', r'/logout(?:/|$|\?|#)', r'/forgot-password(?:/|$|\?|#)',
    r'/reset-password(?:/|$|\?|#)', r'/mfa(?:/|$|\?|#)', r'/2fa(?:/|$|\?|#)',
    r'/verify(?:/|$|\?|#)', r'/auth(?:/|$|\?|#)', r'/authenticate(?:/|$|\?|#)',
    r'/authorize(?:/|$|\?|#)', r'/token(?:/|$|\?|#)', r'/refresh-token(?:/|$|\?|#)',
    r'/profile(?:/|$|\?|#)', r'/account(?:/|$|\?|#)', r'/settings(?:/|$|\?|#)',
    r'/admin(?:/|$|\?|#)', r'/superadmin(?:/|$|\?|#)', r'/staff(?:/|$|\?|#)',
    r'/manage(?:/|$|\?|#)', r'/control-panel(?:/|$|\?|#)', r'/dashboard(?:/|$|\?|#)',
    r'/console(?:/|$|\?|#)', r'/api(?:/|$|\?|#)', r'/api/v1(?:/|$|\?|#)',
    r'/api/v2(?:/|$|\?|#)', r'/api/v3(?:/|$|\?|#)', r'/rest(?:/|$|\?|#)',
    r'/graphql(?:/|$|\?|#)', r'/gql(?:/|$|\?|#)', r'/graphiql(?:/|$|\?|#)',
    r'/playground(?:/|$|\?|#)', r'/swagger(?:/|$|\?|#)', r'/swagger-ui(?:/|$|\?|#)',
    r'/redoc(?:/|$|\?|#)', r'/api-docs(?:/|$|\?|#)', r'/apidocs(?:/|$|\?|#)',
    r'/docs(?:/|$|\?|#)', r'/openapi(?:/|$|\?|#)', r'/metrics(?:/|$|\?|#)',
    r'/health(?:/|$|\?|#)', r'/healthz(?:/|$|\?|#)', r'/status(?:/|$|\?|#)',
    r'/actuator(?:/|$|\?|#)', r'/monitoring(?:/|$|\?|#)', r'/ping(?:/|$|\?|#)',
    r'/ready(?:/|$|\?|#)', r'/live(?:/|$|\?|#)', r'/debug(?:/|$|\?|#)',
    r'/test(?:/|$|\?|#)', r'/sandbox(?:/|$|\?|#)', r'/staging(?:/|$|\?|#)',
    r'/dev(?:/|$|\?|#)', r'/phpinfo\.php', r'/server-status', r'/upload(?:/|$|\?|#)',
    r'/uploads(?:/|$|\?|#)', r'/download(?:/|$|\?|#)', r'/downloads(?:/|$|\?|#)',
    r'/files(?:/|$|\?|#)', r'/file(?:/|$|\?|#)', r'/documents(?:/|$|\?|#)',
    r'/media(?:/|$|\?|#)', r'/images(?:/|$|\?|#)', r'/assets(?:/|$|\?|#)',
    r'/static(?:/|$|\?|#)', r'/public(?:/|$|\?|#)', r'/webhook(?:/|$|\?|#)',
    r'/webhooks(?:/|$|\?|#)', r'/callback(?:/|$|\?|#)', r'/oauth(?:/|$|\?|#)',
    r'/oidc(?:/|$|\?|#)', r'/saml(?:/|$|\?|#)', r'/sso(?:/|$|\?|#)',
    r'/integrations(?:/|$|\?|#)', r'/backup(?:/|$|\?|#)', r'/backups(?:/|$|\?|#)',
    r'/archive(?:/|$|\?|#)', r'/tmp(?:/|$|\?|#)', r'/temp(?:/|$|\?|#)',
    r'/cache(?:/|$|\?|#)', r'/snapshot(?:/|$|\?|#)', r'/restore(?:/|$|\?|#)',
    r'/wp-admin(?:/|$|\?|#)', r'/wp-login\.php', r'/wp-content(?:/|$|\?|#)',
    r'/administrator(?:/|$|\?|#)', r'/cms(?:/|$|\?|#)', r'/joomla(?:/|$|\?|#)',
    r'/drupal(?:/|$|\?|#)', r'/wordpress(?:/|$|\?|#)', r'/robots\.txt',
    r'/sitemap\.xml', r'/\.well-known/', r'/security\.txt', r'/search(?:/|$|\?|#)',
    r'/query(?:/|$|\?|#)', r'/filter(?:/|$|\?|#)', r'/find(?:/|$|\?|#)',
    r'/lookup(?:/|$|\?|#)', r'/cart(?:/|$|\?|#)', r'/checkout(?:/|$|\?|#)',
    r'/orders(?:/|$|\?|#)', r'/payment(?:/|$|\?|#)', r'/payments(?:/|$|\?|#)',
    r'/invoice(?:/|$|\?|#)', r'/billing(?:/|$|\?|#)', r'/subscription(?:/|$|\?|#)',
    r'/products(?:/|$|\?|#)', r'/store(?:/|$|\?|#)', r'/shop(?:/|$|\?|#)',
    r'/users(?:/|$|\?|#)', r'/profiles(?:/|$|\?|#)', r'/accounts(?:/|$|\?|#)',
    r'/members(?:/|$|\?|#)', r'/teams(?:/|$|\?|#)', r'/home(?:/|$|\?|#)',
    r'/app(?:/|$|\?|#)', r'/portal(?:/|$|\?|#)', r'/workspace(?:/|$|\?|#)',
    r'/studio(?:/|$|\?|#)', r'/hub(?:/|$|\?|#)', r'/notifications(?:/|$|\?|#)',
    r'/alerts(?:/|$|\?|#)', r'/activity(?:/|$|\?|#)', r'/feed(?:/|$|\?|#)',
    r'/timeline(?:/|$|\?|#)', r'/overview(?:/|$|\?|#)',
]

SECRETS_PATTERNS = [
    r'api[_-]?key\s*[:=]\s*["\'][^"\']+["\']',
    r'apikey\s*[:=]\s*["\'][^"\']+["\']',
    r'API_KEY\s*=\s*["\'][^"\']+["\']',
    r'"apiKey"\s*:\s*"[^"]+"',
    r'secret\s*[:=]\s*["\'][^"\']+["\']',
    r'client_secret\s*[:=]\s*["\'][^"\']+["\']',
    r'private_key\s*[:=]\s*["\'][^"\']+["\']',
    r'SECRET_KEY\s*=\s*["\'][^"\']+["\']',
    r'token\s*[:=]\s*["\'][^"\']+["\']',
    r'access_token\s*[:=]\s*["\'][^"\']+["\']',
    r'refresh_token\s*[:=]\s*["\'][^"\']+["\']',
    r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
    r'password\s*[:=]\s*["\'][^"\']+["\']',
    r'passwd\s*[:=]\s*["\'][^"\']+["\']',
    r'DB_PASSWORD\s*=\s*["\'][^"\']+["\']',
    r'"password"\s*:\s*"[^"]+"',
    r'AKIA[0-9A-Z]{16}',
    r'ASIA[0-9A-Z]{16}',
    r'sk-[a-zA-Z0-9]{20,}',
    r'gh[pousr]_[a-zA-Z0-9]{36,}',
    r'xox[baprs]-[a-zA-Z0-9-]+',
    r'AIza[0-9A-Za-z\\-_]{35}',
    r'SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}',
    r'BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY',
    r'mongodb://[^"\'\s]+',
    r'mysql://[^"\'\s]+',
    r'postgres://[^"\'\s]+',
    r'redis://[^"\'\s]+',
    r'sqlite://[^"\'\s]+',
    r'DATABASE_URL\s*=\s*["\'][^"\']+["\']',
    r'webhook_secret\s*[:=]\s*["\'][^"\']+["\']',
    r'WEBHOOK_SECRET\s*=\s*["\'][^"\']+["\']',
    r'"webhookSecret"\s*:\s*"[^"]+"',
    r'NODE_ENV\s*=\s*["\'][^"\']+["\']',
    r'REACT_APP_[A-Z_]+\s*=\s*["\'][^"\']+["\']',
    r'NEXT_PUBLIC_[A-Z_]+\s*=\s*["\'][^"\']+["\']',
    r'VUE_APP_[A-Z_]+\s*=\s*["\'][^"\']+["\']',
]

FILE_PATTERNS = [
    r'request\.files', r'file\.save\s*\(', r'multer\s*\(',
    r'upload\.single\s*\(', r'upload\.array\s*\(', r'upload\.fields\s*\(',
    r'\.file\([^)]*\)', r'form-data', r'multipart/form-data',
    r'enctype="multipart/form-data"', r'send_file\s*\(',
    r'send_from_directory\s*\(', r'fs\.readFile\s*\(',
    r'file_get_contents\s*\(', r'readfile\s*\(',
    r'DownloadFile\s*\(', r'response\.sendFile', r'\.\./\.\./',
    r'\.\.\\\.\.\\', r'os\.path\.join\s*\([^,]+,\s*["\']\.\.',
    r'path\.join\s*\([^,]+,\s*["\']\.\.', r'open\s*\([^,]*\.\.\/\.\.',
    r'\.bak$', r'\.old$', r'\.tmp$', r'\.swp$', r'backup_',
    r'copy_of_', r'public-read', r'public_read',
    r'AllowedOrigins\s*:\s*\*', r'aws_s3_bucket', r'S3_BUCKET',
]

API_PATTERNS = [
    r'/api/', r'/rest/', r'/v1/', r'/v2/', r'/v3/',
    r'/service/', r'/graphql', r'/gql', r'/graphiql',
    r'/playground', r'/swagger', r'/swagger-ui', r'/docs',
    r'/redoc', r'/openapi', r'/api-docs', r'/apidocs',
    r'/webhook', r'/callback', r'/oauth', r'/sso',
    r'/saml', r'/oidc', r'/integrations', r'/api/mobile',
    r'/mobile-api', r'/v1/mobile', r'/sdk', r'/client',
    r'\.json$',
]

MISCONFIG_PATTERNS = [
    r'Access-Control-Allow-Origin\s*:\s*\*',
    r'origin\s*:\s*["\']\*["\']',
    r'debug\s*=\s*True',
    r'debug\s*=\s*true',
    r'NODE_ENV\s*=\s*["\']development["\']',
    r'APP_DEBUG\s*=\s*true',
    r'FLASK_DEBUG\s*=\s*1',
    r'X-Powered-By',
    r'Server:\s*Apache',
    r'Server:\s*nginx',
    r'X-AspNet-Version',
    r'X-Frame-Options',
    r'X-Content-Type-Options',
    r'X-XSS-Protection',
    r'Content-Security-Policy',
    r'Strict-Transport-Security',
    r'/debug(?:/|$|\?|#)',
    r'/test(?:/|$|\?|#)',
    r'/dev(?:/|$|\?|#)',
    r'/staging(?:/|$|\?|#)',
    r'/sandbox(?:/|$|\?|#)',
    r'/phpinfo\.php',
    r'/server-status',
    r'/health(?:/|$|\?|#)',
    r'/status(?:/|$|\?|#)',
    r'/metrics(?:/|$|\?|#)',
    r'\.env',
    r'\.env\.example',
    r'\.env\.local',
]

XSS_PATTERNS = [
    r'\.innerHTML\s*=', r'\.outerHTML\s*=', r'document\.write\s*\(',
    r'document\.writeln\s*\(', r'\.insertAdjacentHTML\s*\(',
    r'dangerouslySetInnerHTML', r'v-html\s*=', r'ng-bind-html\s*=',
    r'eval\s*\(', r'new\s+Function\s*\(', r'Function\s*\(',
    r'setTimeout\s*\(\s*["\']', r'setInterval\s*\(\s*["\']',
    r'javascript:', r'location\.href\s*=\s*["\']javascript:',
    r'window\.location\s*=\s*["\']javascript:',
    r'request\.args\.get\s*\(\s*["\']q["\']', r'req\.query\.search',
    r'location\.search', r'\$_GET\[\'q\'\]',
    r'request\.args\.get\s*\(\s*["\'](?:id|user|page|sort|filter|search)["\']',
    r'req\.query\.(?:id|user|page|sort|filter|search)',
    r'redirect\s*\(\s*request\.', r'res\.redirect\s*\(',
    r'redirect_to\s*=', r'return\s+redirect\s*\(',
    r'requests\.get\s*\(\s*["\']https?://.*\+\s*',
    r'fetch\s*\(\s*["\']https?://.*\+\s*',
    r'axios\.get\s*\(\s*["\']https?://.*\+\s*',
]

# ============================================================================
# FEATURE MAPPING
# ============================================================================

FEATURES = {
    "1": {"name": "Endpoint Discovery", "description": "Discover hidden endpoints", "patterns": DISCOVERY_PATTERNS, "severity": "MEDIUM"},
    "2": {"name": "Secrets Detection", "description": "Find hardcoded secrets", "patterns": SECRETS_PATTERNS, "severity": "CRITICAL"},
    "3": {"name": "File Analysis", "description": "Analyze file operations", "patterns": FILE_PATTERNS, "severity": "HIGH"},
    "4": {"name": "API Enumeration", "description": "Discover API endpoints", "patterns": API_PATTERNS, "severity": "MEDIUM"},
    "5": {"name": "Security Misconfigurations", "description": "Find misconfigurations", "patterns": MISCONFIG_PATTERNS, "severity": "HIGH"},
    "6": {"name": "XSS & Parameter Mapping", "description": "Comprehensive XSS testing with 100+ payloads", "patterns": XSS_PATTERNS, "severity": "CRITICAL"},
    "7": {"name": "Full Scan", "description": "Comprehensive analysis", "patterns": None, "severity": "ALL"},
}


def is_build_artifact(endpoint: str) -> bool:
    for pattern in BUILD_ARTIFACT_PATTERNS:
        if re.search(pattern, endpoint, re.IGNORECASE):
            return True
    return False


def display_menu():
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
    return Prompt.ask("Select scan mode", choices=["1","2","3","4","5","6","7"], default="7")


def is_web_url(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")


def scan_web_url(url: str, mode: str, patterns: List[str]) -> List[Dict]:
    console.print(Panel(f"[magenta]Web Target[/magenta] {url}"))
    
    temp_dir = tempfile.mkdtemp()
    all_findings = []
    found_items = set()
    verified_endpoints = set()
    
    try:
        console.print("[cyan]Fetching HTML content...[/cyan]")
        import requests
        html_content = ""
        try:
            response = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
            if response.status_code == 200:
                html_content = response.text
                console.print("[green]HTML content fetched successfully[/green]")
        except Exception as e:
            console.print(f"[yellow]Could not fetch HTML: {e}[/yellow]")
        
        if html_content and patterns:
            console.print(f"[cyan]Scanning HTML with {len(patterns)} patterns...[/cyan]")
            for line_idx, line in enumerate(html_content.split('\n'), 1):
                line = line.strip()
                if not line or len(line) < 10:
                    continue
                for pattern in patterns:
                    try:
                        matches = re.findall(pattern, line, re.IGNORECASE)
                        for match in matches:
                            if isinstance(match, tuple):
                                match = match[0] if match else ""
                            if match and len(str(match)) > 3:
                                potential = str(match)
                                if potential.startswith('/'):
                                    full_url = url.rstrip('/') + potential
                                    if verify_endpoint(full_url):
                                        key = f"{potential}"
                                        if key not in verified_endpoints:
                                            verified_endpoints.add(key)
                                            all_findings.append({
                                                "finding_id": f"EP-{len(all_findings)}",
                                                "cwe": "N/A",
                                                "category": mode,
                                                "name": "Verified Endpoint Found",
                                                "file": url,
                                                "line": line_idx,
                                                "snippet": line[:200],
                                                "status": "VULNERABLE",
                                                "severity": FEATURES.get(mode, {}).get("severity", "MEDIUM"),
                                                "confidence": 95,
                                                "description": f"Verified: {potential} (200 OK)",
                                                "timestamp": datetime.now().isoformat()
                                            })
                                    elif is_build_artifact(potential):
                                        continue
                    except re.error:
                        pass
        
        console.print("[cyan]Crawling website...[/cyan]")
        crawler = WebCrawler(url, max_pages=30)
        data = crawler.crawl()
        console.print(f"[green]Found: {len(data.get('js_files', []))} JS files, {len(data.get('endpoints', []))} endpoints[/green]")
        
        js_output_dir = os.path.join(temp_dir, "js_files")
        os.makedirs(js_output_dir, exist_ok=True)
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Downloading JS files...", total=len(data.get('js_files', [])))
            downloaded = crawler.download_js_files(js_output_dir)
            progress.update(task, completed=len(data.get('js_files', [])))
        
        console.print(f"[green]Downloaded {len(downloaded)} JS files[/green]")
        
        if downloaded and patterns:
            console.print(f"[cyan]Scanning JS files with {len(patterns)} patterns...[/cyan]")
            for js_file in downloaded:
                try:
                    with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.split('\n')
                    
                    if len(lines) < 5 and len(content) > 10000:
                        continue
                    
                    for line_idx, line in enumerate(lines, 1):
                        line = line.strip()
                        if not line or len(line) < 10:
                            continue
                        if any(skip in line for skip in ['console.log', 'console.error', 'module.exports', 'export default', 'import React']):
                            continue
                        for pattern in patterns:
                            try:
                                matches = re.findall(pattern, line, re.IGNORECASE)
                                for match in matches:
                                    if isinstance(match, tuple):
                                        match = match[0] if match else ""
                                    if match and len(str(match)) > 3:
                                        potential = str(match)
                                        if potential.startswith('/'):
                                            full_url = url.rstrip('/') + potential
                                            if verify_endpoint(full_url):
                                                key = f"{potential}"
                                                if key not in verified_endpoints:
                                                    verified_endpoints.add(key)
                                                    all_findings.append({
                                                        "finding_id": f"EP-{len(all_findings)}",
                                                        "cwe": "N/A",
                                                        "category": mode,
                                                        "name": "Verified Endpoint in JS",
                                                        "file": os.path.basename(js_file),
                                                        "line": line_idx,
                                                        "snippet": line[:200],
                                                        "status": "VULNERABLE",
                                                        "severity": FEATURES.get(mode, {}).get("severity", "MEDIUM"),
                                                        "confidence": 90,
                                                        "description": f"Verified: {potential} (200 OK)",
                                                        "timestamp": datetime.now().isoformat()
                                                    })
                                            elif is_build_artifact(potential):
                                                continue
                            except re.error:
                                pass
                except Exception as e:
                    pass
        
        if mode == "1" or mode == "7":
            console.print("[cyan]Scanning discovered endpoints with verification...[/cyan]")
            for endpoint in data.get('endpoints', []):
                if is_build_artifact(endpoint) or endpoint in verified_endpoints:
                    continue
                full_url = url.rstrip('/') + endpoint
                if verify_endpoint(full_url):
                    verified_endpoints.add(endpoint)
                    all_findings.append({
                        "finding_id": f"EP-{len(all_findings)}",
                        "cwe": "N/A",
                        "category": "endpoint",
                        "name": "Verified Discovered Endpoint",
                        "file": url,
                        "line": 0,
                        "snippet": endpoint[:200],
                        "status": "VULNERABLE",
                        "severity": "MEDIUM",
                        "confidence": 95,
                        "description": f"Verified: {endpoint} (200 OK)",
                        "timestamp": datetime.now().isoformat()
                    })
        
        if mode == "6":
            console.print("[bold red]🔥 Running Comprehensive XSS Scan...[/bold red]")
            console.print("[yellow]Testing 100+ XSS payloads across all parameters...[/yellow]")
            xss_scanner = XSSScanner(url)
            xss_results = xss_scanner.scan()
            all_findings.extend(xss_results)
            xss_scanner.render_results()
        
        if all_findings:
            console.print(f"[green]Found {len(all_findings)} verified findings[/green]")
            export_results(all_findings, "output")
        else:
            console.print("[yellow]No verified findings found[/yellow]")
            export_results([], "output")
        
        return all_findings
        
    except Exception as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        import traceback
        traceback.print_exc()
        return []
    
    finally:
        console.print(f"[dim]Temp dir: {temp_dir}[/dim]")


def render_results(results: List[Dict], mode_name: str):
    if not results:
        console.print("\n[green]✅ No vulnerabilities found![/green]")
        return
    
    severity_count = {}
    category_count = {}
    for r in results:
        severity = r.get('severity', 'MEDIUM')
        severity_count[severity] = severity_count.get(severity, 0) + 1
        category = r.get('category', 'UNKNOWN')
        category_count[category] = category_count.get(category, 0) + 1
    
    console.print(f"\n[bold cyan]📊 Scan Summary - {mode_name}[/bold cyan]")
    
    summary_table = Table(title="Findings by Severity")
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count", justify="right")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        count = severity_count.get(severity, 0)
        if count > 0:
            color = {'CRITICAL': 'red', 'HIGH': 'orange1', 'MEDIUM': 'yellow'}.get(severity, 'white')
            summary_table.add_row(f'[{color}]{severity}[/{color}]', str(count))
    console.print(summary_table)
    
    cat_table = Table(title="Findings by Category")
    cat_table.add_column("Category", style="cyan")
    cat_table.add_column("Count", justify="right")
    for category, count in sorted(category_count.items(), key=lambda x: -x[1]):
        cat_table.add_row(category, str(count))
    console.print(cat_table)
    
    console.print(f"\n[bold]📋 Detailed Findings ({len(results)})[/bold]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("ID", style="dim", width=8)
    table.add_column("Severity", width=10)
    table.add_column("Category", width=12)
    table.add_column("Location", width=25)
    table.add_column("Description", width=50)
    
    for r in results[:100]:
        severity = r.get('severity', 'MEDIUM')
        color = {'CRITICAL': 'red', 'HIGH': 'orange1', 'MEDIUM': 'yellow'}.get(severity, 'white')
        location = r.get('file', '')
        if r.get('line', 0) > 0:
            location += f":{r.get('line')}"
        table.add_row(
            r.get('finding_id', 'N/A')[:6],
            f'[{color}]{severity}[/{color}]',
            r.get('category', 'N/A')[:10],
            location[:23],
            r.get('description', 'N/A')[:48]
        )
    console.print(table)
    export_results(results, "output")
    console.print(f"\n[green]✅ Results saved to output/findings.json[/green]")


def main():
    print_banner()
    print_startup()
    print_environment()
    
    target = sys.argv[1] if len(sys.argv) > 1 else Prompt.ask("Target URL (e.g., https://example.com)")
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    choice = display_menu()
    mode_info = FEATURES[choice]
    
    console.print(f"\n[bold cyan]Mode:[/bold cyan] {mode_info['name']}")
    console.print(f"[dim]{mode_info['description']}[/dim]")
    
    if mode_info['patterns'] is None:
        all_patterns = []
        for key, feature in FEATURES.items():
            if key != "7" and feature.get('patterns'):
                all_patterns.extend(feature['patterns'])
        patterns = list(set(all_patterns))
        console.print(f"[yellow]Rules Loaded:[/yellow] {len(patterns)} (All categories)")
    else:
        patterns = mode_info['patterns']
        console.print(f"[yellow]Rules Loaded:[/yellow] {len(patterns)}")
    
    console.print("-" * 80)
    results = scan_web_url(target, choice, patterns)
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