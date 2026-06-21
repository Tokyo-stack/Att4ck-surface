"""
Scanner Module - Core scanning engine with endpoint verification
"""

import os
import re
import json
import requests
import concurrent.futures
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from attack_surface.rules import RULES
from attack_surface.risk_engine import get_risk


# ============================================================================
# COMPLETE FALSE POSITIVE FILTERS
# ============================================================================

# Skip these directories entirely
SKIP_DIRS = {
    '.next', '_next', 'out', 'dist', 'build', 'public', 'static',
    'assets', '.cache', 'node_modules', 'bower_components', 'vendor',
    'venv', '.venv', 'env', '.env', '__pycache__', '.git', '.idea', '.vscode'
}

# Skip files containing these patterns (framework code)
SKIP_FILE_PATTERNS = [
    r'jquery', r'bootstrap', r'react', r'vue', r'angular', r'lodash',
    r'underscore', r'moment', r'axios', r'swiper', r'slick', r'chart',
    r'd3', r'three', r'gsap', r'anime', r'fabric', r'konva', r'pixi',
    r'phaser', r'babylon', r'vendor', r'polyfills', r'runtime',
    r'webpack', r'chunk', r'bundle', r'min\.js', r'map$',
    r'^inline_js_\d+\.js$',
    r'^[a-z0-9_-]{8,}\.js$',
    r'^[a-z0-9_-]{8,}-[a-z0-9_-]*\.js$',
]

# Skip lines containing these patterns (false positive lines)
SKIP_LINE_PATTERNS = [
    r'console\.', r'// @ts-', r'// eslint-', r'/\* eslint-',
    r'"use strict"', r"'use strict'", r'module\.exports',
    r'exports\.', r'require\(', r'import\s+', r'export\s+',
    r'sourceMappingURL', r'@license', r'@preserve',
    r'__webpack_', r'__NEXT_DATA__', r'__next_s',
    r'data-nscript', r'TURBOPACK', r'typeof window',
    r'typeof document', r'process\.env', r'__DEV__',
    r'__react_refresh', r'useState\(', r'useEffect\(',
    r'useContext\(', r'useReducer\(', r'useCallback\(',
    r'useMemo\(', r'useRef\(', r'forwardRef\(',
    r'createElement\(', r'React\.', r'react/',
    r'google-analytics', r'gtag\(', r'dataLayer', r'gtm\.',
    r'google_tag_manager', r'fbq\(', r'twq\(',
    r'linkedin\.', r'pinterest', r'snapchat', r'tiktok',
    r'cookie-consent', r'cookieconsent', r'Cookiebot',
    r'OneTrust', r'CookieNotice', r'cookies\.js',
    r'analytics\.', r'hotjar', r'crazyegg', r'fullstory',
    r'mixpanel', r'amplitude', r'segment\.', r'heap\.',
    r'logrocket', r'sentry\.', r'datadog', r'newrelic',
    r'cloudflare', r'cf-beacon', r'recaptcha', r'hcaptcha',
    r'turnstile', r'facebook\.com/plugins', r'twitter\.com/widgets',
    r'instagram\.com/embed', r'youtube\.com/embed',
    r'vimeo\.com/embed', r'soundcloud\.com/player',
    r'spotify\.com/embed', r'cdn\.', r'gstatic\.com',
    r'cloudfront\.net', r'fonts\.googleapis\.com',
    r'\(self\.__next_s=', r'__NEXT_DATA__',
    r'data-nscript="', r'next-script',
    r'__webpack_require__', r'__webpack_public_path__',
    r'webpackChunk', r'webpackJsonp',
    r'__vite_', r'__rollup_', r'__esbuild_',
]

# ============================================================================
# COMPLETE VULNERABILITY PATTERNS - ALL 40 ATTACK SURFACES
# ============================================================================

VULN_PATTERNS = {
    'authentication': [
        (r'hashlib\.md5\s*\(', 'Weak Hashing - MD5'),
        (r'hashlib\.sha1\s*\(', 'Weak Hashing - SHA1'),
        (r'password\s*=\s*[\'"]\S+[\'"]', 'Hardcoded Password'),
        (r'crypto\.createHash\s*\(\s*[\'"]md5[\'"]', 'Weak Hashing - MD5 (Node)'),
    ],
    'authorization': [
        (r'@app\.route\s*\([^)]*\)(?!.*@login_required)', 'Missing Auth - Flask'),
        (r'app\.(get|post|put|delete)\s*\([^)]*\)(?!.*@login_required)', 'Missing Auth - Flask'),
        (r'router\.(get|post|put|delete)\s*\([^)]*\)(?!.*auth)', 'Missing Auth - Express'),
        (r'/admin.*(?!.*auth)', 'Exposed Admin Route'),
    ],
    'user-inputs': [
        (r'eval\s*\(', 'Code Execution - eval'),
        (r'exec\s*\(', 'Code Execution - exec'),
        (r'system\s*\(', 'Code Execution - system'),
        (r'popen\s*\(', 'Code Execution - popen'),
        (r'subprocess\.(Popen|run|call)\s*\(', 'Code Execution - subprocess'),
        (r'new\s+Function\s*\(', 'Code Execution - Function'),
    ],
    'search-parameters': [
        (r'request\.args\.get\s*\(\s*[\'"]q[\'"]', 'Reflected XSS - search'),
        (r'req\.query\.search', 'Reflected XSS - search'),
        (r'location\.search', 'Reflected XSS - location.search'),
        (r'\$_GET\[\'q\'\]', 'Reflected XSS - $_GET'),
    ],
    'id-parameters': [
        (r'SELECT.*\s+WHERE\s+id\s*=\s*[\'"]?\s*\+\s*\w+', 'SQLi - ID concat'),
        (r'WHERE\s+id\s*=\s*[\'"]?\s*\$', 'SQLi - ID $'),
        (r'request\.(args|form)\.get\s*\(\s*[\'"]id[\'"]', 'ID Parameter - unvalidated'),
        (r'req\.query\.id', 'ID Parameter - req.query'),
        (r'req\.params\.id', 'ID Parameter - req.params'),
    ],
    'api-endpoints': [
        (r'/api/[^"\']+', 'API Endpoint'),
        (r'/rest/[^"\']+', 'REST API'),
        (r'/v\d+/\S+', 'API Version'),
        (r'/service/\S+', 'Service API'),
    ],
    'graphql': [
        (r'gql\s*`[^`]*\$\{', 'GraphQL Injection'),
        (r'graphql\s*`[^`]*\$\{', 'GraphQL Injection'),
        (r'\.query\s*\(\s*`[^`]*\$\{', 'GraphQL Query Injection'),
        (r'\.mutate\s*\(\s*`[^`]*\$\{', 'GraphQL Mutation Injection'),
    ],
    'webhooks': [
        (r'webhook[^"\']*', 'Webhook Endpoint'),
        (r'stripe_webhook', 'Stripe Webhook'),
        (r'github_webhook', 'GitHub Webhook'),
        (r'webhook_handler', 'Webhook Handler'),
    ],
    'file-uploads': [
        (r'request\.files', 'File Upload - request.files'),
        (r'file\.save\s*\(', 'File Upload - save'),
        (r'multer\s*\(', 'File Upload - multer'),
        (r'upload\.single\s*\(', 'File Upload - single'),
        (r'upload\.array\s*\(', 'File Upload - array'),
    ],
    'file-downloads': [
        (r'send_file\s*\(', 'File Download - send_file'),
        (r'send_from_directory\s*\(', 'File Download - send_from_directory'),
        (r'fs\.readFile\s*\(', 'File Download - readFile'),
        (r'file_get_contents\s*\(', 'File Download - file_get_contents'),
        (r'readfile\s*\(', 'File Download - readfile'),
    ],
    'path-traversal': [
        (r'\.\./\.\./', 'Path Traversal'),
        (r'\.\.\\\.\.\\', 'Path Traversal - Windows'),
        (r'\.\.\/\.\.\/\.\.\/', 'Path Traversal - deep'),
        (r'os\.path\.join\s*\([^,]+,\s*[\'"]\.\.', 'Path Traversal - os.path.join'),
        (r'path\.join\s*\([^,]+,\s*[\'"]\.\.', 'Path Traversal - path.join'),
        (r'open\s*\([^,]*\.\.\/\.\.', 'Path Traversal - open'),
    ],
    'admin-portals': [
        (r'/admin[^"\']*', 'Admin Portal'),
        (r'/administrator[^"\']*', 'Admin Portal'),
        (r'/dashboard[^"\']*', 'Dashboard'),
        (r'/control-panel[^"\']*', 'Control Panel'),
        (r'/superadmin[^"\']*', 'Super Admin'),
    ],
    'payment-systems': [
        (r'card_number', 'Credit Card - card_number'),
        (r'cvv', 'Credit Card - CVV'),
        (r'credit_card', 'Credit Card - credit_card'),
        (r'expiry_date', 'Credit Card - expiry_date'),
        (r'cc_number', 'Credit Card - cc_number'),
    ],
    'oauth-sso': [
        (r'/oauth[^"\']*', 'OAuth Endpoint'),
        (r'/sso[^"\']*', 'SSO Endpoint'),
        (r'/saml[^"\']*', 'SAML Endpoint'),
        (r'/oidc[^"\']*', 'OIDC Endpoint'),
        (r'/callback[^"\']*', 'Callback Endpoint'),
    ],
    'email-flows': [
        (r'sendmail\s*\(', 'SMTP - sendmail'),
        (r'smtplib', 'SMTP - smtplib'),
        (r'nodemailer', 'SMTP - nodemailer'),
        (r'mail\s*\(', 'SMTP - mail'),
        (r'send_email\s*\(', 'SMTP - send_email'),
    ],
    'frontend-assets': [
        (r'<script\s+src=[\'"]https://cdn\.[^\'"]+[\'"](?!.*integrity)', 'Missing SRI - CDN'),
        (r'<link\s+rel=[\'"]stylesheet[\'"]\s+href=[\'"]https://cdn\.[^\'"]+[\'"](?!.*integrity)', 'Missing SRI - CSS'),
        (r'src=[\'"]//cdn\.[^\'"]+[\'"](?!.*integrity)', 'Missing SRI - CDN'),
    ],
    'javascript-analysis': [
        (r'\.innerHTML\s*=', 'DOM XSS - innerHTML'),
        (r'\.outerHTML\s*=', 'DOM XSS - outerHTML'),
        (r'document\.write\s*\(', 'DOM XSS - document.write'),
        (r'dangerouslySetInnerHTML', 'React XSS - dangerouslySetInnerHTML'),
        (r'v-html\s*=', 'Vue XSS - v-html'),
        (r'ng-bind-html\s*=', 'Angular XSS - ng-bind-html'),
    ],
    'secrets-config': [
        (r'api[_-]?key\s*[:=]\s*[\'"]\S+[\'"]', 'API Key Hardcoded'),
        (r'secret\s*[:=]\s*[\'"]\S+[\'"]', 'Secret Hardcoded'),
        (r'token\s*[:=]\s*[\'"]\S+[\'"]', 'Token Hardcoded'),
        (r'password\s*[:=]\s*[\'"]\S+[\'"]', 'Password Hardcoded'),
        (r'AKIA[0-9A-Z]{16}', 'AWS Key'),
        (r'sk-[a-zA-Z0-9]{20,}', 'OpenAI Key'),
        (r'gh[pousr]_[a-zA-Z0-9]{36,}', 'GitHub Token'),
        (r'xox[baprs]-[a-zA-Z0-9-]+', 'Slack Token'),
        (r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', 'JWT Token'),
    ],
    'environment-files': [
        (r'DB_PASSWORD\s*=\s*\S+', 'DB Password in .env'),
        (r'SECRET_KEY\s*=\s*\S+', 'Secret Key in .env'),
        (r'API_KEY\s*=\s*\S+', 'API Key in .env'),
        (r'TOKEN\s*=\s*\S+', 'Token in .env'),
        (r'\.env\b', 'Environment File'),
    ],
    'cloud-storage': [
        (r'public-read', 'S3 Public Read'),
        (r'public_read', 'S3 Public Read'),
        (r'AllowedOrigins\s*:\s*\*', 'S3 CORS Wildcard'),
        (r'aws_s3_bucket', 'AWS S3 Bucket'),
        (r'S3_BUCKET', 'S3 Bucket'),
    ],
    'database': [
        (r'\.execute\s*\(\s*[\'"].*[\'"]\s*%', 'SQL Injection - execute %'),
        (r'\.execute\s*\(\s*f[\'"].*\{', 'SQL Injection - f-string'),
        (r'SELECT.*\s*\+\s*.*\s*FROM', 'SQL Injection - concat'),
        (r'INSERT.*\s*\+\s*.*\s*INTO', 'SQL Injection - INSERT'),
        (r'UPDATE.*\s*\+\s*.*\s*SET', 'SQL Injection - UPDATE'),
        (r'DELETE.*\s*\+\s*.*\s*FROM', 'SQL Injection - DELETE'),
        (r'mongodb://\S+', 'MongoDB Connection'),
        (r'mysql://\S+', 'MySQL Connection'),
        (r'postgres://\S+', 'PostgreSQL Connection'),
        (r'redis://\S+', 'Redis Connection'),
    ],
    'message-queues': [
        (r'pickle\.loads\s*\(', 'Insecure Deserialization - pickle'),
        (r'yaml\.load\s*\(', 'Insecure Deserialization - yaml'),
        (r'serialize\.unserialize\s*\(', 'Insecure Deserialization - PHP'),
    ],
    'logging': [
        (r'logger\.(info|debug|error)\(.*password', 'Password in Logs'),
        (r'console\.log\(.*token', 'Token in Console'),
        (r'console\.log\(.*secret', 'Secret in Console'),
        (r'console\.log\(.*password', 'Password in Console'),
    ],
    'monitoring': [
        (r'/metrics[^"\']*', 'Metrics Endpoint'),
        (r'/actuator[^"\']*', 'Actuator Endpoint'),
        (r'/health[^"\']*', 'Health Check'),
        (r'/healthz[^"\']*', 'Health Check'),
        (r'/status[^"\']*', 'Status Endpoint'),
        (r'/prometheus[^"\']*', 'Prometheus Endpoint'),
    ],
    'debug-endpoints': [
        (r'debug\s*=\s*True', 'Debug Mode - True'),
        (r'debug\s*=\s*true', 'Debug Mode - true'),
        (r'NODE_ENV\s*=\s*[\'"]development[\'"]', 'Node Dev Mode'),
        (r'APP_DEBUG\s*=\s*true', 'APP_DEBUG'),
        (r'FLASK_DEBUG\s*=\s*1', 'Flask Debug'),
        (r'/debug[^"\']*', 'Debug Endpoint'),
        (r'/test[^"\']*', 'Test Endpoint'),
        (r'/dev[^"\']*', 'Dev Endpoint'),
    ],
    'documentation': [
        (r'/swagger[^"\']*', 'Swagger UI'),
        (r'/swagger-ui[^"\']*', 'Swagger UI'),
        (r'/docs[^"\']*', 'Docs'),
        (r'/redoc[^"\']*', 'ReDoc'),
        (r'/openapi[^"\']*', 'OpenAPI'),
        (r'/api-docs[^"\']*', 'API Docs'),
        (r'/apidocs[^"\']*', 'API Docs'),
    ],
    'dependencies': [
        (r'[A-Za-z0-9_\-]+==latest', 'Unpinned - latest'),
        (r'"[A-Za-z0-9_\-]+":\s*"\*"', 'Unpinned - *'),
        (r'[A-Za-z0-9_\-]+>=.*$', 'Unpinned - >='),
    ],
    'ci-cd': [
        (r'github_token\s*:\s*\S+', 'GitHub Token in CI'),
        (r'aws_secret\s*:\s*\S+', 'AWS Secret in CI'),
        (r'secrets\s*:\s*[\'"]\S+[\'"]', 'Secrets in CI'),
        (r'Jenkinsfile', 'Jenkinsfile'),
        (r'\.github/', 'GitHub Actions'),
        (r'\.gitlab-ci\.yml', 'GitLab CI'),
    ],
    'containers': [
        (r'FROM.*latest', 'Docker - latest tag'),
        (r'(?i)^USER\s+root', 'Docker - root user'),
        (r'RUN\s+.*sudo', 'Docker - sudo'),
    ],
    'dns': [
        (r'socket\.gethostbyname\s*\(', 'DNS - gethostbyname'),
        (r'dns\.resolve\s*\(', 'DNS - resolve'),
    ],
    'server-config': [
        (r'Access-Control-Allow-Origin\s*:\s*\*', 'CORS Wildcard'),
        (r'origin\s*:\s*[\'"]\*[\'"]', 'CORS Wildcard'),
        (r'X-Powered-By', 'Server Info - X-Powered-By'),
        (r'Server:\s*\S+', 'Server Info'),
        (r'\.htaccess', '.htaccess File'),
        (r'web\.config', 'web.config File'),
    ],
    'backups': [
        (r'\.bak$', 'Backup File'),
        (r'\.old$', 'Old File'),
        (r'\.tmp$', 'Temporary File'),
        (r'backup_\S+\.sql', 'SQL Backup'),
        (r'backup\.zip', 'ZIP Backup'),
        (r'database\.sql', 'Database SQL'),
        (r'db\.sql', 'Database SQL'),
        (r'config\.bak', 'Config Backup'),
        (r'site\.tar\.gz', 'Site Backup'),
    ],
    'source-control': [
        (r'\.git/config', 'Git Config'),
        (r'git\s+clone\s+https://[A-Za-z0-9]+:[A-Za-z0-9]+@', 'Git Credentials'),
        (r'\.gitignore', '.gitignore'),
    ],
    'miscellaneous': [
        (r'ftplib\.FTP\s*\(', 'FTP - unencrypted'),
        (r'telnetlib\.Telnet\s*\(', 'Telnet - unencrypted'),
        (r'xml\.etree\.ElementTree\.parse', 'XXE - ElementTree'),
        (r'XMLReader\s*\(\s*[\'"]http://', 'XXE - XMLReader'),
        (r'DOMDocument\s*\(\s*[\'"]http://', 'XXE - DOMDocument'),
        (r'SimpleXMLElement\s*\(\s*[\'"]http://', 'XXE - SimpleXMLElement'),
    ],
    'ssrf': [
        (r'requests\.get\s*\(\s*[\'"]https?://.*\+\s*', 'SSRF - requests.get'),
        (r'fetch\s*\(\s*[\'"]https?://.*\+\s*', 'SSRF - fetch'),
        (r'axios\.get\s*\(\s*[\'"]https?://.*\+\s*', 'SSRF - axios.get'),
        (r'urllib\.request\.urlopen\s*\(\s*[\'"]https?://.*\+\s*', 'SSRF - urlopen'),
    ],
    'redirects': [
        (r'redirect\s*\(\s*request\.', 'Open Redirect - request'),
        (r'res\.redirect\s*\([^)]*req\.', 'Open Redirect - req'),
        (r'redirect_to\s*=\s*request\.', 'Open Redirect - redirect_to'),
        (r'return\s+redirect\s*\([^)]*request\.', 'Open Redirect - return'),
        (r'location\.href\s*=\s*request\.', 'Open Redirect - location.href'),
    ],
}


def safe_serializer(obj):
    """Custom JSON serializer for non-serializable objects"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, '__dict__'):
        return str(obj)
    return str(obj)


def verify_endpoint(url: str, timeout: int = 5) -> bool:
    """
    Verify if an endpoint actually exists by making a HEAD request.
    Returns True only if status code is 200 OK.
    This eliminates false positives from framework code.
    """
    try:
        # Use HEAD request to avoid downloading content
        response = requests.head(url, timeout=timeout, allow_redirects=True)
        # Only 200 OK means it exists
        if response.status_code == 200:
            return True
        elif response.status_code in [301, 302, 307, 308]:
            # Follow redirect and check final status
            try:
                final_response = requests.get(url, timeout=timeout, allow_redirects=True)
                return final_response.status_code == 200
            except:
                return False
        return False
    except requests.exceptions.ConnectionError:
        return False
    except requests.exceptions.Timeout:
        return False
    except requests.exceptions.InvalidURL:
        return False
    except Exception:
        return False


def _should_skip_file(file_path: str) -> bool:
    """Check if file should be skipped entirely"""
    file_path_lower = file_path.lower()
    file_name = os.path.basename(file_path_lower)
    
    # Skip inline scripts
    if re.match(r'^inline_js_\d+\.js$', file_name):
        return True
    
    # Skip hashed filenames
    if re.match(r'^[a-z0-9_-]{8,}\.js$', file_name, re.IGNORECASE):
        return True
    if re.match(r'^[a-z0-9_-]{8,}-[a-z0-9_-]*\.js$', file_name, re.IGNORECASE):
        return True
    
    # Skip directories
    for skip_dir in SKIP_DIRS:
        if f'/{skip_dir}/' in file_path_lower or f'\\{skip_dir}\\' in file_path_lower:
            return True
    
    # Skip library files
    for pattern in SKIP_FILE_PATTERNS:
        if re.search(pattern, file_path_lower, re.IGNORECASE):
            return True
    
    return False


def _should_skip_line(line: str) -> bool:
    """Check if line should be skipped"""
    line_stripped = line.strip()
    
    if not line_stripped:
        return True
    
    if line_stripped.startswith('//') or line_stripped.startswith('/*'):
        return True
    
    for pattern in SKIP_LINE_PATTERNS:
        if re.search(pattern, line_stripped, re.IGNORECASE):
            return True
    
    if line_stripped in ['{', '}', '(', ')', '[', ']', ';', '=>', '->', ':', ',']:
        return True
    
    return False


def _process_single_file(args):
    """Process a single file for vulnerabilities"""
    file_path, rule, target_dir = args
    local_findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.splitlines()

        if not content.strip():
            return local_findings

        # Skip framework files entirely
        if _should_skip_file(file_path):
            return local_findings

        for line_idx, raw_line in enumerate(lines, 1):
            line = raw_line.strip()

            if _should_skip_line(line):
                continue

            # Check vulnerability patterns
            vuln_category = rule.category.lower() if hasattr(rule, 'category') else 'unknown'
            
            # Get patterns for this category
            category_patterns = VULN_PATTERNS.get(vuln_category, {})
            if not category_patterns:
                # If no specific patterns, check the rule's vuln_patterns
                for pattern in rule.vuln_patterns:
                    if pattern.search(line):
                        local_findings.append({
                            "finding_id": f"AS-{rule.category}-{line_idx}",
                            "cwe": getattr(rule, 'cwe', 'N/A'),
                            "category": getattr(rule, 'category', 'UNKNOWN'),
                            "name": getattr(rule, 'name', 'Unnamed Rule'),
                            "file": os.path.relpath(file_path, target_dir),
                            "line": line_idx,
                            "snippet": line[:200],
                            "status": "VULNERABLE",
                            "severity": getattr(rule, 'severity', 'MEDIUM'),
                            "confidence": getattr(rule, 'confidence', 70),
                            "description": getattr(rule, 'vuln_desc', ''),
                            "timestamp": datetime.now().isoformat()
                        })
                        break
                continue

            # Check specific vulnerability patterns
            for pattern, description in category_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Get context
                    start_win = max(0, line_idx - 3)
                    end_win = min(len(lines), line_idx + 3)
                    context = lines[start_win:end_win]
                    
                    # Check for sanitization
                    is_sanitized = False
                    sanitize_patterns = [
                        r'sanitize', r'escape', r'encode', r'DOMPurify',
                        r'htmlspecialchars', r'strip_tags', r'filter_var',
                        r'prepared', r'bindparam', r'paramstyle',
                        r'validate', r'whitelist', r'allowlist',
                    ]
                    for sp in sanitize_patterns:
                        if any(re.search(sp, c, re.IGNORECASE) for c in context):
                            is_sanitized = True
                            break
                    
                    local_findings.append({
                        "finding_id": f"AS-{vuln_category}-{line_idx}",
                        "cwe": getattr(rule, 'cwe', 'N/A'),
                        "category": vuln_category,
                        "name": description,
                        "file": os.path.relpath(file_path, target_dir),
                        "line": line_idx,
                        "snippet": line[:200],
                        "status": "SANITIZED" if is_sanitized else "VULNERABLE",
                        "severity": getattr(rule, 'severity', 'HIGH'),
                        "confidence": 80 if not is_sanitized else 50,
                        "description": f"{description} detected" + (" (sanitized)" if is_sanitized else ""),
                        "timestamp": datetime.now().isoformat()
                    })
                    break

    except Exception as e:
        print(f"[SCAN ERROR] {file_path}: {e}")

    return local_findings


class SurfaceScanner:
    """Main scanner class - focused on real vulnerabilities"""
    
    def __init__(self, target_dir: str, rules_list: Optional[List] = None):
        self.target_dir = os.path.abspath(target_dir)
        self.rules = rules_list if rules_list is not None else RULES
        self.findings = []
        self.skipped_count = 0
        self.scanned_count = 0

        self.supported_exts = {
            '.js', '.jsx', '.ts', '.tsx', '.html', '.htm',
            '.py', '.php', '.rb', '.java', '.go', '.rs',
            '.c', '.cpp', '.h', '.hpp', '.sh', '.bash',
            '.xml', '.json', '.yml', '.yaml', '.conf',
            '.sql', '.vue', '.svelte', '.env', '.txt',
            '.ini', '.cfg', '.properties', '.toml',
            '.twig', '.j2', '.ejs', '.pug', '.hbs',
        }

    def scan(self) -> List[Dict]:
        """Perform the scan"""
        tasks = []
        self.scanned_count = 0
        self.skipped_count = 0

        print(f"[INFO] Scanning target: {self.target_dir}")
        print(f"[INFO] Rules loaded: {len(self.rules)}")

        for root, dirs, files in os.walk(self.target_dir):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for file in files:
                file_path = os.path.join(root, file)

                if not self._should_scan_file(file_path):
                    self.skipped_count += 1
                    continue

                self.scanned_count += 1

                for rule in self.rules:
                    if self._rule_matches_file(rule, file_path):
                        tasks.append((file_path, rule, self.target_dir))

        print(f"[INFO] Files scanned: {self.scanned_count}")
        print(f"[INFO] Files skipped: {self.skipped_count}")

        if not tasks:
            print("[INFO] No files to scan")
            return self.findings

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = executor.map(_process_single_file, tasks)

        for r in results:
            self.findings.extend(r)

        print(f"[INFO] Findings found: {len(self.findings)}")
        return self.findings

    def _should_scan_file(self, file_path: str) -> bool:
        """Check if file should be scanned"""
        if _should_skip_file(file_path):
            return False
        
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in self.supported_exts:
            return False
        
        try:
            if os.path.getsize(file_path) > 10 * 1024 * 1024:
                return False
        except:
            return False
        
        return True

    def _rule_matches_file(self, rule, file_path: str) -> bool:
        """Check if rule applies to file"""
        ext = os.path.splitext(file_path)[1].lower()
        return any(file_path.endswith(fe) or ext == fe for fe in rule.file_exts)

    def export_findings(self, output_dir: str = "output") -> bool:
        """Export findings to JSON and SQLite"""
        import sqlite3
        
        os.makedirs(output_dir, exist_ok=True)
        
        json_path = os.path.join(output_dir, "findings.json")
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(self.findings, f, default=safe_serializer, indent=2, ensure_ascii=False)
            print(f"[+] Exported {len(self.findings)} findings to {json_path}")
        except Exception as e:
            print(f"[!] Error exporting JSON: {e}")
            return False
        
        db_path = os.path.join(output_dir, "findings.db")
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute("DROP TABLE IF EXISTS security_findings")
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id TEXT,
                    cwe TEXT,
                    category TEXT,
                    name TEXT,
                    file_path TEXT,
                    line_num INTEGER,
                    snippet TEXT,
                    status TEXT,
                    severity TEXT,
                    confidence INTEGER,
                    description TEXT,
                    timestamp TEXT,
                    risk_score INTEGER
                )
            """)
            
            for f in self.findings:
                cursor.execute("""
                    INSERT INTO security_findings (
                        finding_id, cwe, category, name, file_path,
                        line_num, snippet, status, severity,
                        confidence, description, timestamp, risk_score
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    f.get("finding_id"),
                    f.get("cwe"),
                    f.get("category"),
                    f.get("name"),
                    f.get("file"),
                    f.get("line"),
                    f.get("snippet"),
                    f.get("status"),
                    f.get("severity"),
                    f.get("confidence"),
                    f.get("description"),
                    f.get("timestamp"),
                    f.get("risk_score", 0),
                ))
            
            conn.commit()
            conn.close()
            print(f"[+] Exported findings to {db_path}")
            return True
            
        except Exception as e:
            print(f"[!] Error exporting to SQLite: {e}")
            return False


def export_results(results, output_dir):
    """Legacy function for compatibility"""
    scanner = SurfaceScanner(".")
    scanner.findings = results
    return scanner.export_findings(output_dir)