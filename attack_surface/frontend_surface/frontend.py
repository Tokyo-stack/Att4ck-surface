"""
Frontend Surface - Frontend Assets, JavaScript Analysis, Redirects
"""

FRONTEND_RULES = [
    # 12. redirects
    {
        "id": "FRN-001",
        "category": "redirects",
        "name": "Open Redirect",
        "description": "Unvalidated redirect endpoint",
        "file_exts": [".py", ".js", ".php", ".java"],
        "vuln_patterns": [
            r"redirect\s*\(\s*request\.",
            r"res\.redirect\s*\(",
            r"redirect_to\s*=",
            r"return\s+redirect\s*\(",
            r"header\s*\(\s*['\"]Location",
        ],
        "sanitizer_patterns": [
            r"url_parse",
            r"is_safe_url",
            r"whitelist",
            r"validate_redirect",
            r"allowed_domains",
        ],
        "severity": "MEDIUM",
        "cwe": "CWE-601"
    },
    # 19. frontend-assets
    {
        "id": "FRN-002",
        "category": "frontend-assets",
        "name": "Missing SRI",
        "description": "CDN resource without Subresource Integrity",
        "file_exts": [".html", ".htm", ".js"],
        "vuln_patterns": [
            r"<script\s+src=['\"]https://cdn\.",
            r"<link\s+rel=['\"]stylesheet['\"]\s+href=['\"]https://cdn\.",
            r"src=['\"]//cdn\.",
            r"src=['\"]https://maxcdn\.",
            r"src=['\"]https://cdnjs\.",
        ],
        "sanitizer_patterns": [
            r"integrity\s*=\s*['\"]sha",
            r"crossorigin\s*=\s*['\"]anonymous['\"]",
            r"integrity=",
        ],
        "severity": "MEDIUM",
        "cwe": "CWE-829"
    },
    # 20. javascript-analysis
    {
        "id": "FRN-003",
        "category": "javascript-analysis",
        "name": "DOM XSS - innerHTML",
        "description": "Unsafe DOM manipulation with innerHTML",
        "file_exts": [".js", ".jsx", ".ts", ".tsx", ".html"],
        "vuln_patterns": [
            r"\.innerHTML\s*=",
            r"\.outerHTML\s*=",
            r"document\.write\s*\(",
            r"document\.writeln\s*\(",
            r"\.insertAdjacentHTML\s*\(",
            r"dangerouslySetInnerHTML",
            r"v-html\s*=",
            r"ng-bind-html\s*=",
            r"\.appendChild\s*\(\s*document\.createElement",
        ],
        "sanitizer_patterns": [
            r"textContent\s*=",
            r"innerText\s*=",
            r"DOMPurify",
            r"sanitize\s*\(",
            r"escape\s*\(",
            r"encodeURIComponent\s*\(",
            r"\.createTextNode\s*\(",
        ],
        "severity": "HIGH",
        "cwe": "CWE-79"
    },
    # 37. server-config
    {
        "id": "FRN-004",
        "category": "server-config",
        "name": "Wildcard CORS",
        "description": "CORS allows any domain (*)",
        "file_exts": [".py", ".js", ".conf", ".json"],
        "vuln_patterns": [
            r"Access-Control-Allow-Origin\s*:\s*\*",
            r"origin\s*:\s*['\"]\*['\"]",
            r"allow_origins\s*=\s*\[['\"]\*['\"]\]",
            r"cors\s*\(\s*\{[^}]*origin\s*:\s*['\"]\*['\"]",
        ],
        "sanitizer_patterns": [
            r"Access-Control-Allow-Origin:\s*https://",
            r"origin:\s*['\"][^'\"]+['\"]",
            r"allow_origins\s*=\s*\[[^\*]+\]",
            r"verify_origin",
        ],
        "severity": "MEDIUM",
        "cwe": "CWE-346"
    },
    # 27. logging
    {
        "id": "FRN-005",
        "category": "logging",
        "name": "Sensitive Data in Console Logs",
        "description": "Password/token logged to console",
        "file_exts": [".js", ".jsx", ".ts", ".tsx"],
        "vuln_patterns": [
            r"console\.(log|info|debug|warn|error)\s*\(\s*.*?(password|token|secret|key|credit|ssn)",
            r"console\.dir\s*\(\s*.*?(password|token|secret)",
            r"console\.table\s*\(\s*.*?(password|token|secret)",
        ],
        "sanitizer_patterns": [
            r"process\.env\.NODE_ENV\s*===?\s*['\"]development['\"]",
            r"__DEV__",
            r"logger\.(info|debug)",
            r"debug\s*\(",
        ],
        "severity": "MEDIUM",
        "cwe": "CWE-532"
    },
]