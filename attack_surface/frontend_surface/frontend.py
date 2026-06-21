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
        ],
        "sanitizer_patterns": [
            r"url_parse",
            r"is_safe_url",
            r"whitelist",
            r"validate_redirect",
        ],
        "severity": "MEDIUM",
        "cwe": "CWE-601"
    },
    # 20. javascript-analysis
    {
        "id": "FRN-002",
        "category": "javascript-analysis",
        "name": "DOM XSS - innerHTML",
        "description": "Unsafe DOM manipulation with innerHTML",
        "file_exts": [".js", ".jsx", ".ts", ".tsx", ".html"],
        "vuln_patterns": [
            r"\.innerHTML\s*=",
            r"\.outerHTML\s*=",
            r"document\.write\s*\(",
            r"\.insertAdjacentHTML\s*\(",
            r"dangerouslySetInnerHTML",
            r"v-html\s*=",
            r"ng-bind-html\s*=",
        ],
        "sanitizer_patterns": [
            r"textContent\s*=",
            r"innerText\s*=",
            r"DOMPurify",
            r"sanitize\s*\(",
            r"escape\s*\(",
            r"encodeURIComponent\s*\(",
        ],
        "severity": "HIGH",
        "cwe": "CWE-79"
    },
]