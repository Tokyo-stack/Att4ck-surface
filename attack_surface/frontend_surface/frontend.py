"""
Frontend Surface - Frontend Assets, JavaScript Analysis, Redirects
"""

FRONTEND_RULES = [
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
]