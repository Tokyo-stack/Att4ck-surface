"""
Secrets Surface - Secrets detection rules
"""

SECRETS_RULES = [
    {
        "id": "SEC-001",
        "category": "secrets",
        "name": "Hardcoded API Keys and Tokens",
        "description": "Hardcoded API key, token, or secret in client-side code",
        "file_exts": [".js", ".jsx", ".ts", ".tsx", ".json", ".env"],
        "vuln_patterns": [
            r"api[_-]?key\s*[:=]\s*['\"][^'\"]+['\"]",
            r"secret\s*[:=]\s*['\"][^'\"]+['\"]",
            r"token\s*[:=]\s*['\"][^'\"]+['\"]",
            r"password\s*[:=]\s*['\"][^'\"]+['\"]",
            r"auth\s*[:=]\s*['\"][^'\"]+['\"]",
            r"AKIA[0-9A-Z]{16}",
            r"sk-[a-zA-Z0-9]{20,}",
            r"gh[pousr]_[a-zA-Z0-9]{36,}",
            r"xox[baprs]-[a-zA-Z0-9-]+",
            r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        ],
        "sanitizer_patterns": [
            r"process\.env\.",
            r"import\.meta\.env",
            r"window\.env",
            r"REACT_APP_",
            r"NEXT_PUBLIC_",
            r"VUE_APP_",
            r"VITE_",
            r"getenv\s*\(",
            r"os\.getenv",
            r"dotenv",
        ],
        "severity": "CRITICAL",
        "cwe": "CWE-798"
    },
]