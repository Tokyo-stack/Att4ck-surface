"""
Secrets Surface - Secrets Config, Environment Files, Server Config, Source Control
"""

SECRETS_RULES = [
    # 21. secrets-config
    {
        "id": "SEC-001",
        "category": "secrets-config",
        "name": "Hardcoded Secrets in Config",
        "description": "API keys/tokens in config files",
        "file_exts": [".json", ".ini", ".conf", ".yml", ".yaml", ".xml"],
        "vuln_patterns": [
            r"(?i)(api_key|apikey|secret|token|password|key|auth)\s*[:=]\s*['\"][^'\"]+['\"]",
            r"\"apiKey\"\s*:\s*\"[^\"]+\"",
            r"\"secret\"\s*:\s*\"[^\"]+\"",
            r"\"token\"\s*:\s*\"[^\"]+\"",
        ],
        "sanitizer_patterns": [
            r"\{\{.*\}\}",
            r"\$.*",
            r"ENV_",
            r"process\.env",
            r"os\.getenv",
            r"\${",
        ],
        "severity": "CRITICAL",
        "cwe": "CWE-798"
    },
    # 22. environment-files
    {
        "id": "SEC-002",
        "category": "environment-files",
        "name": "Secrets in Environment Files",
        "description": "Secrets stored in .env files",
        "file_exts": [".env", ".env.example", ".env.local", ".env.production"],
        "vuln_patterns": [
            r"(?i)(DB_PASSWORD|SECRET_KEY|API_KEY|TOKEN)\s*=\s*[A-Za-z0-9_\-]+",
            r"(?i)(PASSWORD|SECRET|KEY)\s*=\s*[A-Za-z0-9_\-]{10,}",
        ],
        "sanitizer_patterns": [
            r"YOUR_",
            r"ENTER_",
            r"CHANGEME",
            r"EXAMPLE_",
            r"PLACEHOLDER",
        ],
        "severity": "CRITICAL",
        "cwe": "CWE-798"
    },
    # 37. server-config
    {
        "id": "SEC-003",
        "category": "server-config",
        "name": "CORS Wildcard",
        "description": "Wildcard CORS allows any domain",
        "file_exts": [".py", ".js", ".conf", ".json"],
        "vuln_patterns": [
            r"Access-Control-Allow-Origin\s*:\s*\*",
            r"origin\s*:\s*['\"]\*['\"]",
            r"allow_origins\s*=\s*\[['\"]\*['\"]\]",
        ],
        "sanitizer_patterns": [
            r"Access-Control-Allow-Origin:\s*https://",
            r"origin:\s*['\"][^'\"]+['\"]",
            r"allow_origins\s*=\s*\[[^\*]+\]",
        ],
        "severity": "MEDIUM",
        "cwe": "CWE-346"
    },
    # 39. source-control
    {
        "id": "SEC-004",
        "category": "source-control",
        "name": "Credentials in Git",
        "description": "Credentials exposed in version control",
        "file_exts": [".py", ".js", ".sh", ".yml"],
        "vuln_patterns": [
            r"\.git/config",
            r"git\s+clone\s+https://[A-Za-z0-9]+:[A-Za-z0-9]+@",
            r"git\s+push\s+https://[A-Za-z0-9]+:[A-Za-z0-9]+@",
        ],
        "sanitizer_patterns": [
            r"ssh://",
            r"git_token",
            r"\.gitcredentials",
            r"GIT_ASKPASS",
        ],
        "severity": "HIGH",
        "cwe": "CWE-312"
    },
    # Cloud provider keys
    {
        "id": "SEC-005",
        "category": "secrets-config",
        "name": "Cloud Provider API Keys",
        "description": "AWS, OpenAI, GitHub, Slack keys exposed",
        "file_exts": [".py", ".js", ".json", ".yml", ".env"],
        "vuln_patterns": [
            r"AKIA[0-9A-Z]{16}",
            r"sk-[a-zA-Z0-9]{20,}",
            r"gh[pousr]_[a-zA-Z0-9]{36,}",
            r"xox[baprs]-[a-zA-Z0-9-]+",
            r"AIza[0-9A-Za-z\\-_]{35}",
            r"SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}",
        ],
        "sanitizer_patterns": [
            r"process\.env\.",
            r"os\.getenv",
            r"import\.meta\.env",
        ],
        "severity": "CRITICAL",
        "cwe": "CWE-798"
    },
    # JWT tokens
    {
        "id": "SEC-006",
        "category": "secrets-config",
        "name": "JWT Tokens in Code",
        "description": "JWT tokens hardcoded in code",
        "file_exts": [".py", ".js", ".json"],
        "vuln_patterns": [
            r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
            r"jwt\s*[:=]\s*['\"][^'\"]+['\"]",
        ],
        "sanitizer_patterns": [
            r"process\.env\.",
            r"os\.getenv",
            r"jwt\.verify",
        ],
        "severity": "HIGH",
        "cwe": "CWE-798"
    },
]