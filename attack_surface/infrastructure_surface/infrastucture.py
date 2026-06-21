"""
Infrastructure Surface - Containers, CI/CD, Dependencies, DNS
"""

INFRASTRUCTURE_RULES = [
    # 32. dependencies
    {
        "id": "INF-001",
        "category": "dependencies",
        "name": "Unpinned Dependencies",
        "description": "Dependencies without version pinning",
        "file_exts": [".txt", ".json", ".lock", ".toml"],
        "vuln_patterns": [
            r"^[A-Za-z0-9_\-]+==latest",
            r"\"[A-Za-z0-9_\-]+\":\s*\"\*\"",
            r"^[A-Za-z0-9_\-]+>=.*$",
            r"^[A-Za-z0-9_\-]+<.*$",
        ],
        "sanitizer_patterns": [
            r"==[0-9\.]+",
            r"\"[0-9\.]+\"",
            r"~=[0-9\.]+",
            r"^[0-9\.]+$",
        ],
        "severity": "MEDIUM",
        "cwe": "CWE-1104"
    },
    # 33. ci-cd
    {
        "id": "INF-002",
        "category": "ci-cd",
        "name": "Hardcoded Tokens in CI/CD",
        "description": "Tokens hardcoded in GitHub Actions",
        "file_exts": [".yml", ".yaml"],
        "vuln_patterns": [
            r"github_token\s*:\s*[A-Za-z0-9]+",
            r"aws_secret\s*:\s*[A-Za-z0-9]+",
            r"secrets\s*:\s*['\"][^'\"]+['\"]",
            r"ACCESS_TOKEN",
            r"GH_TOKEN",
        ],
        "sanitizer_patterns": [
            r"secrets\.",
            r"\$\{\{.*\}\}",
            r"env\.",
            r"SECRET_",
        ],
        "severity": "CRITICAL",
        "cwe": "CWE-798"
    },
    # 38. containers
    {
        "id": "INF-003",
        "category": "containers",
        "name": "Insecure Docker Configuration",
        "description": "Dockerfile using latest tag or running as root",
        "file_exts": ["Dockerfile", ".dockerfile"],
        "vuln_patterns": [
            r"FROM.*latest",
            r"(?i)^USER\s+root",
            r"RUN\s+.*sudo",
            r"ADD\s+.*\.tar\.gz",
        ],
        "sanitizer_patterns": [
            r"FROM.*@sha256:",
            r"USER\s+[A-Za-z0-9_\-]+",
            r"USER\s+[0-9]+",
            r"FROM.*:[0-9]+\.[0-9]+\.[0-9]+",
        ],
        "severity": "HIGH",
        "cwe": "CWE-269"
    },
    # 35. subdomains - already in api.py
    # 36. dns - already in api.py
]