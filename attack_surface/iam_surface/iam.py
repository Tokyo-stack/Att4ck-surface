"""
IAM Surface - Authentication, Authorization, Session Management
"""

IAM_RULES = [
    # 1. authentication
    {
        "id": "IAM-001",
        "category": "authentication",
        "name": "Weak Hashing Algorithm",
        "description": "MD5/SHA1 hashing detected - use bcrypt, Argon2, or PBKDF2",
        "file_exts": [".py", ".js", ".java", ".go", ".php"],
        "vuln_patterns": [
            r"hashlib\.md5\s*\(",
            r"hashlib\.sha1\s*\(",
            r"crypto\.createHash\s*\(\s*['\"]md5['\"]",
            r"crypto\.createHash\s*\(\s*['\"]sha1['\"]",
        ],
        "sanitizer_patterns": [
            r"bcrypt",
            r"argon2",
            r"PBKDF2",
            r"sha256",
            r"sha512",
        ],
        "severity": "HIGH",
        "cwe": "CWE-327"
    },
    {
        "id": "IAM-002",
        "category": "authentication",
        "name": "Hardcoded Credentials",
        "description": "Hardcoded username/password found in code",
        "file_exts": [".py", ".js", ".java", ".go", ".php", ".rb"],
        "vuln_patterns": [
            r"password\s*=\s*['\"][^'\"]+['\"]",
            r"passwd\s*=\s*['\"][^'\"]+['\"]",
            r"username\s*=\s*['\"][^'\"]+['\"]",
            r"user\s*=\s*['\"][^'\"]+['\"]",
        ],
        "sanitizer_patterns": [
            r"os\.environ",
            r"process\.env",
            r"getenv\s*\(",
            r"config\.get",
        ],
        "severity": "CRITICAL",
        "cwe": "CWE-798"
    },
    # 2. authorization
    {
        "id": "IAM-003",
        "category": "authorization",
        "name": "Missing Authorization Check",
        "description": "Endpoint lacks authorization decorators/checks",
        "file_exts": [".py", ".js", ".java", ".go"],
        "vuln_patterns": [
            r"@app\.route\s*\(\s*['\"][^'\"]+['\"]\s*\)",
            r"app\.(get|post|put|delete)\s*\(",
            r"router\.(get|post|put|delete)\s*\(",
        ],
        "sanitizer_patterns": [
            r"@login_required",
            r"@roles_required",
            r"@permission_required",
            r"@authenticated",
            r"auth_middleware",
        ],
        "severity": "HIGH",
        "cwe": "CWE-862"
    },
    # 13. admin-portals
    {
        "id": "IAM-004",
        "category": "admin-portals",
        "name": "Exposed Admin Portal",
        "description": "Admin panel accessible without authentication",
        "file_exts": [".py", ".js", ".html", ".java"],
        "vuln_patterns": [
            r"/admin",
            r"/administrator",
            r"/dashboard",
            r"/controlpanel",
            r"/cp",
            r"/manager",
            r"/management",
            r"/superuser",
            r"/root",
        ],
        "sanitizer_patterns": [
            r"is_admin\s*\(",
            r"require_sudo",
            r"@admin_required",
        ],
        "severity": "HIGH",
        "cwe": "CWE-284"
    },
]