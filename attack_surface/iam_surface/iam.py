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
            r"MessageDigest\.getInstance\s*\(\s*['\"]MD5['\"]",
            r"MessageDigest\.getInstance\s*\(\s*['\"]SHA-1['\"]",
        ],
        "sanitizer_patterns": [
            r"bcrypt",
            r"argon2",
            r"PBKDF2",
            r"sha256",
            r"sha512",
            r"scrypt",
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
            r"login\s*=\s*['\"][^'\"]+['\"]",
            r"credential\s*=\s*['\"][^'\"]+['\"]",
        ],
        "sanitizer_patterns": [
            r"os\.environ",
            r"process\.env",
            r"getenv\s*\(",
            r"config\.get",
            r"settings\.get",
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
            r"@GetMapping",
            r"@PostMapping",
            r"@PutMapping",
            r"@DeleteMapping",
            r"express\.Router\s*\(\s*\)",
        ],
        "sanitizer_patterns": [
            r"@login_required",
            r"@roles_required",
            r"@permission_required",
            r"@authenticated",
            r"auth_middleware",
            r"check_permission",
            r"@PreAuthorize",
        ],
        "severity": "HIGH",
        "cwe": "CWE-862"
    },
    # 3. session-management
    {
        "id": "IAM-004",
        "category": "session-management",
        "name": "Insecure Cookie Configuration",
        "description": "Missing HttpOnly/Secure flags on cookies",
        "file_exts": [".py", ".js", ".java", ".go"],
        "vuln_patterns": [
            r"set_cookie\s*\(",
            r"cookies\.set\s*\(",
            r"res\.cookie\s*\(",
            r"response\.set_cookie\s*\(",
            r"cookie\s*[:=]",
        ],
        "sanitizer_patterns": [
            r"httponly\s*=\s*True",
            r"httpOnly\s*:\s*true",
            r"secure\s*=\s*True",
            r"secure\s*:\s*true",
            r"samesite\s*=\s*['\"]strict['\"]",
            r"samesite\s*:\s*['\"]strict['\"]",
        ],
        "severity": "HIGH",
        "cwe": "CWE-614"
    },
    {
        "id": "IAM-005",
        "category": "session-management",
        "name": "Unverified JWT",
        "description": "JWT verification disabled or missing",
        "file_exts": [".py", ".js", ".java", ".go"],
        "vuln_patterns": [
            r"jwt\.decode\s*\(.*verify\s*=\s*False",
            r"jwt\.verify\s*\(\s*false",
            r"JWT\.decode\s*\(.*skip_verification",
            r"verify\s*=\s*False",
        ],
        "sanitizer_patterns": [
            r"verify\s*=\s*True",
            r"verify\s*:\s*true",
            r"jwt\.decode\s*\([^,]+,\s*[^,]+,\s*[^)]*\)",
        ],
        "severity": "CRITICAL",
        "cwe": "CWE-347"
    },
    # 13. admin-portals
    {
        "id": "IAM-006",
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
            r"check_admin",
            r"IP_whitelist",
        ],
        "severity": "HIGH",
        "cwe": "CWE-284"
    },
    # 14. user-management
    {
        "id": "IAM-007",
        "category": "user-management",
        "name": "IDOR - Missing Ownership Check",
        "description": "User profile operations missing ownership validation",
        "file_exts": [".py", ".js", ".java", ".go"],
        "vuln_patterns": [
            r"update_profile\s*\(",
            r"change_password\s*\(",
            r"delete_account\s*\(",
            r"update_user\s*\(",
            r"edit_profile\s*\(",
            r"user_id\s*=\s*request\.",
        ],
        "sanitizer_patterns": [
            r"current_user\.id",
            r"session\['user_id'\]",
            r"owner_check\s*\(",
            r"get_current_user\s*\(",
            r"authenticated_user",
        ],
        "severity": "HIGH",
        "cwe": "CWE-639"
    },
    # 16. oauth-sso
    {
        "id": "IAM-008",
        "category": "oauth-sso",
        "name": "Missing OAuth State Parameter",
        "description": "OAuth callback missing CSRF state verification",
        "file_exts": [".py", ".js", ".java"],
        "vuln_patterns": [
            r"/oauth/callback",
            r"/google_callback",
            r"/github_callback",
            r"/facebook_callback",
            r"oauth_callback",
        ],
        "sanitizer_patterns": [
            r"state\s*=",
            r"session\['state'\]",
            r"csrf_token",
            r"verify_state",
            r"check_state",
        ],
        "severity": "HIGH",
        "cwe": "CWE-352"
    },
]