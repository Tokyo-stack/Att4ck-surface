"""
IAM Surface - Authentication, Authorization, Session Management
"""

IAM_RULES = [
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
]