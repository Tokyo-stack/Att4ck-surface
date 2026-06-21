"""
File Surface - File Uploads, Downloads, Cloud Storage, Backups
"""

FILE_RULES = [
    # 10. file-uploads
    {
        "id": "FIL-001",
        "category": "file-uploads",
        "name": "Unrestricted File Upload",
        "description": "File upload without validation or sanitization",
        "file_exts": [".py", ".js", ".php", ".java"],
        "vuln_patterns": [
            r"request\.files",
            r"file\.save\s*\(",
            r"multer\s*\(",
            r"upload\.single\s*\(",
            r"upload\.array\s*\(",
        ],
        "sanitizer_patterns": [
            r"secure_filename",
            r"allowed_file",
            r"mime",
            r"extension_check",
            r"validate_file",
        ],
        "severity": "HIGH",
        "cwe": "CWE-434"
    },
    # 11. file-downloads
    {
        "id": "FIL-002",
        "category": "file-downloads",
        "name": "Path Traversal",
        "description": "File download with path traversal vulnerability",
        "file_exts": [".py", ".js", ".php", ".java"],
        "vuln_patterns": [
            r"send_file\s*\(",
            r"send_from_directory\s*\(",
            r"fs\.readFile\s*\(",
            r"file_get_contents\s*\(",
            r"readfile\s*\(",
        ],
        "sanitizer_patterns": [
            r"safe_join",
            r"werkzeug\.utils",
            r"path\.resolve",
            r"os\.path\.join",
        ],
        "severity": "HIGH",
        "cwe": "CWE-22"
    },
    # 34. backups
    {
        "id": "FIL-003",
        "category": "backups",
        "name": "Backup Files in Codebase",
        "description": "Backup/temporary files stored in code",
        "file_exts": [".bak", ".old", ".tmp", ".swp", ".swo"],
        "vuln_patterns": [
            r"\.bak$",
            r"\.old$",
            r"\.tmp$",
            r"\.swp$",
            r"copy_of_",
            r"backup_",
        ],
        "sanitizer_patterns": [
            r"\.gitignore",
            r"tmp/",
            r"backup/",
        ],
        "severity": "MEDIUM",
        "cwe": "CWE-530"
    },
]