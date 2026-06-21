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
            r"handle_upload",
            r"save_upload",
        ],
        "sanitizer_patterns": [
            r"secure_filename",
            r"allowed_file",
            r"mime",
            r"extension_check",
            r"validate_file",
            r"sanitize_filename",
            r"file_type_check",
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
            r"DownloadFile\s*\(",
        ],
        "sanitizer_patterns": [
            r"safe_join",
            r"werkzeug\.utils",
            r"path\.resolve",
            r"os\.path\.join",
            r"sanitize_path",
            r"validate_path",
        ],
        "severity": "HIGH",
        "cwe": "CWE-22"
    },
    # 23. cloud-storage
    {
        "id": "FIL-003",
        "category": "cloud-storage",
        "name": "Public Cloud Storage",
        "description": "S3 bucket with public read access",
        "file_exts": [".py", ".json", ".tf", ".yml"],
        "vuln_patterns": [
            r"public-read",
            r"public_read",
            r"AllowedOrigins\s*:\s*\*",
            r"aws_s3_bucket",
            r"S3_BUCKET",
        ],
        "sanitizer_patterns": [
            r"private",
            r"bucket-owner-full-control",
            r"restrict_public_buckets",
            r"block_public_access",
            r"authenticated-read",
        ],
        "severity": "HIGH",
        "cwe": "CWE-284"
    },
    # 34. backups
    {
        "id": "FIL-004",
        "category": "backups",
        "name": "Backup Files in Codebase",
        "description": "Backup/temporary files stored in code",
        "file_exts": [".bak", ".old", ".tmp", ".swp", ".swo", "~"],
        "vuln_patterns": [
            r"\.bak$",
            r"\.old$",
            r"\.tmp$",
            r"\.swp$",
            r"\.swo$",
            r"~$",
            r"copy_of_",
            r"backup_",
        ],
        "sanitizer_patterns": [
            r"\.gitignore",
            r"tmp/",
            r"backup/",
            r"\.git/",
        ],
        "severity": "MEDIUM",
        "cwe": "CWE-530"
    },
]