"""
API Surface - API Endpoints, Webhooks, Monitoring, Debug
"""

API_RULES = [
    {
        "id": "API-001",
        "category": "api-endpoints",
        "name": "Unauthenticated API Endpoint",
        "description": "API endpoint without authentication",
        "file_exts": [".py", ".js", ".java", ".go"],
        "vuln_patterns": [
            r"/api/",
            r"/rest/",
            r"/v\d+/",
        ],
        "sanitizer_patterns": [
            r"@login_required",
            r"@authenticated",
            r"api_key",
            r"token",
            r"auth_middleware",
        ],
        "severity": "HIGH",
        "cwe": "CWE-862"
    },
]