"""
API Surface - API Endpoints, Webhooks, Monitoring, Debug
"""

API_RULES = [
    # 7. api-endpoints
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
            r"/service/",
            r"/services/",
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
    # 9. webhooks
    {
        "id": "API-002",
        "category": "webhooks",
        "name": "Missing Webhook Signature Verification",
        "description": "Webhook endpoint without HMAC verification",
        "file_exts": [".py", ".js", ".java"],
        "vuln_patterns": [
            r"webhook",
            r"stripe_webhook",
            r"github_webhook",
            r"webhook_handler",
        ],
        "sanitizer_patterns": [
            r"signature",
            r"hmac",
            r"verify",
            r"construct_event",
            r"validate_signature",
        ],
        "severity": "HIGH",
        "cwe": "CWE-345"
    },
    # 28. monitoring
    {
        "id": "API-003",
        "category": "monitoring",
        "name": "Exposed Monitoring Endpoint",
        "description": "Metrics endpoint accessible without auth",
        "file_exts": [".py", ".js", ".json"],
        "vuln_patterns": [
            r"/metrics",
            r"/actuator",
            r"/health",
            r"/healthz",
            r"/status",
            r"/prometheus",
        ],
        "sanitizer_patterns": [
            r"auth_middleware",
            r"@authenticated",
            r"IP_whitelist",
            r"internal_only",
        ],
        "severity": "MEDIUM",
        "cwe": "CWE-200"
    },
    # 29. debug-endpoints
    {
        "id": "API-004",
        "category": "debug-endpoints",
        "name": "Debug Mode Enabled",
        "description": "Debug mode active in production",
        "file_exts": [".py", ".js", ".json", ".env"],
        "vuln_patterns": [
            r"debug\s*=\s*True",
            r"debug\s*=\s*true",
            r"NODE_ENV\s*=\s*['\"]development['\"]",
            r"APP_DEBUG\s*=\s*true",
            r"FLASK_DEBUG\s*=\s*1",
        ],
        "sanitizer_patterns": [
            r"debug\s*=\s*False",
            r"NODE_ENV\s*=\s*['\"]production['\"]",
            r"APP_DEBUG\s*=\s*false",
        ],
        "severity": "HIGH",
        "cwe": "CWE-489"
    },
    # 30. documentation
    {
        "id": "API-005",
        "category": "documentation",
        "name": "Exposed API Documentation",
        "description": "Swagger/Redoc exposed without auth",
        "file_exts": [".py", ".js", ".html"],
        "vuln_patterns": [
            r"/swagger",
            r"/swagger-ui",
            r"/docs",
            r"/redoc",
            r"/api-docs",
            r"/openapi",
            r"/graphiql",
        ],
        "sanitizer_patterns": [
            r"is_authenticated",
            r"@login_required",
            r"auth_middleware",
        ],
        "severity": "MEDIUM",
        "cwe": "CWE-200"
    },
]