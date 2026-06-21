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
            r"@app\.route\s*\(\s*['\"](/api/[^'\"]+)['\"]",
        ],
        "sanitizer_patterns": [
            r"@login_required",
            r"@authenticated",
            r"api_key",
            r"token",
            r"auth_middleware",
            r"@PreAuthorize",
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
            r"webhook_receiver",
            r"/webhook",
        ],
        "sanitizer_patterns": [
            r"signature",
            r"hmac",
            r"verify",
            r"construct_event",
            r"validate_signature",
            r"verify_signature",
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
            r"/monitoring",
        ],
        "sanitizer_patterns": [
            r"auth_middleware",
            r"@authenticated",
            r"IP_whitelist",
            r"internal_only",
            r"require_auth",
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
            r"DEBUG\s*=\s*True",
            r"FLASK_DEBUG\s*=\s*1",
        ],
        "sanitizer_patterns": [
            r"debug\s*=\s*False",
            r"NODE_ENV\s*=\s*['\"]production['\"]",
            r"APP_DEBUG\s*=\s*false",
            r"DEBUG\s*=\s*False",
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
            r"/apidocs",
            r"/openapi",
            r"/graphiql",
            r"/playground",
        ],
        "sanitizer_patterns": [
            r"is_authenticated",
            r"@login_required",
            r"auth_middleware",
            r"docs_url\s*=\s*None",
        ],
        "severity": "MEDIUM",
        "cwe": "CWE-200"
    },
    # 35. subdomains
    {
        "id": "API-006",
        "category": "subdomains",
        "name": "Hardcoded Subdomain",
        "description": "Development/staging subdomain hardcoded",
        "file_exts": [".py", ".js", ".json", ".yml"],
        "vuln_patterns": [
            r"['\"][a-zA-Z0-9\-]+\.staging\.",
            r"['\"][a-zA-Z0-9\-]+\.dev\.",
            r"['\"][a-zA-Z0-9\-]+\.test\.",
            r"['\"][a-zA-Z0-9\-]+\.local\.",
            r"['\"][a-zA-Z0-9\-]+\.sandbox\.",
        ],
        "sanitizer_patterns": [
            r"config\.get",
            r"base_url",
            r"os\.getenv",
            r"process\.env",
            r"settings\.",
        ],
        "severity": "MEDIUM",
        "cwe": "CWE-200"
    },
    # 36. dns
    {
        "id": "API-007",
        "category": "dns",
        "name": "Insecure DNS Resolution",
        "description": "DNS resolution without validation",
        "file_exts": [".py", ".js", ".java"],
        "vuln_patterns": [
            r"socket\.gethostbyname\s*\(",
            r"dns\.resolve\s*\(",
            r"gethostbyname\s*\(",
            r"lookup\s*\(",
        ],
        "sanitizer_patterns": [
            r"trusted_resolver",
            r"dnssec",
            r"validate_ip\s*\(",
            r"is_valid_hostname",
        ],
        "severity": "MEDIUM",
        "cwe": "CWE-350"
    },
]