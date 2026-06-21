import re

# Categories 26 - 35: Operational environments, log analysis, and system engineering
OPERATIONS_RULES = [
    # 26. messageQueues
    {
        "category": "messageQueues",
        "name": "Insecure Object Deserialization",
        "file_exts": [".py", ".js"],
        "vuln_patterns": [r"pickle\.loads\(", r"yaml\.load\(", r"serialize\.unserialize\("],
        "sanitizer_patterns": [r"json\.loads", r"yaml\.safe_load", r"Loader\s*=\s*yaml\.SafeLoader"],
        "vuln_desc": "Message broker components unpack payloads using formats that allow object instantiation attacks.",
        "safe_desc": "No attack surface found (Data hydration bounded strictly through native standard JSON schemas)."
    },
    # 27. logging
    {
        "category": "logging",
        "name": "Plaintext Credential Log Leak",
        "file_exts": [".py", ".js"],
        "vuln_patterns": [r"logger\.(info|debug|error)\(.*password", r"console\.log\(.*token"],
        "sanitizer_patterns": [r"redact\(", r"hash\(", r"mask_credentials\("],
        "vuln_desc": "Logging actions appending sensitive run-time account parameters to unencrypted log paths.",
        "safe_desc": "No attack surface found (Diagnostic output processes filter out runtime PII variables automatically)."
    },
    # 28. monitoring
    {
        "category": "monitoring",
        "name": "Exposed Health Metrics Route",
        "file_exts": [".py", ".js"],
        "vuln_patterns": [r"/metrics", r"/actuator", r"/healthz"],
        "sanitizer_patterns": [r"auth_middleware", r"IP_whitelist", r"internal_only"],
        "vuln_desc": "Internal runtime monitoring endpoints configured inside the primary public context path root.",
        "safe_desc": "No attack surface found (System metrics isolated behind network-level validation systems)."
    },
    # 29. debugEndpoints
    {
        "category": "debugEndpoints",
        "name": "Active Debug Mode Flag",
        "file_exts": [".py", ".js", ".json"],
        "vuln_patterns": [r"debug\s*=\s*True", r"NODE_ENV\s*=\s*['\"]development['\"]"],
        "sanitizer_patterns": [r"debug\s*=\s*False", r"NODE_ENV\s*=\s*['\"]production['\"]"],
        "vuln_desc": "Diagnostic options left active, presenting descriptive runtime stack traces to remote users.",
        "safe_desc": "No attack surface found (Debug configurations hardlocked off inside deployment runtimes)."
    },
    # 30. documentation
    {
        "category": "documentation",
        "name": "Public API Schema Definition",
        "file_exts": [".py", ".html", ".json"],
        "vuln_patterns": [r"/swagger-ui", r"/docs", r"/redoc"],
        "sanitizer_patterns": [r"is_authenticated", r"docs_url\s*=\s*None"],
        "vuln_desc": "Interactive API routing document layouts readable without access control checks.",
        "safe_desc": "No attack surface found (System blueprint catalogs hidden completely behind authentication blocks)."
    },
    # 31. thirdPartyIntegrations
    {
        "category": "thirdPartyIntegrations",
        "name": "Unbounded External Request Routing (SSRF)",
        "file_exts": [".py", ".js"],
        "vuln_patterns": [r"requests\.get\(request", r"axios\.get\("],
        "sanitizer_patterns": [r"timeout\s*=", r"validate_destination", r"allow_list"],
        "vuln_desc": "Outbound HTTP modules fetching foreign targets using unsanitized connection timeouts.",
        "safe_desc": "No attack surface found (External integrations run with fixed processing resource limit restrictions)."
    },
    # 32. dependencies
    {
        "category": "dependencies",
        "name": "Unpinned Manifest Package Version",
        "file_exts": [".txt", ".json", ".lock"],
        "vuln_patterns": [r"^[A-Za-z0-9_\-]+==latest", r"\"[A-Za-z0-9_\-]+\":\s*\"\*\""],
        "sanitizer_patterns": [r"==[0-9\.]+", r"\"[0-9\.]+\""],
        "vuln_desc": "Dependency packages defined without absolute build-version anchors (supply chain vulnerability).",
        "safe_desc": "No attack surface found (Third party components locked strictly to immutable, test-verified releases)."
    },
    # 33. ciCd
    {
        "category": "ciCd",
        "name": "Inline Pipeline Token Exposure",
        "file_exts": [".yml", ".yaml"],
        "vuln_patterns": [r"github_token\s*:\s*[A-Za-z0-9]+", r"aws_secret\s*:\s*[A-Za-z0-9]+"],
        "sanitizer_patterns": [r"secrets\.", r"\$\{\{.*\}\}"], # Safely escaped curly braces
        "vuln_desc": "Continuous integration steps running tasks with secrets declared in standard plaintext configuration files.",
        "safe_desc": "No attack surface found (Pipeline actions load parameters from runtime vault stores dynamic contexts)."
    },
    # 34. backups
    {
        "category": "backups",
        "name": "Local Asset Backup Tracking",
        "file_exts": [".py", ".bak", ".old", ".tmp"],
        "vuln_patterns": [r"\.bak$", r"\.tmp$", r"copy_of_"],
        "sanitizer_patterns": [r"\.gitignore", r"tmp/"],
        "vuln_desc": "Temporary workspace archives or old scripts remaining inside tracking file boundaries.",
        "safe_desc": "No attack surface found (Dangling file definitions excluded or wiped by lifecycle managers)."
    },
    # 35. subdomains
    {
        "category": "subdomains",
        "name": "Hardcoded Internal Sandbox Domains",
        "file_exts": [".py", ".js", ".json"],
        "vuln_patterns": [r"['\"][A-Za-z0-9\-]+\.staging\.", r"['\"][A-Za-z0-9\-]+\.dev\."],
        "sanitizer_patterns": [r"config\.get", r"base_url", r"os\.getenv"],
        "vuln_desc": "Development staging routes tracked as static constant arrays across application blocks.",
        "safe_desc": "No attack surface found (System layout references gathered dynamically via host configuration environments)."
    }
]
