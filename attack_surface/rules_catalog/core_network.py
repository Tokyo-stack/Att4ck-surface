import re

# Categories 16 - 25: Transit protocols, API architectures, and boundary systems
NETWORK_RULES = [
    # 16. oauthSso
    {
        "category": "oauthSso",
        "name": "Missing OAuth State Validation Check",
        "file_exts": [".py", ".js"],
        "vuln_patterns": [r"oauth/callback", r"google_callback", r"github_callback"],
        "sanitizer_patterns": [r"state", r"session\['state'\]", r"xsrf", r"csrf"],
        "vuln_desc": "Single Sign-On callback hooks missing anti-forgery tracking tokens (CSRF exposure).",
        "safe_desc": "No attack surface found (OAuth login procedures cross-validate unique ephemeral state arguments)."
    },
    # 17. emailFlows
    {
        "category": "emailFlows",
        "name": "SMTP Injection Possibility",
        "file_exts": [".py", ".js"],
        "vuln_patterns": [r"sendmail\(", r"smtplib", r"nodemailer"],
        "sanitizer_patterns": [r"replace\(['\\]n', ''\)", r"validate_email", r"MIMEText"],
        "vuln_desc": "Mail sending setups constructing parameter envelopes from multi-line parameter blocks.",
        "safe_desc": "No attack surface found (Dynamic strings context-scrubbed or structure-enforced via standard schemas)."
    },
    # 18. notificationServices
    {
        "category": "notificationServices",
        "name": "Plaintext Sensitive Notifications",
        "file_exts": [".py", ".js"],
        "vuln_patterns": [r"send_sms\(", r"send_push\(", r"twilio\.messages"],
        "sanitizer_patterns": [r"mask\(", r"encrypted", r"redact", r"token_only"],
        "vuln_desc": "Telemetry alerts mapping user authorization data into cleartext messaging arrays.",
        "safe_desc": "No attack surface found (Sensitive values systematically redacted or tokenized before transport)."
    },
    # 19. frontendAssets
    {
        "category": "frontendAssets",
        "name": "Missing Subresource Integrity (SRI)",
        "file_exts": [".html", ".js"],
        "vuln_patterns": [r"<script\s+src=['\"]https://cdn.*['\"](?![^>]*integrity)"],
        "sanitizer_patterns": [r"integrity\s*=\s*['\"]sha"],
        "vuln_desc": "External assets imported from third-party locations missing explicit hash verification checks.",
        "safe_desc": "No attack surface found (Asset imports protected via structural subresource cryptographic digests)."
    },
    # 20. javascriptAnalysis
    {
        "category": "javascriptAnalysis",
        "name": "Dangerous DOM manipulation",
        "file_exts": [".js", ".html"],
        "vuln_patterns": [r"\.innerHTML\s*=", r"document\.write\("],
        "sanitizer_patterns": [r"DOMPurify\.sanitize", r"textContent", r"innerText"],
        "vuln_desc": "Client runtime script vectors directly rendering dynamic raw parameters to window surfaces.",
        "safe_desc": "No attack surface found (DOM updates processed securely using standard sandboxed innerText targets)."
    },
    # 21. secretsConfig
    {
        "category": "secretsConfig",
        "name": "Hardcoded Configuration Metadata",
        "file_exts": [".json", ".ini", ".conf"],
        "vuln_patterns": [r"(?i)(api_key|secret|password)\s*[:=]"],
        "sanitizer_patterns": [r"\{\{.*\}\}", r"\$.*", r"ENV_"],
        "vuln_desc": "Static dictionary configurations containing unencrypted private system asset credentials.",
        "safe_desc": "No attack surface found (Config schemas abstract real secrets through reference strings)."
    },
    # 22. environmentFiles
    {
        "category": "environmentFiles",
        "name": "Leaked Production Secrets Template",
        "file_exts": [".env", ".env.example"],
        "vuln_patterns": [r"(?i)(db_password|prod_key)\s*=\s*[A-Za-z0-9_\-]+(?!\s*$)"],
        "sanitizer_patterns": [r"YOUR_", r"ENTER_", r"CHANGEME", r"^$"],
        "vuln_desc": "Environment templates tracking live configurations into local tracking files.",
        "safe_desc": "No attack surface found (Environment templates expose placeholder parameter strings safely)."
    },
    # 23. cloudStorage
    {
        "category": "cloudStorage",
        "name": "Public Read S3 Bucket Configuration",
        "file_exts": [".py", ".json", ".tf"],
        "vuln_patterns": [r"public-read", r"AllowedOrigins.*\*"],
        "sanitizer_patterns": [r"private", r"bucket-owner-full-control", r"restrict_public_buckets"],
        "vuln_desc": "Object storage bucket architectures opening resources wide to anonymous remote lookups.",
        "safe_desc": "No attack surface found (Cloud bucket access paths hard-locked into authorization domains)."
    },
    # 24. database
    {
        "category": "database",
        "name": "SQL Injection Risk Context",
        "file_exts": [".py", ".js"],
        "vuln_patterns": [r"\.execute\(['\"].*%\s*.*['\"]", r"\.execute\(f['\"].*\{.*\}['\"]"],
        "sanitizer_patterns": [r"%\s*args", r"\?,", r"paramstyle", r"bindparameters"],
        "vuln_desc": "SQL backend processes executing commands constructed via raw runtime string concatenation.",
        "safe_desc": "No attack surface found (Database operations process actions safely via bound parameters)."
    },
    # 25. cacheServices
    {
        "category": "cacheServices",
        "name": "Unencrypted Memory Cache Configuration",
        "file_exts": [".py", ".conf"],
        "vuln_patterns": [r"redis\.Redis\(", r"memcache\.Client\("],
        "sanitizer_patterns": [r"ssl\s*=\s*True", r"password\s*=", r"requirepass"],
        "vuln_desc": "In-memory caching nodes connecting across shared local networks without credentials or transport security.",
        "safe_desc": "No attack surface found (Cache interactions secured via active authentication and TLS tunnels)."
    }
]
