import re

class Rule:
    def __init__(self, category, name, file_exts, vuln_patterns, sanitizer_patterns, vuln_desc, safe_desc):
        """
        category: The structural category (e.g., 'database')
        name: User-friendly name
        file_exts: List of target file extensions (e.g., ['.py', '.js'])
        vuln_patterns: List of compiled regexes representing potential vulnerability patterns
        sanitizer_patterns: List of compiled regexes representing sanitization/remediation
        vuln_desc: Description to display when a vulnerability is found
        safe_desc: Description to display when a sanitized vulnerability is found
        """
        self.category = category
        self.name = name
        self.file_exts = file_exts
        self.vuln_patterns = [re.compile(p, re.IGNORECASE) for p in vuln_patterns]
        self.sanitizer_patterns = [re.compile(p, re.IGNORECASE) for p in sanitizer_patterns]
        self.vuln_desc = vuln_desc
        self.safe_desc = safe_desc

# Definition of standard rules for all 40 attack surfaces
RULES = [
    # 1. authentication
    Rule(
        category="authentication",
        name="Weak Hashing or Hardcoded Passwords",
        file_exts=[".py", ".js", ".json", ".yml", ".yaml"],
        vuln_patterns=[
            r"password\s*=\s*['\"][^'\"]+['\"]",
            r"hashlib\.md5\(",
            r"hashlib\.sha1\(",
            r"crypto\.createHash\(['\"]md5['\"]",
            r"crypto\.createHash\(['\"]sha1['\"]"
        ],
        sanitizer_patterns=[
            r"bcrypt", r"argon2", r"pbkdf2", r"sha256", r"sha512",
            r"os\.environ", r"process\.env", r"getpass", r"ConfigParser"
        ],
        vuln_desc="Hardcoded password or weak hashing algorithm (MD5/SHA1)",
        safe_desc="No attack surface found (Proper hashing or external configuration used)"
    ),
    # 2. authorization
    Rule(
        category="authorization",
        name="Missing Authorization Check",
        file_exts=[".py", ".js"],
        vuln_patterns=[
            r"@app\.route\(['\"].*['\"]\)",
            r"router\.(get|post|put|delete)\("
        ],
        sanitizer_patterns=[
            r"@login_required", r"@roles_required", r"@permission_required",
            r"check_permission", r"authenticate", r"has_role", r"middleware"
        ],
        vuln_desc="Exposed endpoint without authorization checks",
        safe_desc="No attack surface found (Endpoint secured via authorization checks)"
    ),
    # 3. sessionManagement
    Rule(
        category="sessionManagement",
        name="Insecure Cookie or JWT configuration",
        file_exts=[".py", ".js"],
        vuln_patterns=[
            r"set_cookie\(",
            r"cookies\.set\(",
            r"jwt\.decode\(.*verify\s*=\s*False"
        ],
        sanitizer_patterns=[
            r"httponly\s*=\s*True", r"secure\s*=\s*True", r"samesite",
            r"verify\s*=\s*True"
        ],
        vuln_desc="Insecure cookie flags (HttpOnly/Secure missing) or unverified JWT",
        safe_desc="No attack surface found (Cookie flags set properly / JWT verified)"
    ),
    # 4. userInputs
    Rule(
        category="userInputs",
        name="Unsanitized Dynamic Command Execution",
        file_exts=[".py", ".js"],
        vuln_patterns=[
            r"eval\(", r"exec\(", r"subprocess\.popen\(", r"subprocess\.run\("
        ],
        sanitizer_patterns=[
            r"int\(", r"float\(", r"shlex\.quote", r"escape", r"validation"
        ],
        vuln_desc="Dynamic code execution wrapper using potential input",
        safe_desc="No attack surface found (Dynamic input properly parsed or validated)"
    ),
    # 5. searchParameters
    Rule(
        category="searchParameters",
        name="Reflected Search Parameter (XSS possibility)",
        file_exts=[".py", ".js", ".html"],
        vuln_patterns=[
            r"request\.args\.get\(['\"]q['\"]",
            r"req\.query\.search",
            r"location\.search"
        ],
        sanitizer_patterns=[
            r"html\.escape", r"DOMPurify", r"escape", r"textContent", r"innerText"
        ],
        vuln_desc="Search parameter XSS possibility",
        safe_desc="No attack surface found (Search parameter properly escaped or sanitized)"
    ),
    # 6. idParameters
    Rule(
        category="idParameters",
        name="Raw ID Formatting",
        file_exts=[".py", ".js"],
        vuln_patterns=[
            r"['\"]select\s+.*\s+where\s+id\s*=\s*['\"]\s*\+\s*\w+",
            r"f['\"]select\s+.*\s+where\s+id\s*=\s*\{\w+\}",
            r"request\.(args|form)\.get\(['\"]id['\"]"
        ],
        sanitizer_patterns=[
            r"int\(", r"uuid", r"parsed_id", r"ObjectId"
        ],
        vuln_desc="Unvalidated ID parameter formatted into SQL or endpoint logic",
        safe_desc="No attack surface found (ID properly cast to integer/uuid/ObjectId)"
    ),
    # 7. apiEndpoints
    Rule(
        category="apiEndpoints",
        name="Unauthenticated API Route",
        file_exts=[".py", ".js"],
        vuln_patterns=[
            r"/api/v[0-9]/"
        ],
        sanitizer_patterns=[
            r"api_key", r"token", r"jwt", r"auth", r"decorators"
        ],
        vuln_desc="API endpoint declared without active protection",
        safe_desc="No attack surface found (API endpoint verified to have authentication)"
    ),
    # 8. graphql
    Rule(
        category="graphql",
        name="Dynamic GraphQL construction",
        file_exts=[".py", ".js"],
        vuln_patterns=[
            r"gql\(.*f['\"].*",
            r"gql\(.*\+\s*\w+"
        ],
        sanitizer_patterns=[
            r"variables", r"variableValues", r"params"
        ],
        vuln_desc="Dynamic GraphQL construction (vulnerability to GraphQL Injection)",
        safe_desc="No attack surface found (GraphQL variables utilized correctly)"
    ),
    # 9. webhooks
    Rule(
        category="webhooks",
        name="Webhook Signature Bypass",
        file_exts=[".py", ".js"],
        vuln_patterns=[
            r"webhook_receiver",
            r"stripe_webhook",
            r"webhook_handle"
        ],
        sanitizer_patterns=[
            r"signature", r"hmac", r"verify", r"construct_event"
        ],
        vuln_desc="Webhook handler without signature validation",
        safe_desc="No attack surface found (Webhook signature securely verified)"
    ),
    # 10. fileUploads
    Rule(
        category="fileUploads",
        name="Insecure File Upload Handling",
        file_exts=[".py", ".js"],
        vuln_patterns=[
            r"request\.files",
            r"file\.save\(",
            r"multer\("
        ],
        sanitizer_patterns=[
            r"secure_filename", r"allowed_file", r"mime", r"extension_check"
        ],
        vuln_desc="File upload handler without explicit extension/filename sanitization",
        safe_desc="No attack surface found (Uploaded files sanitized using secure_filename/extension whitelist)"
    ),
    # 11. fileDownloads
    Rule(
        category="fileDownloads",
        name="Path Traversal in File Download",
        file_exts=[".py", ".js"],
        vuln_patterns=[
            r"send_file\(",
            r"send_from_directory\(",
            r"res\.download\("
        ],
        sanitizer_patterns=[
            r"os\.path\.basename", r"safe_join", r"secure_filename", r"whitelist"
        ],
        vuln_desc="File download/send logic vulnerable to path traversal",
        safe_desc="No attack surface found (Path traversal protected via safe path helpers)"
    ),
    # 12. redirects
    Rule(
        category="redirects",
        name="Open Redirect Vulnerability",
        file_exts=[".py", ".js"],
        vuln_patterns=[
            r"redirect\(request\.",
            r"res\.redirect\(req\."
        ],
        sanitizer_patterns=[
            r"is_safe_url", r"urlparse", r"startswith\(['\"]/['\"]"
        ],
        vuln_desc="Dynamic redirect using unvalidated user input",
        safe_desc="No attack surface found (Open redirect protected via URL checking)"
    ),
    # 13. adminPortals
    Rule(
        category="adminPortals",
        name="Exposed Admin Panel Route",
        file_exts=[".py", ".js", ".html"],
        vuln_patterns=[
            r"/admin", r"/dashboard/admin"
        ],
        sanitizer_patterns=[
            r"is_admin", r"role.*admin", r"require_admin", r"has_role\(['\"]admin['\"]"
        ],
        vuln_desc="Admin portal route with no visible administrator check",
        safe_desc="No attack surface found (Admin portal authenticated/authorized)"
    ),
    # 14. userManagement
    Rule(
        category="userManagement",
        name="Insecure Profile / Privilege Change",
        file_exts=[".py", ".js"],
        vuln_patterns=[
            r"update_user", r"change_password", r"delete_user"
        ],
        sanitizer_patterns=[
            r"session\['user_id'\]", r"req\.session\.user", r"csrf", r"verify_current_password"
        ],
        vuln_desc="User management actions without session owner / CSRF checks",
        safe_desc="No attack surface found (Actions validated with session context/CSRF protection)"
    ),
    # 15. paymentSystems
    Rule(
        category="paymentSystems",
        name="Custom Credit Card Handling",
        file_exts=[".py", ".js"],
        vuln_patterns=[
            r"card_number", r"cvv", r"credit_card", r"expiry_month"
        ],
        sanitizer_patterns=[
            r"stripe", r"paypal", r"braintree", r"checkout_session"
        ],
        vuln_desc="Handling raw credit card data locally (PCI-DSS violation risk)",
        safe_desc="No attack surface found (Integrating payment through standard external SDK/Checkout)"
    ),
    # 16. oauthSSO
    Rule(
        category="oauthSSO",
        name="OAuth Flow Missing State/Nonce Validation",
        file_exts=[".py", ".js"],
        vuln_patterns=[
            r"oauth_callback", r"authorize_callback"
        ],
        sanitizer_patterns=[
            r"state\s*==", r"session\['state'\]", r"nonce", r"pkce"
        ],
        vuln_desc="OAuth callback endpoint missing CSRF state/PKCE verification",
        safe_desc="No attack surface found (OAuth flow enforces state verification)"
    ),
    # 17. emailFlows
    Rule(
        category="emailFlows",
        name="Potential Email Header Injection",
        file_exts=[".py", ".js"],
        vuln_patterns=[
            r"send_mail\(", r"sendmail\(", r"SMTP"
        ],
        sanitizer_patterns=[
            r"replace\(['\"]\\n['\"]", r"split\(['\"]\\n['\"]", r"jinja2\.escape", r"django\.core\.mail"
        ],
        vuln_desc="Sending email with dynamic headers or body vulnerable to injection",
        safe_desc="No attack surface found (Headers sanitized or standard library used)"
    ),
    # 18. notificationServices
    Rule(
        category="notificationServices",
        name="Plaintext SMS/Push Notifications",
        file_exts=[".py", ".js"],
        vuln_patterns=[
            r"sns\.publish", r"twilio\.messages\.create"
        ],
        sanitizer_patterns=[
            r"otp_hash", r"masked", r"verification_code"
        ],
        vuln_desc="Plaintext notification containing potentially sensitive payload",
        safe_desc="No attack surface found (Payload sanitized or generic/masked content sent)"
    ),
    # 19. frontendAssets
    Rule(
        category="frontendAssets",
        name="Missing Subresource Integrity (SRI)",
        file_exts=[".html", ".jsp", ".php"],
        vuln_patterns=[
            r'<script\s+[^>]*src=["\']http',
            r'<link\s+[^>]*rel=["\']stylesheet["\']\s+[^>]*href=["\']http'
        ],
        sanitizer_patterns=[
            r"integrity="
        ],
        vuln_desc="CDN resources loaded without subresource integrity (SRI)",
        safe_desc="No attack surface found (CDN asset loaded with integrity verification)"
    ),
    # 20. javascriptAnalysis
    Rule(
        category="javascriptAnalysis",
        name="Direct DOM Write (Client-Side XSS)",
        file_exts=[".js", ".html"],
        vuln_patterns=[
            r"\.innerHTML\s*=",
            r"document\.write\("
        ],
        sanitizer_patterns=[
            r"DOMPurify", r"escape", r"textContent", r"innerText"
        ],
        vuln_desc="Direct DOM manipulation using innerHTML or document.write",
        safe_desc="No attack surface found (Sanitized DOM modification detected)"
    ),
    # 21. secretsConfig
    Rule(
        category="secretsConfig",
        name="Hardcoded Secret Key in Configuration",
        file_exts=[".py", ".js", ".json", ".ini", ".conf"],
        vuln_patterns=[
            r"api_key\s*:\s*['\"][a-zA-Z0-9_-]{10,}['\"]",
            r"secret_key\s*=\s*['\"][a-zA-Z0-9_-]{10,}['\"]",
            r"aws_secret_key"
        ],
        sanitizer_patterns=[
            r"os\.environ", r"process\.env", r"ConfigParser", r"vault", r"\$\{.*\}", r"<insert-here>"
        ],
        vuln_desc="Hardcoded secret key / API key found in configuration",
        safe_desc="No attack surface found (Key references environment variable / external store)"
    ),
    # 22. environmentFiles
    Rule(
        category="environmentFiles",
        name="Production Credentials in Env File",
        file_exts=[".env", ".env.example", ".env.local"],
        vuln_patterns=[
            r"PASSWORD\s*=\s*[^\s#]+",
            r"SECRET\s*=\s*[^\s#]+",
            r"KEY\s*=\s*[^\s#]+"
        ],
        sanitizer_patterns=[
            r"your_", r"insert_", r"TODO", r"placeholder", r"change_me", r"xoxb-dummy"
        ],
        vuln_desc="Production secret / API credential committed in env file",
        safe_desc="No attack surface found (Env file contains template placeholders only)"
    ),
    # 23. cloudStorage
    Rule(
        category="cloudStorage",
        name="Insecure Cloud Storage Access Control",
        file_exts=[".py", ".tf", ".json", ".yml"],
        vuln_patterns=[
            r"acl\s*=\s*['\"]public-read['\"]",
            r"aws_s3_bucket",
            r"boto3\.client\(['\"]s3['\"]"
        ],
        sanitizer_patterns=[
            r"private", r"restrict", r"iam_role", r"kms", r"BlockPublicAcls\s*=\s*true"
        ],
        vuln_desc="Cloud storage bucket or access configured with public access permissions",
        safe_desc="No attack surface found (Bucket restricted with private policies / IAM)"
    ),
    # 24. database
    Rule(
        category="database",
        name="SQL Injection vulnerability",
        file_exts=[".py", ".js"],
        vuln_patterns=[
            r"['\"]select\s+.*\s+from\s+.*\s+where\s+.*['\"]\s*\+\s*",
            r"f['\"]select\s+.*\s+from\s+.*\s+where\s+.*\{\w+\}",
            r"\.execute\(.*%\s*\w+",
            r"\.raw\(",
            r"db\.run\("
        ],
        sanitizer_patterns=[
            r",\s*\([a-zA-Z0-9_, ]+\)",
            r"params\s*=",
            r"bind",
            r"int\(",
            r"escape",
            r"db\.query_params",
            r"sql_escape"
        ],
        vuln_desc="SQLI possibility",
        safe_desc="No attack surface found (Parameterized database input detected)"
    ),
    # 25. cacheServices
    Rule(
        category="cacheServices",
        name="Plaintext / Unsecured Cache Storage",
        file_exts=[".py", ".js"],
        vuln_patterns=[
            r"redis\.set\(", r"memcached\.set\("
        ],
        sanitizer_patterns=[
            r"encrypt", r"json\.dumps", r"pickle", r"expire", r"ex="
        ],
        vuln_desc="Caching sensitive data in plaintext or without cache expiry limits",
        safe_desc="No attack surface found (Cached object encrypted, structured or expired securely)"
    ),
    # 26. messageQueues
    Rule(
        category="messageQueues",
        name="Insecure Deserialization in Queue",
        file_exts=[".py"],
        vuln_patterns=[
            r"celery\.task", r"pika\.channel", r"pickle\.loads"
        ],
        sanitizer_patterns=[
            r"json", r"serializer\s*=\s*['\"]json['\"]", r"msgpack", r"protobuf"
        ],
        vuln_desc="Parsing queue payloads using insecure deserializers (pickle.loads)",
        safe_desc="No attack surface found (Queue messages deserialized using secure formats (json/msgpack))"
    ),
    # 27. logging
    Rule(
        category="logging",
        name="Logging Credentials / PII",
        file_exts=[".py", ".js"],
        vuln_patterns=[
            r"logging\.(info|debug|warn|error)\(.*(password|token|secret|credit|email|phone|card)",
            r"console\.log\(.*(password|token|secret|credit|email|phone|card)"
        ],
        sanitizer_patterns=[
            r"mask", r"hash", r"redact", r"obfuscate", r"truncate"
        ],
        vuln_desc="Logging plaintext credentials or PII in local application log",
        safe_desc="No attack surface found (PII/Secret redacted before logging)"
    ),
    # 28. monitoring
    Rule(
        category="monitoring",
        name="Exposed Prometheus Metrics Without Auth",
        file_exts=[".py", ".js", ".yml"],
        vuln_patterns=[
            r"/metrics", r"prometheus_client"
        ],
        sanitizer_patterns=[
            r"auth", r"basic_auth", r"require_login", r"ip_whitelist"
        ],
        vuln_desc="Prometheus metrics / monitoring endpoint without access controls",
        safe_desc="No attack surface found (Metrics endpoint restricted with authentication)"
    ),
    # 29. debugEndpoints
    Rule(
        category="debugEndpoints",
        name="Active Debug Mode in Production",
        file_exts=[".py", ".js", ".html", ".conf"],
        vuln_patterns=[
            r"debug\s*=\s*True",
            r"devMode\s*=\s*true",
            r"/debug"
        ],
        sanitizer_patterns=[
            r"os\.environ", r"os\.getenv", r"process\.env", r"CONFIG_MODE", r"development", r"dev_"
        ],
        vuln_desc="Debug mode or debugger console routes active",
        safe_desc="No attack surface found (Debug mode resolved dynamically from env/config settings)"
    ),
    # 30. documentation
    Rule(
        category="documentation",
        name="Unauthenticated Swagger/API Docs",
        file_exts=[".py", ".js"],
        vuln_patterns=[
            r"/swagger", r"/redoc", r"SwaggerUI"
        ],
        sanitizer_patterns=[
            r"is_dev", r"require_auth", r"login_required", r"auth_middleware"
        ],
        vuln_desc="Swagger/OpenAPI documentation exposed without credentials check",
        safe_desc="No attack surface found (API documentation access secured)"
    ),
    # 31. thirdPartyIntegrations
    Rule(
        category="thirdPartyIntegrations",
        name="SSRF or Missing Request Timeout",
        file_exts=[".py", ".js"],
        vuln_patterns=[
            r"requests\.(get|post|put)\(",
            r"axios\.(get|post)\("
        ],
        sanitizer_patterns=[
            r"timeout\s*=", r"is_valid_url", r"whitelist", r"validate_domain"
        ],
        vuln_desc="Outbound request missing timeout (Denial of Service risk) or domain validation",
        safe_desc="No attack surface found (Timeout parameters or URL validations are configured)"
    ),
    # 32. dependencies
    Rule(
        category="dependencies",
        name="Outdated / Unpinned Package Dependencies",
        file_exts=["requirements.txt", "package.json"],
        vuln_patterns=[
            r"^[a-zA-Z0-9_-]+\s*$",
            r"==\*",
            r"\*\s*$"
        ],
        sanitizer_patterns=[
            r"==[0-9]+", r"\^[0-9]+", r"~=[0-9]+"
        ],
        vuln_desc="Wildcard/unpinned package versions in dependency files",
        safe_desc="No attack surface found (Packages pinned using strict version operators)"
    ),
    # 33. cicd
    Rule(
        category="cicd",
        name="Hardcoded Secret in CI/CD configuration",
        file_exts=[".yml", ".yaml"],
        vuln_patterns=[
            r"password\s*:\s*[a-zA-Z0-9_-]+",
            r"token\s*:\s*[a-zA-Z0-9_-]+"
        ],
        sanitizer_patterns=[
            r"\$\{\{\s*secrets\..*\}\}", r"\$.*"
        ],
        vuln_desc="Hardcoded password/token key committed in CI/CD script",
        safe_desc="No attack surface found (Secrets managed via Github Secrets or environment variables)"
    ),
    # 34. backups
    Rule(
        category="backups",
        name="Referencing Temporary Backup Files",
        file_exts=[".py", ".js", ".sh"],
        vuln_patterns=[
            r"\.bak", r"\.tmp", r"\.backup", r"backup_dir"
        ],
        sanitizer_patterns=[
            r"tempfile", r"cleanup", r"delete=True"
        ],
        vuln_desc="Manual file backups or temporary directories references inside scripts",
        safe_desc="No attack surface found (Temporary/backup files handled by standard systems/cleanup)"
    ),
    # 35. subdomains
    Rule(
        category="subdomains",
        name="Hardcoded Dev/Staging Subdomain",
        file_exts=[".py", ".js", ".html", ".conf"],
        vuln_patterns=[
            r"dev\.[a-zA-Z0-9_-]+\.[a-z]+",
            r"staging\.[a-zA-Z0-9_-]+\.[a-z]+"
        ],
        sanitizer_patterns=[
            r"os\.getenv", r"process\.env", r"config", r"\$\{.*\}", r"example\.com"
        ],
        vuln_desc="Hardcoded dev/staging subdomains inside application code",
        safe_desc="No attack surface found (Subdomains mapped dynamically / placeholders utilized)"
    ),
    # 36. dns
    Rule(
        category="dns",
        name="Custom DNS Query Construction",
        file_exts=[".py", ".js"],
        vuln_patterns=[
            r"dns\.resolver\.resolve\(", r"dns\.query"
        ],
        sanitizer_patterns=[
            r"dnssec", r"verify", r"trusted_resolver"
        ],
        vuln_desc="Custom DNS resolving scripts without authentication / validation",
        safe_desc="No attack surface found (DNS resolution properly signed or secured)"
    ),
    # 37. serverConfig
    Rule(
        category="serverConfig",
        name="Insecure CORS Allow-All Configuration",
        file_exts=[".py", ".js", ".conf", ".nginx"],
        vuln_patterns=[
            r"Access-Control-Allow-Origin\s*,\s*['\"]\*['\"]",
            r"CORS\(app,\s*resources\s*=\s*\{\s*r['\"].*['\"]\s*:\s*\{\s*['\"]origins['\"]\s*:\s*['\"]\*['\"]"
        ],
        sanitizer_patterns=[
            r"allow_credentials\s*=\s*False", r"origins\s*=\s*\[.*\]"
        ],
        vuln_desc="CORS allow-all '*' header configured on API endpoints",
        safe_desc="No attack surface found (CORS limited or credentials disallowed)"
    ),
    # 38. containers
    Rule(
        category="containers",
        name="Dockerfile Running as Privileged User",
        file_exts=["Dockerfile", "docker-compose.yml"],
        vuln_patterns=[
            r"FROM\s+.*:latest",
            r"privileged\s*:\s*true"
        ],
        sanitizer_patterns=[
            r"USER\s+[a-zA-Z0-9_-]+",
            r"RUN\s+useradd"
        ],
        vuln_desc="Containers running as root user/privileged with unpinned latest tag",
        safe_desc="No attack surface found (Containers set up with user configuration)"
    ),
    # 39. sourceControl
    Rule(
        category="sourceControl",
        name="Exposed Source Control Credentials",
        file_exts=[".py", ".js", ".sh"],
        vuln_patterns=[
            r"git\s+clone\s+https://.*:.*@"
        ],
        sanitizer_patterns=[
            r"SSH", r"\$\{.*\}", r"\$GITHUB_TOKEN"
        ],
        vuln_desc="Git credentials / private tokens committed in scripts",
        safe_desc="No attack surface found (Secure tokens or SSH key paths used instead)"
    ),
    # 40. miscellaneous
    Rule(
        category="miscellaneous",
        name="Insecure Dynamic Parsing",
        file_exts=[".py", ".js"],
        vuln_patterns=[
            r"yaml\.load\(",
            r"tempfile\.mktemp\("
        ],
        sanitizer_patterns=[
            r"yaml\.safe_load", r"tempfile\.mkstemp", r"SafeLoader"
        ],
        vuln_desc="Unsafe YAML/JSON loader or temporary file generation (RCE/Arbitrary file creation)",
        safe_desc="No attack surface found (Safe YAML loader / Secure temporary creation applied)"
    )
]
