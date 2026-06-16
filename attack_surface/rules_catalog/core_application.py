import re

# Categories 1 - 15: Deep application logic, input flow, and data handling
APPLICATION_RULES = [
    # 1. authentication
    {
        "category": "authentication",
        "name": "Weak Hashing or Hardcoded Passwords",
        "file_exts": [".py", ".js", ".json", ".yml", ".yaml"],
        "vuln_patterns": [r"password\s*=\s*['\"][^'\"]+['\"]", r"hashlib\.md5\(", r"hashlib\.sha1\(", r"crypto\.createHash\(['\"](md5|sha1)['\"]"],
        "sanitizer_patterns": [r"bcrypt", r"argon2", r"pbkdf2", r"sha256", r"os\.environ", r"process\.env", r"getpass"],
        "vuln_desc": "Hardcoded credential or dangerous weak cryptographic hashing (MD5/SHA1).",
        "safe_desc": "No attack surface found (Proper production hashing or externalized secrets used)."
    },
    # 2. authorization
    {
        "category": "authorization",
        "name": "Missing Authorization Check",
        "file_exts": [".py", ".js"],
        "vuln_patterns": [r"@app\.route\(['\"].*['\"]\)", r"router\.(get|post|put|delete)\("],
        "sanitizer_patterns": [r"@login_required", r"@roles_required", r"@permission_required", r"check_permission", r"middleware"],
        "vuln_desc": "Exposed application web endpoint lacking structural access control checks.",
        "safe_desc": "No attack surface found (Endpoint securely protected via routing authorization wrappers)."
    },
    # 3. sessionManagement
    {
        "category": "sessionManagement",
        "name": "Insecure Cookie or JWT configuration",
        "file_exts": [".py", ".js"],
        "vuln_patterns": [r"set_cookie\(", r"cookies\.set\(", r"jwt\.decode\(.*verify\s*=\s*False"],
        "sanitizer_patterns": [r"httponly\s*=\s*True", r"secure\s*=\s*True", r"samesite", r"verify\s*=\s*True"],
        "vuln_desc": "Insecure cookie flags (HttpOnly/Secure missing) or unverified JWT token evaluation.",
        "safe_desc": "No attack surface found (Cookie flags set properly or JWT cryptographically verified)."
    },
    # 4. userInputs
    {
        "category": "userInputs",
        "name": "Unsanitized Dynamic Command Execution",
        "file_exts": [".py", ".js"],
        "vuln_patterns": [r"\beval\(", r"\bexec\(", r"subprocess\.(Popen|run|call)\("],
        "sanitizer_patterns": [r"int\(", r"float\(", r"shlex\.quote", r"escape", r"validation"],
        "vuln_desc": "Dynamic evaluation blocks capable of triggering arbitrary code execution flaws.",
        "safe_desc": "No attack surface found (Dynamic parameters cleanly validated or cast to primitive metrics)."
    },
    # 5. searchParameters
    {
        "category": "searchParameters",
        "name": "Reflected Search Parameter (XSS possibility)",
        "file_exts": [".py", ".js", ".html"],
        "vuln_patterns": [r"request\.args\.get\(['\"]q['\"]", r"req\.query\.search", r"location\.search"],
        "sanitizer_patterns": [r"html\.escape", r"DOMPurify", r"escape", r"textContent", r"innerText"],
        "vuln_desc": "Unfiltered url parameters direct-rendering to client views, exposing Reflected XSS vectors.",
        "safe_desc": "No attack surface found (Search parameter safely context-escaped or sanitized before render)."
    },
    # 6. idParameters
    {
        "category": "idParameters",
        "name": "Raw ID Parameter Formatting",
        "file_exts": [".py", ".js"],
        "vuln_patterns": [r"['\"]select\s+.*\s+where\s+id\s*=\s*['\"]\s*\+\s*\w+", r"f['\"]select\s+.*\s+where\s+id\s*=\s*\{\w+\}", r"request\.(args|form)\.get\(['\"]id['\"]"],
        "sanitizer_patterns": [r"int\(", r"uuid", r"parsed_id", r"ObjectId"],
        "vuln_desc": "Unvalidated ID routing elements processed inside database statement format strings.",
        "safe_desc": "No attack surface found (Target index identifiers strongly cast to discrete numerical primitives)."
    },
    # 7. apiEndpoints
    {
        "category": "apiEndpoints",
        "name": "Unauthenticated API Route",
        "file_exts": [".py", ".js"],
        "vuln_patterns": [r"/api/v[0-9]/"],
        "sanitizer_patterns": [r"api_key", r"token", r"jwt", r"auth", r"decorators"],
        "vuln_desc": "API interface routes discovered without explicit systemic authorization enforcement markers.",
        "safe_desc": "No attack surface found (Active validation middleware tracks global access credentials)."
    },
    # 8. graphql
    {
        "category": "graphql",
        "name": "Dynamic GraphQL construction",
        "file_exts": [".py", ".js"],
        "vuln_patterns": [r"gql\(.*f['\"].*", r"gql\(.*\+\s*\w+"],
        "sanitizer_patterns": [r"variables", r"variableValues", r"params"],
        "vuln_desc": "Dynamic string construction inside GraphQL query execution chains.",
        "safe_desc": "No attack surface found (GraphQL query parameterized securely via discrete variable arrays)."
    },
    # 9. webhooks
    {
        "category": "webhooks",
        "name": "Webhook Signature Bypass",
        "file_exts": [".py", ".js"],
        "vuln_patterns": [r"webhook_receiver", r"stripe_webhook", r"webhook_handle"],
        "sanitizer_patterns": [r"signature", r"hmac", r"verify", r"construct_event"],
        "vuln_desc": "Webhook event controller listening for incoming data without signature digest verification.",
        "safe_desc": "No attack surface found (Incoming webhook events securely verified against provider secrets)."
    },
    # 10. fileUploads
    {
        "category": "fileUploads",
        "name": "Insecure File Upload Handling",
        "file_exts": [".py", ".js"],
        "vuln_patterns": [r"request\.files", r"file\.save\(", r"multer\("],
        "sanitizer_patterns": [r"secure_filename", r"allowed_file", r"mime", r"extension_check"],
        "vuln_desc": "File ingest pipeline active without explicit runtime naming or mimetype isolation policies.",
        "safe_desc": "No attack surface found (Payload writes pass strict safe name and extension validation filters)."
    },
    # 11. fileDownloads
    {
        "category": "fileDownloads",
        "name": "Arbitrary File Path Traversal",
        "file_exts": [".py", ".js"],
        "vuln_patterns": [r"send_file\(", r"send_from_directory\(", r"fs\.readFile\("],
        "sanitizer_patterns": [r"safe_join", r"werkzeug\.utils", r"path\.resolve"],
        "vuln_desc": "Local data retrieval loops serving server assets through unvalidated path arguments.",
        "safe_desc": "No attack surface found (Path resolutions bound to isolated sandbox directories safely)."
    },
    # 12. redirects
    {
        "category": "redirects",
        "name": "Unvalidated Client Redirects",
        "file_exts": [".py", ".js"],
        "vuln_patterns": [r"redirect\(request", r"res\.redirect\("],
        "sanitizer_patterns": [r"url_parse", r"is_safe_url", r"whitelist"],
        "vuln_desc": "Open redirect interface exposed to client parameter manipulation vectors.",
        "safe_desc": "No attack surface found (Forced destination urls restricted to authorized local domain domains)."
    },
    # 13. adminPortals
    {
        "category": "adminPortals",
        "name": "Exposed Privileged Administrative Portal",
        "file_exts": [".py", ".js", ".html"],
        "vuln_patterns": [r"/admin", r"/dashboard/root", r"/superuser"],
        "sanitizer_patterns": [r"is_admin", r"require_sudo", r"IP_whitelist", r"MFA"],
        "vuln_desc": "Privileged routing interface paths defined inside client-accessible tracking domains.",
        "safe_desc": "No attack surface found (Administrative panels bound behind strict role evaluation checkpoints)."
    },
    # 14. userManagement
    {
        "category": "userManagement",
        "name": "IDOR profile modification context",
        "file_exts": [".py", ".js"],
        "vuln_patterns": [r"update_profile", r"change_password", r"delete_account"],
        "sanitizer_patterns": [r"current_user\.id", r"session\['user_id'\]", r"owner_check"],
        "vuln_desc": "Profile resource mutation controllers missing contextual cross-tenant access ownership locks.",
        "safe_desc": "No attack surface found (User updates verified strictly against immutable session context IDs)."
    },
    # 15. paymentSystems
    {
        "category": "paymentSystems",
        "name": "Custom Credit Card Data Handling",
        "file_exts": [".py", ".js"],
        "vuln_patterns": [r"card_number", r"cvv", r"credit_card", r"expiry_date"],
        "sanitizer_patterns": [r"stripe", r"braintree", r"paypal", r"pci_compliant"],
        "vuln_desc": "In-house management parameters referencing raw credit card metadata (PCI-DSS compliance breach).",
        "safe_desc": "No attack surface found (Payment fields managed offsite via authenticated standard gateway abstractions)."
    }
]
