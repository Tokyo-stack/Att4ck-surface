"""Single source of truth for the 40 attack surfaces and the rule registry.

Every surface is described once here (number, key, human name, description,
owning package, default severity, CWE, and surface-wide sanitization
indicators).  Detection rules live in the surface packages and are collected
by :func:`load_rules`.  Adding a new surface means adding a :class:`Surface`
entry below, dropping a module into the matching package and listing it in
``RULE_MODULES``.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from functools import lru_cache

from attack_surface.models import Rule, Severity, compile_all

# --------------------------------------------------------------------------- #
# Surface catalogue
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Surface:
    """Static metadata for one attack surface."""

    number: int
    key: str
    name: str
    description: str
    package: str
    default_severity: Severity
    cwe: str
    sanitization_indicators: tuple[str, ...] = ()
    _indicators: tuple[re.Pattern[str], ...] = field(default=(), repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_indicators", compile_all(self.sanitization_indicators, re.IGNORECASE))

    def find_indicator(self, text: str) -> str | None:
        for pattern in self._indicators:
            match = pattern.search(text)
            if match:
                return match.group(0)
        return None


IAM = "iam"
INPUT = "input"
API = "api"
FILE = "file"
FRONTEND = "frontend"
SECRET = "secret"
INFRASTRUCTURE = "infrastructure"
COMMUNICATION = "communication"

PACKAGES: dict[str, str] = {
    IAM: "attack_surface.iam_surface",
    INPUT: "attack_surface.input_surface",
    API: "attack_surface.api_surface",
    FILE: "attack_surface.file_surface",
    FRONTEND: "attack_surface.frontend_surface",
    SECRET: "attack_surface.secret_surface",
    INFRASTRUCTURE: "attack_surface.infrastructure_surface",
    COMMUNICATION: "attack_surface.communication_surface",
}

SURFACES: tuple[Surface, ...] = (
    Surface(1, "authentication", "Authentication",
            "Weak hashing (MD5/SHA1), hardcoded credentials.", IAM, Severity.HIGH, "CWE-287",
            (r"\bbcrypt\b", r"\bargon2", r"pbkdf2", r"\bscrypt\b", r"usedforsecurity\s*=\s*False")),
    Surface(2, "authorization", "Authorization",
            "Exposed endpoints lacking decorators.", IAM, Severity.HIGH, "CWE-862",
            (r"login_required", r"permission_required", r"jwt_required", r"requires?_auth", r"auth_required",
             r"roles?_required", r"has_perm", r"Depends\(", r"current_user", r"request\.user", r"is_authenticated",
             r"\bauthenticate\b", r"isAuthenticated", r"requireAuth", r"verifyToken", r"passport\.", r"ensureLoggedIn")),
    Surface(3, "session-management", "Session Management",
            "Insecure cookie flags or unverified JWTs.", IAM, Severity.HIGH, "CWE-614",
            (r"secure\s*[=:]\s*true", r"httponly\s*[=:]\s*true", r"samesite", r"jwt\.verify\(", r"verify_signature['\"]\s*:\s*True")),
    Surface(4, "user-inputs", "User Inputs",
            "Dangerous dynamic exec inputs (eval, exec).", INPUT, Severity.CRITICAL, "CWE-94",
            (r"shlex\.quote", r"ast\.literal_eval", r"escapeshellarg", r"escapeshellcmd", r"allowlist", r"whitelist",
             r"execFile\(", r"\bspawn\(")),
    Surface(5, "search-parameters", "Search Parameters",
            "Insecure search parameters (reflected XSS).", INPUT, Severity.HIGH, "CWE-79",
            (r"html\.escape", r"markupsafe", r"\bescape\(", r"\bbleach\b", r"DOMPurify", r"htmlspecialchars",
             r"textContent", r"encodeURIComponent", r"render_template\((?!_string)", r"\bsanitize")),
    Surface(6, "id-parameters", "ID Parameters",
            "Unvalidated ID variables mapped to SQL.", INPUT, Severity.CRITICAL, "CWE-89",
            (r"\bint\(", r"parseInt\(", r"Number\(", r"\buuid\b", r"UUID\(", r"ObjectId\(", r"isdigit\(", r"isnumeric\(",
             r"\bvalidate", r"pydantic", r"marshmallow", r"get_object_or_404", r"\.filter\(", r"\bintval\(")),
    Surface(7, "api-endpoints", "API Endpoints",
            "Unauthenticated API paths.", API, Severity.HIGH, "CWE-306",
            (r"login_required", r"jwt_required", r"permission_classes", r"IsAuthenticated", r"Depends\(",
             r"requireAuth", r"authenticate", r"verifyToken", r"api_key_required", r"token_required", r"passport\.")),
    Surface(8, "graphql", "GraphQL",
            "Dynamic GraphQL query constructs.", INPUT, Severity.HIGH, "CWE-943",
            (r"variables\s*[:=]", r"\$\w+\s*:\s*(String|ID|Int|Float|Boolean|\[)", r"introspection\s*[:=]\s*false",
             r"depth_limit", r"depthLimit", r"complexity")),
    Surface(9, "webhooks", "Webhooks",
            "Webhooks receiving events without HMAC verification.", API, Severity.HIGH, "CWE-345",
            (r"\bhmac\b", r"compare_digest", r"construct_event", r"verify_signature", r"X-Hub-Signature",
             r"Stripe-Signature", r"X-Slack-Signature", r"RequestValidator", r"timingSafeEqual", r"\bsvix\b",
             r"verify_webhook", r"verifyWebhook", r"signature")),
    Surface(10, "file-uploads", "File Uploads",
            "Arbitrary file uploads without name checks.", FILE, Severity.HIGH, "CWE-434",
            (r"secure_filename", r"allowed_file", r"ALLOWED_EXTENSIONS", r"fileFilter", r"\bmimetype\b",
             r"content_type", r"splitext", r"\.endswith\(", r"\bmagic\b", r"imghdr", r"uuid", r"MAX_CONTENT_LENGTH",
             r"fileSize", r"limits\s*:", r"allowlist", r"whitelist")),
    Surface(11, "file-downloads", "File Downloads",
            "Path traversal vulnerability in serving files.", FILE, Severity.HIGH, "CWE-22",
            (r"secure_filename", r"safe_join", r"\bbasename\(", r"realpath", r"is_relative_to", r"\.resolve\(\)",
             r"startswith\(", r"path\.normalize", r"root\s*:", r"\.\.\s*(in|not in)", r"allowlist", r"whitelist")),
    Surface(12, "redirects", "Redirects",
            "Open redirect endpoints.", FILE, Severity.MEDIUM, "CWE-601",
            (r"url_has_allowed_host_and_scheme", r"is_safe_url", r"url_for\(", r"ALLOWED_REDIRECT", r"allowed_hosts",
             r"\.netloc\b", r"urlparse\(", r"startswith\(\s*['\"]/", r"safe_redirect", r"validate_redirect", r"allowlist",
             r"whitelist")),
    Surface(13, "admin-portals", "Admin Portals",
            "Unsecured admin route definitions.", IAM, Severity.HIGH, "CWE-284",
            (r"login_required", r"admin_required", r"staff_member_required", r"superuser", r"is_admin", r"isAdmin",
             r"requireAdmin", r"role", r"permission", r"Depends\(", r"authenticate", r"\bauth\b", r"IsAdminUser",
             r"admin\.site\.urls")),
    Surface(14, "user-management", "User Management",
            "User password/profile adjustments missing ownership checks.", IAM, Severity.HIGH, "CWE-639",
            (r"current_user", r"request\.user", r"g\.user", r"req\.user", r"get_jwt_identity", r"session\[",
             r"is_owner", r"owner", r"check_password", r"verify_password", r"old_password", r"current_password",
             r"user_id\s*[!=]=", r"\.id\s*[!=]=", r"authorize", r"permission")),
    Surface(15, "payment-systems", "Payment Systems",
            "Custom credit card detail handling (non-PCI compliance).", SECRET, Severity.CRITICAL, "CWE-311",
            (r"\bstripe\b", r"braintree", r"tokeni[sz]", r"payment_method", r"paymentIntent", r"\badyen\b",
             r"\bsquare\b", r"paypal", r"last4", r"last_four", r"masked", r"\*{4}", r"encrypt")),
    Surface(16, "oauth-sso", "OAuth / SSO",
            "Missing state checks in OAuth callback hooks.", IAM, Severity.HIGH, "CWE-352",
            (r"\bstate\b", r"oauth_state", r"verify_state", r"check_state", r"\bnonce\b", r"\bpkce\b", r"code_verifier",
             r"authorize_access_token", r"passport\.", r"state\s*:\s*true")),
    Surface(17, "email-flows", "Email Flows",
            "SMTP connections vulnerable to header injection.", COMMUNICATION, Severity.MEDIUM, "CWE-93",
            (r"\\r", r"\\n", r"replace\(\s*['\"]\\[rn]", r"\.strip\(", r"validate_email", r"email_validator",
             r"EmailValidator", r"BadHeaderError", r"sanitize", r"starttls\(", r"SMTP_SSL", r"secure\s*:\s*true")),
    Surface(18, "notification-services", "Notification Services",
            "Plaintext sensitive SMS or notifications.", COMMUNICATION, Severity.MEDIUM, "CWE-319",
            (r"encrypt", r"masked", r"\*{4}", r"last4", r"redact", r"magic_link", r"one_time_link", r"expires_in",
             r"hash")),
    Surface(19, "frontend-assets", "Frontend Assets",
            "Missing Subresource Integrity (SRI) on CDNs.", FRONTEND, Severity.MEDIUM, "CWE-353",
            (r"integrity\s*=", r"crossorigin")),
    Surface(20, "javascript-analysis", "JavaScript Analysis",
            "Raw DOM writes (innerHTML, document.write).", FRONTEND, Severity.HIGH, "CWE-79",
            (r"DOMPurify", r"sanitizeHtml", r"sanitize\(", r"escapeHtml", r"escape\(", r"encodeURIComponent",
             r"createTextNode", r"textContent", r"he\.encode", r"filterXSS", r"\bxss\(", r"purify")),
    Surface(21, "secrets-config", "Secrets Config",
            "Hardcoded keys in config files (.json, .ini).", SECRET, Severity.CRITICAL, "CWE-798",
            (r"\$\{", r"\{\{", r"process\.env", r"os\.environ", r"getenv", r"vault", r"keyring", r"secretsmanager",
             r"ssm:", r"KMS")),
    Surface(22, "environment-files", "Environment Files",
            "Actual secrets stored in env template files.", SECRET, Severity.HIGH, "CWE-540", ()),
    Surface(23, "cloud-storage", "Cloud Storage",
            "Public read S3 configurations.", INFRASTRUCTURE, Severity.HIGH, "CWE-732",
            (r"\bCondition\b", r"aws:SourceArn", r"aws:SourceVpce", r"aws:Referer", r"CloudFront", r"OriginAccessIdentity",
             r"\"Effect\"\s*:\s*\"Deny\"", r"private")),
    Surface(24, "database", "Database",
            "SQL injection patterns via string formatting.", INPUT, Severity.CRITICAL, "CWE-89",
            (r"\?\s*,", r"%s", r":\w+\s*\)", r"\$\d\b", r"prepare\(", r"bind_param", r"bindValue", r"parameterized",
             r"placeholders", r"sql\.Identifier", r"psycopg2\.sql", r"quote_ident")),
    Surface(25, "cache-services", "Cache Services",
            "Redis/Memcached keys set without encryption or limits.", INFRASTRUCTURE, Severity.MEDIUM, "CWE-312",
            (r"\bex\s*=", r"\bpx\s*=", r"setex", r"\.expire\(", r"ttl", r"timeout\s*=", r"encrypt", r"fernet", r"cipher",
             r"rediss://", r"ssl\s*=\s*True", r"password\s*=", r"tls\s*:")),
    Surface(26, "message-queues", "Message Queues",
            "Insecure deserialization formats (e.g. pickle payload parsing).", INFRASTRUCTURE, Severity.CRITICAL, "CWE-502",
            (r"\bhmac\b", r"compare_digest", r"signature", r"verify", r"json\.loads", r"itsdangerous", r"signed",
             r"trusted")),
    Surface(27, "logging", "Logging",
            "Plaintext login logs or PII logged in file output.", INFRASTRUCTURE, Severity.MEDIUM, "CWE-532",
            (r"\bmask", r"redact", r"scrub", r"obfuscat", r"\*{3,}", r"\bhash", r"len\(", r"\.length\b", r"last4",
             r"\[:4\]", r"filter", r"sanitize")),
    Surface(28, "monitoring", "Monitoring",
            "Exposed metrics endpoints without protection.", API, Severity.MEDIUM, "CWE-200",
            (r"\bauth", r"basic_auth", r"BasicAuth", r"token", r"login_required", r"allowlist", r"whitelist",
             r"ip_whitelist", r"internal", r"127\.0\.0\.1", r"localhost", r"Depends\(", r"protect", r"security")),
    Surface(29, "debug-endpoints", "Debug Endpoints",
            "Active debug mode or debug console routes.", API, Severity.HIGH, "CWE-489",
            (r"if\s+__name__", r"os\.environ", r"getenv", r"env\(", r"process\.env", r"NODE_ENV\s*!==?\s*['\"]production",
             r"settings\.DEBUG", r"if\s+.*debug", r"development only", r"dev only")),
    Surface(30, "documentation", "Documentation",
            "Swagger or Redoc files exposed without authorization.", API, Severity.LOW, "CWE-200",
            (r"\bauth", r"login_required", r"basic_auth", r"permission", r"Depends\(", r"protect", r"password",
             r"IsAuthenticated", r"IsAdminUser", r"settings\.DEBUG", r"if\s+.*debug", r"docs_url\s*=\s*None")),
    Surface(31, "third-party-integrations", "Third-Party Integrations",
            "Requests to outbound services missing timeouts (SSRF).", API, Severity.HIGH, "CWE-918",
            (r"allowlist", r"whitelist", r"ALLOWED_HOSTS", r"ALLOWED_DOMAINS", r"urlparse\(", r"validate_url",
             r"is_safe_url", r"ipaddress\.", r"is_private", r"hostname\s+(in|not in)", r"timeout\s*[=:]")),
    Surface(32, "dependencies", "Dependencies",
            "Outdated or unpinned versions in package lists.", INFRASTRUCTURE, Severity.MEDIUM, "CWE-1104", ()),
    Surface(33, "ci-cd", "CI/CD",
            "Hardcoded tokens in GitHub Actions YAML files.", SECRET, Severity.CRITICAL, "CWE-798",
            (r"\$\{\{\s*secrets\.", r"\$\{\{\s*env\.", r"\$\w+", r"\$\(", r"vault", r"secretsmanager", r"\bmasked\b")),
    Surface(34, "backups", "Backups",
            "Storing temporary/backup files inside local code.", FILE, Severity.LOW, "CWE-530", ()),
    Surface(35, "subdomains", "Subdomains",
            "Hardcoded staging/development server subdomains.", INFRASTRUCTURE, Severity.LOW, "CWE-200",
            (r"os\.environ", r"getenv", r"process\.env", r"\$\{", r"\{\{", r"config\.", r"settings\.")),
    Surface(36, "dns", "DNS",
            "Insecure DNS resolution implementations.", INFRASTRUCTURE, Severity.MEDIUM, "CWE-350",
            (r"want_dnssec", r"dnssec", r"\bdoh\b", r"\bdot\b", r"https://dns", r"dns\.google", r"cloudflare-dns",
             r"allowlist", r"whitelist", r"ALLOWED_HOSTS", r"validate_host", r"hostname\s+(in|not in)", r"timeout")),
    Surface(37, "server-config", "Server Config",
            "Wide CORS wildcards (Access-Control-Allow-Origin: *).", INFRASTRUCTURE, Severity.MEDIUM, "CWE-942",
            (r"origins?\s*[=:]\s*\[?\s*['\"]https?://", r"ALLOWED_ORIGINS", r"CORS_ALLOWED_ORIGINS", r"allowlist",
             r"whitelist", r"if\s+origin\s+in")),
    Surface(38, "containers", "Containers",
            "Dockerfiles using latest tags or running as root.", INFRASTRUCTURE, Severity.MEDIUM, "CWE-250",
            (r"^\s*USER\s+(?!root\b|0\b)\w+", r"runAsNonRoot\s*:\s*true", r"runAsUser\s*:\s*[1-9]\d*", r"@sha256:")),
    Surface(39, "source-control", "Source Control",
            "Credentials exposed in VCS clones.", SECRET, Severity.CRITICAL, "CWE-522",
            (r"\$\{", r"\{\{", r"\$\w+", r"credential\.helper\s*=?\s*(manager|osxkeychain|libsecret|cache)", r"ssh://",
             r"git@")),
    Surface(40, "miscellaneous", "Miscellaneous",
            "Insecure library methods (like standard yaml.load).", INPUT, Severity.MEDIUM, "CWE-20",
            (r"SafeLoader", r"safe_load", r"defusedxml", r"secrets\.", r"SystemRandom", r"os\.urandom",
             r"weights_only\s*=\s*True", r"verify\s*=\s*True", r"CERT_REQUIRED", r"mkstemp", r"NamedTemporaryFile")),
)

SURFACE_BY_KEY: dict[str, Surface] = {s.key: s for s in SURFACES}
SURFACE_KEYS: tuple[str, ...] = tuple(s.key for s in SURFACES)
SURFACE_COUNT = len(SURFACES)

assert SURFACE_COUNT == 40, "The catalogue must describe exactly 40 surfaces"
assert len(SURFACE_BY_KEY) == 40, "Surface keys must be unique"
assert tuple(s.number for s in SURFACES) == tuple(range(1, 41)), "Surfaces must be numbered 1..40"

# --------------------------------------------------------------------------- #
# Rule registry
# --------------------------------------------------------------------------- #

#: Modules that export a ``RULES`` sequence.  Drop a new module into a surface
#: package and list it here to have its rules picked up automatically.
RULE_MODULES: tuple[str, ...] = (
    "attack_surface.iam_surface.iam",
    "attack_surface.input_surface.input",
    "attack_surface.api_surface.api",
    "attack_surface.file_surface.file",
    "attack_surface.frontend_surface.frontend",
    "attack_surface.secret_surface.secret",
    "attack_surface.infrastructure_surface.infrastructure",
    "attack_surface.communication_surface.communications",
)


class RuleRegistryError(RuntimeError):
    """Raised when the loaded rule set is inconsistent."""


@lru_cache(maxsize=1)
def load_rules() -> tuple[Rule, ...]:
    """Import every rule module and return the validated, de-duplicated rule set."""
    rules: list[Rule] = []
    seen_ids: set[str] = set()
    for module_name in RULE_MODULES:
        module = importlib.import_module(module_name)
        exported = getattr(module, "RULES", None)
        if not exported:
            raise RuleRegistryError(f"{module_name} does not export RULES")
        for rule in exported:
            if not isinstance(rule, Rule):
                raise RuleRegistryError(f"{module_name} exported a non-Rule object: {rule!r}")
            if rule.surface not in SURFACE_BY_KEY:
                raise RuleRegistryError(f"Rule {rule.id} references unknown surface {rule.surface!r}")
            if rule.id in seen_ids:
                raise RuleRegistryError(f"Duplicate rule id {rule.id}")
            seen_ids.add(rule.id)
            rules.append(rule)

    covered = {rule.surface for rule in rules}
    missing = [key for key in SURFACE_KEYS if key not in covered]
    if missing:
        raise RuleRegistryError(f"Surfaces without detection rules: {', '.join(missing)}")
    return tuple(rules)


def rules_for_surfaces(surfaces: Iterable[str] | None = None) -> tuple[Rule, ...]:
    """Return rules for the selected surface keys (all surfaces when empty)."""
    selected = resolve_surface_keys(surfaces)
    wanted = set(selected)
    return tuple(rule for rule in load_rules() if rule.surface in wanted)


def resolve_surface_keys(surfaces: Iterable[str] | None) -> tuple[str, ...]:
    """Normalise user-supplied surface selectors (keys, numbers, packages)."""
    if not surfaces:
        return SURFACE_KEYS
    resolved: list[str] = []
    for raw in surfaces:
        for token in str(raw).split(","):
            token = token.strip().lower()
            if not token:
                continue
            if token == "all":
                return SURFACE_KEYS
            if token in SURFACE_BY_KEY:
                resolved.append(token)
            elif token.isdigit() and 1 <= int(token) <= SURFACE_COUNT:
                resolved.append(SURFACES[int(token) - 1].key)
            elif token in PACKAGES:
                resolved.extend(s.key for s in SURFACES if s.package == token)
            else:
                candidates = [s.key for s in SURFACES if token in s.key or token in s.name.lower()]
                if not candidates:
                    raise ValueError(f"Unknown surface selector: {raw!r}")
                resolved.extend(candidates)
    ordered = [key for key in SURFACE_KEYS if key in set(resolved)]
    return tuple(ordered)


def rules_by_surface(rules: Sequence[Rule] | None = None) -> dict[str, list[Rule]]:
    grouped: dict[str, list[Rule]] = {key: [] for key in SURFACE_KEYS}
    for rule in rules or load_rules():
        grouped[rule.surface].append(rule)
    return grouped


def get_rule(rule_id: str) -> Rule | None:
    for rule in load_rules():
        if rule.id == rule_id:
            return rule
    return None


__all__ = [
    "Surface",
    "SURFACES",
    "SURFACE_BY_KEY",
    "SURFACE_KEYS",
    "SURFACE_COUNT",
    "PACKAGES",
    "RULE_MODULES",
    "RuleRegistryError",
    "Rule",
    "Severity",
    "load_rules",
    "rules_for_surfaces",
    "resolve_surface_keys",
    "rules_by_surface",
    "get_rule",
]
