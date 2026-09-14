"""IAM surface: authentication, authorization, session management, admin
portals, user management and OAuth/SSO detectors (surfaces 1, 2, 3, 13, 14, 16).
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from attack_surface.analysis import (
    JS_AUTH_MIDDLEWARE,
    SECRET_KEY_NAMES,
    function_body_source,
    handler_block,
    lookahead,
    lookbehind,
    looks_like_secret,
    make_hit,
    python_routes,
)
from attack_surface.models import FileContext, Hit, Rule, Severity

CODE_EXTS = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".rb", ".java", ".go", ".cs", ".kt", ".scala")
WEB_EXTS = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".rb", ".go", ".java", ".kt")
CONFIG_EXTS = (".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".env", ".php", ".rb")

# --------------------------------------------------------------------------- #
# 1. authentication
# --------------------------------------------------------------------------- #

_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
_SENSITIVE_PATH = re.compile(r"/(admin|user|users|account|accounts|profile|settings|manage|internal|delete|update|order|payment|billing)", re.I)
_API_PATH = re.compile(r"/(api|v\d+)/", re.I)
_MITIGATION_IN_BODY = re.compile(
    r"current_user|request\.user|g\.user|get_jwt_identity|session\[|is_authenticated|abort\(\s*40[13]|"
    r"raise\s+(Unauthorized|Forbidden|PermissionDenied|HTTPException\(\s*status_code\s*=\s*40[13])|check_permission|"
    r"has_permission|verify_token|authenticate\(|require_login|api_key\s*(==|!=)|Authorization",
    re.I,
)


def _hardcoded_credential(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    value = match.group("value")
    if not looks_like_secret(value, min_length=6, min_entropy=2.5):
        return None
    key = match.group("key").lower()
    severity = Severity.CRITICAL if re.search(r"password|passwd|pwd|secret|private", key) else Severity.HIGH
    return make_hit(ctx, line_no, column=match.start() + 1, severity=severity)


def _weak_hash_checker(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    window = ctx.window(line_no, 4, 4).lower()
    # Checksums / cache keys are legitimate uses of MD5 - lower confidence.
    if re.search(r"checksum|etag|cache[_-]?key|fingerprint|digest_for_cache|usedforsecurity\s*=\s*false|integrity", window):
        return make_hit(ctx, line_no, column=match.start() + 1, confidence=35, severity=Severity.LOW,
                        name="Weak hash used for non-security purpose",
                        description="MD5/SHA1 appears to be used as a checksum; verify it never protects credentials.")
    confidence = 95 if re.search(r"password|passwd|pwd|secret|token|credential|salt|login|auth", window) else 70
    return make_hit(ctx, line_no, column=match.start() + 1, confidence=confidence)


def _authz_python(rule: Rule, ctx: FileContext) -> Iterator[Hit]:
    for route in python_routes(ctx):
        if route.has_auth:
            continue
        if _API_PATH.search(route.path):
            continue  # covered by api-endpoints
        if re.search(r"webhook|/hook|/callback|/events?\b|/notify|/health|/ping|/status|/login|/register|/signup|/logout|/csrf|oauth", route.path, re.I):
            continue  # authenticated by signature/token, or intentionally public
        state_changing = bool(set(route.methods) & _STATE_CHANGING)
        sensitive = bool(_SENSITIVE_PATH.search(route.path))
        if not (state_changing or sensitive):
            continue
        body = function_body_source(ctx, route.func)
        mitigated = _MITIGATION_IN_BODY.search(body)
        confidence = 85 if state_changing and sensitive else 70
        yield Hit(
            line=route.lineno,
            snippet=ctx.line(route.lineno),
            confidence=confidence,
            mitigated_by=mitigated.group(0) if mitigated else None,
            skip_sanitizer_check=True,
            description=(
                f"Handler '{route.func.name}' for {route.path or '<dynamic path>'} "
                f"({', '.join(route.methods)}) has no authentication/authorization decorator."
            ),
        )


_JS_ROUTE = re.compile(
    r"\b(?:app|router|server|api|fastify|route)\s*\.\s*(?P<method>post|put|delete|patch|del)\s*\(\s*"
    r"(?P<quote>['\"`])(?P<path>[^'\"`]*)(?P=quote)\s*,\s*(?P<rest>.*)$",
    re.I,
)


def _authz_js(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    path = match.group("path")
    if _API_PATH.search(path):
        return None
    rest = match.group("rest")
    # A middleware between the path and the handler => something guards it.
    if not re.match(r"^(?:async\s*)?(?:\(|function\b|\w+\s*=>)", rest):
        return None
    if JS_AUTH_MIDDLEWARE.search(rest):
        return None
    block = lookahead(ctx, line_no, 25)
    mitigated = JS_AUTH_MIDDLEWARE.search(block) or re.search(r"\.use\(\s*\w*(auth|protect|verify|passport|guard)", ctx.text, re.I)
    return make_hit(ctx, line_no, column=match.start() + 1, confidence=70,
                    mitigated_by=mitigated.group(0) if mitigated else None, skip_sanitizer_check=True,
                    description=f"{match.group('method').upper()} {path} is registered without an auth middleware.")


# --------------------------------------------------------------------------- #
# 3. session-management
# --------------------------------------------------------------------------- #

_COOKIE_CALL = re.compile(r"\b(?:set_cookie|setCookie|res\.cookie|response\.cookie|cookies\.set|cookie\.set|Set-Cookie)\b", re.I)


def _cookie_flags(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    statement = ctx.statement(line_no, 10)
    low = statement.lower()
    if re.search(r"delete_cookie|clearcookie|clear_cookie|max_age\s*=\s*0|expires\s*=\s*0", low):
        return None
    missing: list[str] = []
    if not re.search(r"secure\s*[=:]\s*true|;\s*secure\b|\bsecure\b\s*[,)]|secure:\s*process\.env", low):
        missing.append("Secure")
    if not re.search(r"httponly\s*[=:]\s*true|;\s*httponly\b|http_only\s*[=:]\s*true|httponly\b\s*[,)]", low):
        missing.append("HttpOnly")
    if not re.search(r"samesite", low):
        missing.append("SameSite")
    if not missing:
        return None
    severity = Severity.HIGH if {"Secure", "HttpOnly"} <= set(missing) else Severity.MEDIUM
    if missing == ["SameSite"]:
        severity = Severity.LOW
    return make_hit(ctx, line_no, column=match.start() + 1, severity=severity, skip_sanitizer_check=True,
                    description=f"Cookie is set without the {', '.join(missing)} flag(s).")


def _jwt_decode_js(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    window = ctx.window(line_no, 5, 5)
    if re.search(r"jwt\.verify\(|jose\.|jwtVerify\(|verify\(", window):
        return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by="jwt.verify", skip_sanitizer_check=True)
    return make_hit(ctx, line_no, column=match.start() + 1)


# --------------------------------------------------------------------------- #
# 13. admin-portals
# --------------------------------------------------------------------------- #

_ADMIN_GUARD = re.compile(
    r"login_required|admin_required|staff_member_required|superuser|is_admin|isAdmin|requireAdmin|adminOnly|"
    r"role|permission|Depends\(|authenticate|\bauth\b|IsAdminUser|jwt_required|passport|verifyToken|guard|"
    r"protect|ensureAdmin|checkAdmin|admin\.site\.urls|before_action\s*:\s*\w*(auth|admin)|"
    r"AdminAuthenticationMiddleware|@admin\.register|admin_bp\.before_request",
    re.I,
)


def _admin_route(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    line = ctx.line(line_no)
    if re.search(r"admin\.site\.urls|admin\.register|django\.contrib\.admin|from\s+.*admin|import\s+admin|adminjs|AdminJS", line, re.I):
        return None
    if re.search(r"class\s+\w*Admin\s*\(|ModelAdmin|AdminSite", line):
        return None
    if ctx.ext == ".py":
        block = handler_block(ctx, line_no, 15)
        above = lookbehind(ctx, line_no, 5)
        guard = _ADMIN_GUARD.search(above + "\n" + line + "\n" + block)
    else:
        above = lookbehind(ctx, line_no, 3)
        below = lookahead(ctx, line_no, 12)
        guard = _ADMIN_GUARD.search(above + "\n" + line + "\n" + below)
    if guard and re.search(_ADMIN_GUARD, line):
        # Guard is on the very same line (e.g. Express middleware, decorator on one line) => properly protected.
        return None
    return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by=guard.group(0) if guard else None,
                    skip_sanitizer_check=True)


# --------------------------------------------------------------------------- #
# 14. user-management
# --------------------------------------------------------------------------- #

_OWNERSHIP = re.compile(
    r"current_user|request\.user|g\.user|req\.user|get_jwt_identity|session\[|session\.get\(|is_owner|\.owner\b|"
    r"check_password|verify_password|old_password|current_password|user_id\s*[!=]=|\.id\s*[!=]=|==\s*\w*user\w*\.id|"
    r"authorize|permission|abort\(\s*403|HTTP_403|Forbidden|PermissionDenied|has_object_permission|"
    r"IsOwner|get_object_or_404\([^)]*user|filter\([^)]*user\s*=|owner_id|created_by|belongs_to|can_edit|"
    r"ensure_owner|require_owner|self\.request\.user|@login_required|jwt_required|Depends\(|token",
    re.I,
)

_USER_MGMT_FUNC = re.compile(
    r"^\s*(?:async\s+)?(?:def|function)\s+(?P<name>\w*(?:change|update|reset|set|edit|modify|delete|remove)_?(?:password|profile|email|account|user|username|phone)\w*)\s*\(",
    re.I,
)
_USER_MGMT_ROUTE = re.compile(
    r"(?:@\s*[\w.]+\.(?:route|post|put|patch|delete)|\b(?:app|router)\s*\.\s*(?:post|put|patch|delete))\s*\(\s*['\"][^'\"]*"
    r"(?:password|profile|account|user|email|username|settings)[^'\"]*['\"]",
    re.I,
)


def _user_mgmt(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    line = ctx.line(line_no)
    if re.search(r"class\s|import\s|from\s|test_|spec\b|describe\(|it\(", line):
        return None
    block = handler_block(ctx, line_no, 35)
    # Only flag handlers that actually mutate user state.
    if not re.search(r"password|profile|email|\.save\(|update\(|UPDATE|set_password|commit\(|findOneAndUpdate|updateOne|\.update|patch|delete|destroy", block, re.I):
        return None
    ownership = _OWNERSHIP.search(block)
    return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by=ownership.group(0) if ownership else None,
                    skip_sanitizer_check=True, confidence=75 if not ownership else 45)


# --------------------------------------------------------------------------- #
# 16. oauth-sso
# --------------------------------------------------------------------------- #

_STATE_CHECK = re.compile(
    r"\bstate\b|oauth_state|verify_state|check_state|\bnonce\b|\bpkce\b|code_verifier|authorize_access_token|"
    r"passport\.authenticate|state\s*:\s*true|fetch_token\(|OAuth2Session|authlib|\bcsrf\b|id_token|"
    r"validate_state|compare_digest|session\.pop\(\s*['\"](?:state|oauth)",
    re.I,
)

_OAUTH_CALLBACK = re.compile(
    r"(?:@\s*[\w.]+\.(?:route|get|post)\s*\(\s*['\"][^'\"]*(?:oauth|callback|sso|auth/(?:google|github|facebook|okta|azure|microsoft|apple|twitter|discord|slack|login))[^'\"]*['\"]"
    r"|\b(?:app|router)\s*\.\s*(?:get|post)\s*\(\s*['\"][^'\"]*(?:oauth|callback|sso|auth/(?:google|github|facebook|okta|azure|microsoft|apple|twitter|discord|slack))[^'\"]*['\"]"
    r"|def\s+\w*(?:oauth|sso)\w*callback\w*\s*\(|def\s+\w*callback\w*\s*\(\s*(?:request|self)"
    r"|(?:request\.(?:args|GET|query_params)\.get|req\.query)\s*[\.(]\s*['\"]?code['\"]?)",
    re.I,
)


def _oauth_state(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    line = ctx.line(line_no)
    block = handler_block(ctx, line_no, 40)
    if not re.search(r"\bcode\b|access_token|token|oauth|client_id|client_secret|exchange|id_token", block, re.I):
        return None
    if re.search(r"webhook|stripe|payment|status_code|error_code|zip_code|postal|country_code|promo|coupon|otp|verification_code|sms_code|discount", line + block, re.I) and not re.search(r"oauth|client_id|redirect_uri|access_token", block, re.I):
        return None
    state = _STATE_CHECK.search(block)
    if state and re.search(r"\bstate\b", block) and re.search(r"(?:!=|==|compare|verify|check|pop\(|session)[^\n]*state|state[^\n]*(?:!=|==|compare|verify|check|session)", block, re.I):
        return None  # State is compared against the session => properly implemented.
    return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by=state.group(0) if state else None,
                    skip_sanitizer_check=True)


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

RULES: tuple[Rule, ...] = (
    # ---- 1. authentication ------------------------------------------------ #
    Rule(
        id="AUTH-001",
        surface="authentication",
        name="Weak password hashing algorithm (MD5/SHA1)",
        description="MD5 and SHA1 are broken for password storage and integrity of secrets.",
        severity=Severity.HIGH,
        cwe="CWE-328",
        confidence=80,
        extensions=CODE_EXTS,
        keywords=("md5", "sha1", "sha-1", "createhash", "messagedigest", "digest::"),
        patterns=(
            r"hashlib\.(?:md5|sha1)\s*\(",
            r"hashlib\.new\s*\(\s*['\"](?:md5|sha1)['\"]",
            r"crypto\.createHash\s*\(\s*['\"](?:md5|sha1)['\"]",
            r"MessageDigest\.getInstance\s*\(\s*['\"](?:MD5|SHA-?1)['\"]",
            r"\b(?:md5|sha1)\s*\(\s*\$",
            r"Digest::(?:MD5|SHA1)\.(?:hexdigest|digest)",
            r"\bmd5\.(?:Sum|New)\(|\bsha1\.(?:Sum|New)\(",
            r"password_hash\s*\([^)]*\bMD5\b",
        ),
        negatives=(r"usedforsecurity\s*=\s*False",),
        sanitizers=(r"\bbcrypt\b", r"\bargon2", r"pbkdf2", r"\bscrypt\b", r"generate_password_hash", r"password_hash\("),
        checker=_weak_hash_checker,
        recommendation="Use a slow, salted password hash (Argon2id, bcrypt, scrypt or PBKDF2-HMAC-SHA256).",
        remediation="Replace hashlib.md5/sha1 with argon2-cffi or bcrypt; for integrity checks use SHA-256 or HMAC.",
    ),
    Rule(
        id="AUTH-002",
        surface="authentication",
        name="Hardcoded credential in source code",
        description="A credential-like assignment with a literal value was found in application code.",
        severity=Severity.CRITICAL,
        cwe="CWE-798",
        confidence=85,
        extensions=CODE_EXTS,
        keywords=("password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "api-key", "credential", "private_key", "access_key"),
        patterns=(
            rf"(?<![\w.])(?P<key>{SECRET_KEY_NAMES})\s*(?::\s*(?:str|string|String)\s*)?[:=]\s*(?!==)[rbf]?(?P<quote>['\"])(?P<value>[^'\"]{4,})(?P=quote)",
            r"(?P<key>Authorization)['\"]?\s*[:=]\s*['\"](?:Basic|Bearer)\s+(?P<value>[A-Za-z0-9+/=._-]{12,})['\"]",
            r"(?P<key>auth)\s*=\s*\(\s*['\"][^'\"]+['\"]\s*,\s*['\"](?P<value>[^'\"]{4,})['\"]\s*\)",
        ),
        negatives=(
            r"os\.environ|getenv|process\.env|\$\{|\{\{|\bENV\[|System\.getenv|config\.|settings\.|input\(|getpass|prompt\(|"
            r"\.example|placeholder|example\.com|xxx|\*\*\*|<[^>]+>|password_field|password_hash|check_password|"
            r"verify_password|type\s*=\s*['\"]password|name\s*=\s*['\"]password|label|class(?:Name)?=|"
            r"\.d\.ts|interface\s|\bfaker\b|random|generate|uuid|\bmock|fixture|\bdummy\b|redacted|test_password|"
            r"PASSWORD_VALIDATORS|password_validation|MinimumLength|help_text|placeholder|regex|pattern|"
            r"re\.compile|match\(|__doc__"
        ),
        checker=_hardcoded_credential,
        sanitizer_scope="line",
        scan_comments=True,
        recommendation="Load credentials from environment variables or a secrets manager; never commit them.",
        remediation="Move the value to configuration injected at runtime (env var, Vault, AWS Secrets Manager) and rotate the exposed credential.",
    ),
    # ---- 2. authorization ------------------------------------------------- #
    Rule(
        id="AUTHZ-001",
        surface="authorization",
        name="State-changing endpoint without authorization decorator",
        description="A route handler that modifies data or serves a sensitive path has no auth decorator or dependency.",
        severity=Severity.HIGH,
        cwe="CWE-862",
        confidence=75,
        extensions=(".py",),
        file_checker=_authz_python,
        recommendation="Guard the handler with @login_required / Depends(get_current_user) / permission checks.",
        remediation="Add an authentication decorator or dependency and an explicit object-level permission check before mutating data.",
    ),
    Rule(
        id="AUTHZ-002",
        surface="authorization",
        name="State-changing route registered without auth middleware",
        description="An Express/Koa/Fastify style route for POST/PUT/PATCH/DELETE has a handler but no auth middleware.",
        severity=Severity.HIGH,
        cwe="CWE-862",
        confidence=70,
        extensions=(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
        keywords=(".post(", ".put(", ".delete(", ".patch(", ".del("),
        patterns=(_JS_ROUTE,),
        checker=_authz_js,
        recommendation="Insert an authentication middleware (passport, express-jwt, custom verifyToken) before the handler.",
        remediation="router.post('/path', requireAuth, handler) — or mount router.use(requireAuth) before the routes.",
    ),
    Rule(
        id="AUTHZ-003",
        surface="authorization",
        name="Authorization explicitly disabled",
        description="Framework setting turns authorization off for all views or the API.",
        severity=Severity.HIGH,
        cwe="CWE-285",
        confidence=90,
        extensions=(".py", ".js", ".ts", ".rb", ".yaml", ".yml", ".json"),
        keywords=("allowany", "permission_classes", "skip_authorization", "skip_before_action", "authorization: false", "auth: false", "authorization = false"),
        patterns=(
            r"DEFAULT_PERMISSION_CLASSES['\"]?\s*[:=]\s*[\[(]\s*['\"]rest_framework\.permissions\.AllowAny",
            r"permission_classes\s*=\s*[\[(]\s*[\]),]",
            r"skip_authorization_check|skip_before_action\s+:authenticate",
            r"['\"]?authorization['\"]?\s*[:=]\s*false",
            r"auth\s*:\s*false\s*[,}]",
        ),
        recommendation="Default to authenticated access and opt out only for explicitly public views.",
        remediation="Set DEFAULT_PERMISSION_CLASSES to IsAuthenticated and use AllowAny only on individual public views.",
    ),
    # ---- 3. session-management ------------------------------------------- #
    Rule(
        id="SESS-001",
        surface="session-management",
        name="Cookie set without Secure/HttpOnly/SameSite flags",
        description="Session or auth cookies missing hardening flags can be stolen via XSS or plaintext transport.",
        severity=Severity.MEDIUM,
        cwe="CWE-614",
        confidence=80,
        extensions=WEB_EXTS,
        keywords=("cookie",),
        patterns=(_COOKIE_CALL,),
        negatives=(r"^\s*(?:import|from|require)\b", r"cookie(?:s)?\.get\(", r"get_cookie|getCookie|cookie_name|CookieJar"),
        checker=_cookie_flags,
        recommendation="Set Secure, HttpOnly and SameSite=Lax/Strict on every session and authentication cookie.",
        remediation="response.set_cookie(name, value, secure=True, httponly=True, samesite='Lax')",
    ),
    Rule(
        id="SESS-002",
        surface="session-management",
        name="Insecure session cookie configuration",
        description="Framework-level cookie hardening is explicitly disabled.",
        severity=Severity.HIGH,
        cwe="CWE-614",
        confidence=95,
        extensions=CONFIG_EXTS,
        keywords=("cookie", "session"),
        patterns=(
            r"(?:SESSION|CSRF|REMEMBER)_COOKIE_(?:SECURE|HTTPONLY)\s*[:=]\s*(?:False|false|0)\b",
            r"SESSION_COOKIE_SAMESITE\s*[:=]\s*(?:None|['\"]None['\"])",
            r"cookie\s*:\s*\{[^}]*(?:secure|httpOnly)\s*:\s*false",
            r"secure\s*:\s*false\s*,?\s*(?://.*)?$",
            r"session\.cookie_secure\s*=\s*(?:0|Off)",
            r"session\.cookie_httponly\s*=\s*(?:0|Off)",
        ),
        recommendation="Enable secure and HttpOnly cookies in production settings.",
        remediation="SESSION_COOKIE_SECURE = True, SESSION_COOKIE_HTTPONLY = True, CSRF_COOKIE_SECURE = True",
    ),
    Rule(
        id="SESS-003",
        surface="session-management",
        name="JWT accepted without signature verification",
        description="Tokens are decoded with verification disabled or with the 'none' algorithm allowed.",
        severity=Severity.CRITICAL,
        cwe="CWE-347",
        confidence=95,
        extensions=WEB_EXTS,
        keywords=("jwt", "jose", "verify"),
        patterns=(
            r"jwt\.decode\s*\([^)]*verify\s*=\s*False",
            r"verify_signature['\"]?\s*:\s*False",
            r"jwt\.decode\s*\([^)]*options\s*=\s*\{[^}]*verify\w*\s*:\s*False",
            r"algorithms?\s*[=:]\s*\[?\s*['\"]none['\"]",
            r"JWT\.decode\s*\([^)]*,\s*nil\s*,\s*false",
            r"jwt\.decode\s*\([^)]*\{\s*complete\s*:\s*true\s*\}\s*\)\s*(?:\.|;)?\s*(?:$|//)",
            r"ignoreExpiration\s*:\s*true",
            r"verify\s*:\s*false",
        ),
        use_surface_indicators=False,
        recommendation="Always verify the signature and the algorithm allow-list when decoding JWTs.",
        remediation="jwt.decode(token, key, algorithms=['HS256']) — never pass verify=False or allow 'none'.",
    ),
    Rule(
        id="SESS-004",
        surface="session-management",
        name="Unverified jwt.decode() used for authentication",
        description="jsonwebtoken's decode() does not verify signatures; use verify() instead.",
        severity=Severity.HIGH,
        cwe="CWE-347",
        confidence=70,
        extensions=(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
        keywords=("jwt.decode", "jsonwebtoken"),
        patterns=(r"\bjwt\.decode\s*\(",),
        checker=_jwt_decode_js,
        recommendation="Use jwt.verify(token, secret, {algorithms: [...]}) for any trust decision.",
        remediation="Replace jwt.decode with jwt.verify and handle verification errors explicitly.",
    ),
    Rule(
        id="SESS-005",
        surface="session-management",
        name="Weak or default session secret",
        description="A short, well-known or placeholder value is used as the session signing secret.",
        severity=Severity.HIGH,
        cwe="CWE-1392",
        confidence=90,
        extensions=CONFIG_EXTS,
        keywords=("secret", "keyboard cat"),
        patterns=(
            r"(?:SECRET_KEY|SESSION_SECRET|JWT_SECRET|secret)\s*[:=]\s*['\"](?:secret|changeme|change_me|dev|development|test|password|keyboard cat|mysecret|supersecret|123456?|abc123|your-secret-key|your_secret_key|s3cr3t|secretkey|jwtsecret)['\"]",
            r"(?:SECRET_KEY|SESSION_SECRET|JWT_SECRET)\s*[:=]\s*['\"][^'\"]{1,11}['\"]\s*(?:#.*|//.*)?$",
        ),
        use_surface_indicators=False,
        recommendation="Generate a long random secret (>= 32 bytes) and inject it from the environment.",
        remediation="SECRET_KEY = os.environ['SECRET_KEY']  # generated with secrets.token_urlsafe(48)",
    ),
    # ---- 13. admin-portals ------------------------------------------------ #
    Rule(
        id="ADM-001",
        surface="admin-portals",
        name="Admin route registered without access control",
        description="An /admin route definition has no authentication or role guard attached.",
        severity=Severity.HIGH,
        cwe="CWE-284",
        confidence=80,
        extensions=WEB_EXTS,
        keywords=("admin",),
        patterns=(
            r"(?:@\s*[\w.]+\.(?:route|get|post|put|delete|patch|api_route)|\b(?:app|router|server|api)\s*\.\s*(?:get|post|put|delete|patch|use|all|route)|\bpath|\bre_path|\burl|\bHandleFunc|\bHandle|\bGET|\bPOST|\bmount|\bnamespace|\bget|\bpost)\s*\(\s*r?['\"`][^'\"`]*/admin(?:istrator|istration)?(?:/[^'\"`]*)?['\"`]",
            r"(?:@\s*[\w.]+\.(?:route|get|post|put|delete|patch))\s*\(\s*r?['\"`][^'\"`]*(?:/manage|/backoffice|/control-?panel|/superuser|/internal)[^'\"`]*['\"`]",
        ),
        negatives=(r"^\s*(?:import|from|require)\b", r"static|assets|\.css|\.js['\"]", r"redirect\(", r"test_|spec\.|describe\("),
        checker=_admin_route,
        recommendation="Protect admin routes with an authentication + admin role check at the router level.",
        remediation="Apply @admin_required (or router.use('/admin', requireAdmin)) and restrict by network where possible.",
    ),
    Rule(
        id="ADM-002",
        surface="admin-portals",
        name="Admin interface with default or disabled protection",
        description="Configuration exposes an admin console with default credentials or no login.",
        severity=Severity.CRITICAL,
        cwe="CWE-1188",
        confidence=90,
        extensions=CONFIG_EXTS + (".xml", ".sh", ".dockerfile"),
        keywords=("admin", "management", "console"),
        patterns=(
            r"(?:admin|ADMIN)_(?:PASSWORD|PASS|PWD)\s*[:=]\s*['\"]?(?:admin|password|admin123|changeme|123456|root|secret|test)['\"]?\s*$",
            r"enable_admin_(?:console|ui|portal)\s*[:=]\s*true",
            r"admin\.enabled\s*[:=]\s*true",
            r"management\.security\.enabled\s*[:=]\s*false",
            r"security\.basic\.enabled\s*[:=]\s*false",
            r"ADMIN_NO_AUTH\s*[:=]\s*(?:true|1)",
            r"DJANGO_SUPERUSER_PASSWORD\s*[:=]\s*['\"]?(?:admin|password|admin123|changeme|123456)",
            r"GF_SECURITY_ADMIN_PASSWORD\s*[:=]\s*['\"]?(?:admin|password|changeme)['\"]?\s*$",
            r"GF_AUTH_ANONYMOUS_ENABLED\s*[:=]\s*['\"]?true",
        ),
        use_surface_indicators=False,
        recommendation="Require strong unique admin credentials and never disable admin authentication.",
        remediation="Remove default admin passwords, enable authentication on management consoles and bind them to internal networks.",
    ),
    # ---- 14. user-management ---------------------------------------------- #
    Rule(
        id="USR-001",
        surface="user-management",
        name="User/password/profile update without ownership check",
        description="A handler modifies user attributes without verifying the caller owns the target account.",
        severity=Severity.HIGH,
        cwe="CWE-639",
        confidence=75,
        extensions=WEB_EXTS,
        keywords=("password", "profile", "account", "email", "user", "username", "settings"),
        patterns=(_USER_MGMT_FUNC, _USER_MGMT_ROUTE),
        checker=_user_mgmt,
        recommendation="Verify request.user matches the target user (or has admin rights) and require the current password for password changes.",
        remediation="Load the target user via the authenticated identity (current_user) instead of an id from the request, and re-authenticate before changing the password.",
    ),
    Rule(
        id="USR-002",
        surface="user-management",
        name="Mass assignment of user attributes",
        description="Request data is mapped wholesale onto a user model, allowing privilege fields (is_admin, role) to be set.",
        severity=Severity.HIGH,
        cwe="CWE-915",
        confidence=80,
        extensions=WEB_EXTS,
        keywords=("user", "update", "**", "assign", "permit", "params"),
        patterns=(
            r"User(?:\.objects)?\.(?:create|update|update_or_create)\s*\(\s*\*\*\s*(?:request\.(?:json|form|data|POST|get_json\(\))|data|payload|body|params)\b",
            r"\bUser\s*\(\s*\*\*\s*(?:request\.(?:json|form|data|POST)|data|payload|body|params)\b",
            r"user\.update\s*\(\s*(?:request\.body|req\.body|params|payload|data)\s*\)",
            r"User\.(?:findByIdAndUpdate|findOneAndUpdate|updateOne)\s*\([^,]+,\s*req\.body\s*[,)]",
            r"Object\.assign\s*\(\s*user\s*,\s*req\.body\s*\)",
            r"\{\s*\.\.\.\s*user\s*,\s*\.\.\.\s*req\.body\s*\}",
            r"params\.require\(\s*:user\s*\)\.permit!",
            r"User\.new\(\s*params\[:user\]\s*\)",
            r"setattr\(\s*user\s*,\s*\w+\s*,\s*\w+\s*\)\s*$",
        ),
        sanitizers=(r"permit\(", r"allowed_fields", r"ALLOWED_FIELDS", r"fields\s*=", r"exclude\s*=", r"pick\(", r"schema", r"Serializer", r"pydantic", r"whitelist", r"allowlist", r"only\("),
        recommendation="Explicitly allow-list updatable fields (pydantic/marshmallow schema, strong params, lodash pick).",
        remediation="Build the update payload from a fixed set of fields and never map raw request bodies onto the user model.",
    ),
    # ---- 16. oauth-sso ---------------------------------------------------- #
    Rule(
        id="OAUTH-001",
        surface="oauth-sso",
        name="OAuth callback without state/nonce validation",
        description="The authorization code is exchanged without checking the anti-CSRF state parameter.",
        severity=Severity.HIGH,
        cwe="CWE-352",
        confidence=80,
        extensions=WEB_EXTS,
        keywords=("oauth", "callback", "sso", "code", "auth/"),
        patterns=(_OAUTH_CALLBACK,),
        negatives=(r"^\s*(?:import|from|require)\b", r"status_code|error_code|zip_code|country_code|promo_code|coupon|otp|verification_code|sms_code|invite_code|referral"),
        checker=_oauth_state,
        recommendation="Generate a random state (and nonce/PKCE verifier) before redirecting and compare it in the callback.",
        remediation="Store state in the session on /login, then in /callback verify request.args['state'] == session.pop('oauth_state') before exchanging the code.",
    ),
    Rule(
        id="OAUTH-002",
        surface="oauth-sso",
        name="Insecure OAuth / SSO client configuration",
        description="OAuth client settings weaken the flow (implicit grant, wildcard redirect URIs, disabled TLS verification, insecure transport).",
        severity=Severity.HIGH,
        cwe="CWE-346",
        confidence=90,
        extensions=CONFIG_EXTS,
        keywords=("oauth", "redirect_uri", "response_type", "insecure_transport", "saml", "sso", "validate_iss", "verify_at_hash"),
        patterns=(
            r"OAUTHLIB_INSECURE_TRANSPORT\s*[\]=:'\"]+\s*['\"]?(?:1|true)['\"]?",
            r"response_type\s*[:=]\s*['\"]token['\"]",
            r"redirect_uris?\s*[:=]\s*\[?\s*['\"][^'\"]*\*[^'\"]*['\"]",
            r"(?:verify_ssl|verify_tls|ssl_verify)\s*[:=]\s*(?:False|false)",
            r"(?:validate_iss|verify_at_hash|verify_aud|verify_iss|validate_signature|wantAssertionsSigned|want_assertions_signed|strict)\s*[:=]\s*(?:False|false)",
            r"allow_unsafe_redirect\s*[:=]\s*(?:True|true)",
            r"skip_state_check\s*[:=]\s*(?:True|true)",
            r"state\s*[:=]\s*(?:False|false|None|null)\b",
        ),
        use_surface_indicators=False,
        recommendation="Use the authorization-code flow with PKCE, exact-match redirect URIs and strict token validation.",
        remediation="Remove wildcard redirect URIs, keep TLS verification on and never set OAUTHLIB_INSECURE_TRANSPORT outside local tests.",
    ),
)
