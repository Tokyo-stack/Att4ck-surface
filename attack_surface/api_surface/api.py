"""API surface: unauthenticated API paths, webhooks, monitoring endpoints,
debug endpoints, documentation exposure and outbound integrations
(surfaces 7, 9, 28, 29, 30, 31).
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from attack_surface.analysis import (
    JS_AUTH_MIDDLEWARE,
    arg_tainted,
    call_name,
    function_body_source,
    handler_block,
    has_input,
    has_keyword,
    hit_from_node,
    is_constant_str,
    iter_calls,
    keyword_value,
    lookahead,
    lookbehind,
    make_hit,
    node_source,
    node_tainted,
    python_routes,
)
from attack_surface.models import FileContext, Hit, Rule, Severity

WEB_EXTS = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".rb", ".go", ".java", ".kt", ".cs")
CONFIG_EXTS = (".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".env", ".php", ".rb", ".xml", ".sh")

# --------------------------------------------------------------------------- #
# 7. api-endpoints
# --------------------------------------------------------------------------- #

_API_PATH = re.compile(r"(?:^|['\"`])/(?:api|rest|graphql|v\d+)(?:/|['\"`]|$)", re.I)
_PUBLIC_HINT = re.compile(r"public|health|ping|status|login|register|signup|sign-up|signin|sign-in|token|auth/|oauth|webhook|callback|docs|openapi|swagger|version|csrf|captcha|forgot|reset|verify|contact|search|catalog|products?|feed|rss|sitemap|robots|logout|refresh", re.I)
_BODY_AUTH = re.compile(
    r"current_user|request\.user|g\.user|get_jwt_identity|session\[|is_authenticated|abort\(\s*40[13]|"
    r"HTTPException\(\s*status_code\s*=\s*40[13]|Unauthorized|Forbidden|PermissionDenied|check_auth|verify_token|"
    r"authenticate\(|api_key\b|Authorization|X-API-Key|require_login|has_permission|check_permission|token\b",
    re.I,
)


def _api_python(rule: Rule, ctx: FileContext) -> Iterator[Hit]:
    file_guard = re.search(
        r"(?:APIRouter|Blueprint|Router)\([^)]*dependencies\s*=\s*\[|before_request|@\w+\.before_app_request|"
        r"DEFAULT_PERMISSION_CLASSES|IsAuthenticated|login_manager|JWTManager\(|HTTPBearer\(|OAuth2PasswordBearer\(|"
        r"middleware\s*\(|app\.add_middleware\(\s*\w*Auth|include_router\([^)]*dependencies\s*=",
        ctx.text,
    )
    for route in python_routes(ctx):
        if route.has_auth:
            continue
        path = route.path or ""
        if not _API_PATH.search('"' + path + '"'):
            continue
        if _PUBLIC_HINT.search(path):
            continue
        body = function_body_source(ctx, route.func)
        guard = _BODY_AUTH.search(body) or file_guard
        yield Hit(
            line=route.lineno,
            snippet=ctx.line(route.lineno),
            confidence=80 if not guard else 45,
            severity=Severity.HIGH if set(route.methods) & {"POST", "PUT", "PATCH", "DELETE"} else Severity.MEDIUM,
            mitigated_by=guard.group(0) if guard else None,
            skip_sanitizer_check=True,
            description=f"API handler '{route.func.name}' ({', '.join(route.methods)} {path}) has no authentication requirement.",
        )


_JS_API_ROUTE = re.compile(
    r"\b(?:app|router|server|api|fastify|r|route)\s*\.\s*(?P<method>get|post|put|delete|patch|del|all|use)\s*\(\s*"
    r"(?P<quote>['\"`])(?P<path>/(?:api|rest|graphql|v\d+)[^'\"`]*)(?P=quote)\s*,\s*(?P<rest>.*)$",
    re.I,
)
_GO_ROUTE = re.compile(
    r"\b(?:HandleFunc|Handle|GET|POST|PUT|DELETE|PATCH|Get|Post|Put|Delete|Patch)\s*\(\s*['\"](?P<path>/(?:api|rest|v\d+)[^'\"]*)['\"]\s*,\s*(?P<rest>.*)$",
)


def _api_js(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    path = match.group("path")
    rest = match.group("rest")
    if _PUBLIC_HINT.search(path):
        return None
    if not re.match(r"^(?:async\s*)?(?:\(|function\b|\w+\s*=>|\w+\s*[,)])", rest):
        return None
    if JS_AUTH_MIDDLEWARE.search(rest):
        return None
    method = match.groupdict().get("method", "GET") or "GET"
    if method.lower() == "use" and not re.search(r"\(|function|=>", rest):
        return None
    global_guard = re.search(
        r"\.use\(\s*(?:['\"]/(?:api|v\d+)[^'\"]*['\"]\s*,\s*)?\w*(?:auth|protect|verify|passport|guard|jwt|apiKey|session)\w*",
        ctx.text, re.I,
    ) or re.search(r"preHandler\s*:\s*\w*(?:auth|verify)|addHook\(\s*['\"](?:onRequest|preHandler)['\"]", ctx.text, re.I)
    block = lookahead(ctx, line_no, 20)
    local_guard = JS_AUTH_MIDDLEWARE.search(block) or re.search(r"401|403|Unauthorized|Forbidden|api[_-]?key|authorization", block, re.I)
    guard = local_guard or global_guard
    return make_hit(ctx, line_no, column=match.start() + 1, confidence=80 if not guard else 45,
                    severity=Severity.HIGH if method.lower() in {"post", "put", "patch", "delete", "del"} else Severity.MEDIUM,
                    mitigated_by=guard.group(0) if guard else None, skip_sanitizer_check=True,
                    description=f"{method.upper()} {path} is registered without an auth middleware.")


# --------------------------------------------------------------------------- #
# 9. webhooks
# --------------------------------------------------------------------------- #

_WEBHOOK_VERIFY = re.compile(
    r"\bhmac\b|compare_digest|construct_event|verify_signature|verify_header|X-Hub-Signature|Stripe-Signature|"
    r"X-Slack-Signature|X-Twilio-Signature|RequestValidator|timingSafeEqual|\bsvix\b|Webhook\(\s*\w*secret|"
    r"verify_webhook|verifyWebhook|verifySignature|validate_signature|validateSignature|signature|"
    r"x-signature|X-Signature|Paddle-Signature|Shopify-Hmac|X-Shopify-Hmac|webhook_secret|WEBHOOK_SECRET|signing_secret|"
    r"crypto\.createHmac|hashlib\.sha256\(.*secret|\.verify\(|jwt\.decode|bearer|Authorization|api_key|token\s*(?:==|!=)",
    re.I,
)

_WEBHOOK_ROUTE = re.compile(
    r"(?:@\s*[\w.]+\.(?:route|post|put|api_route)\s*\(\s*['\"][^'\"]*(?:webhook|hook|/events?|/notify|/callback/(?:stripe|github|slack|paypal|twilio|sendgrid|mailgun|shopify))[^'\"]*['\"]"
    r"|\b(?:app|router|server|api|fastify)\s*\.\s*(?:post|put|all)\s*\(\s*['\"`][^'\"`]*(?:webhook|hook|/events?|/notify)[^'\"`]*['\"`]"
    r"|(?:def|function|async\s+def|async\s+function)\s+\w*(?:webhook|WebHook|_hook|Hook)\w*\s*\("
    r"|(?:HandleFunc|POST|Post)\s*\(\s*['\"][^'\"]*webhook[^'\"]*['\"]"
    r"|post\s+['\"][^'\"]*webhook[^'\"]*['\"]\s*,\s*to:"
    r"|Route::post\(\s*['\"][^'\"]*webhook)",
    re.I,
)


def _webhook(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    line = ctx.line(line_no)
    if re.search(r"send_webhook|sendWebhook|post_webhook|trigger_webhook|dispatch_webhook|notify_webhook|call_webhook|WebhookClient|register_webhook|create_webhook|webhook_url\s*=|requests\.post|axios\.post|fetch\(", line, re.I):
        return None  # outbound webhook client, not a receiver
    block = handler_block(ctx, line_no, 40)
    if not re.search(r"request|req\b|body|payload|event|json|data|params|form", block, re.I):
        return None
    verify = _WEBHOOK_VERIFY.search(block) or _WEBHOOK_VERIFY.search(lookbehind(ctx, line_no, 6))
    if verify and re.search(r"compare_digest|construct_event|timingSafeEqual|RequestValidator|\bsvix\b|verify_signature|verifyWebhook|verify_webhook|verifySignature|verify_header", verify.group(0), re.I):
        return None  # a real cryptographic verification helper is in use
    return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by=verify.group(0) if verify else None,
                    skip_sanitizer_check=True, confidence=85 if not verify else 45)


# --------------------------------------------------------------------------- #
# 28. monitoring
# --------------------------------------------------------------------------- #

_METRICS_GUARD = re.compile(
    r"\bauth|basic_auth|BasicAuth|token|login_required|allowlist|whitelist|ip_whitelist|internal|127\.0\.0\.1|localhost|"
    r"Depends\(|protect|security|password|secret|X-API-Key|api_key|firewall|allow\s+\d+\.|deny\s+all|require_role|admin|"
    r"metrics_token|METRICS_TOKEN|bearer|jwt|verifyToken|isAuthenticated|middleware|guard|network_policy|private",
    re.I,
)


def _metrics(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    line = ctx.line(line_no)
    if re.search(r"^\s*(?:import|from|require)\b|test_|spec\.|describe\(|\.md['\"]|readme|curl |http\.get|requests\.get|fetch\(|axios", line, re.I):
        return None
    if re.search(r"127\.0\.0\.1|localhost|addr\s*=\s*['\"](?:127|::1)", line):
        return None
    around = lookbehind(ctx, line_no, 6) + "\n" + line + "\n" + lookahead(ctx, line_no, 12)
    guard = _METRICS_GUARD.search(around)
    if guard and re.search(_METRICS_GUARD, line):
        return None
    return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by=guard.group(0) if guard else None,
                    skip_sanitizer_check=True, confidence=75 if not guard else 40)


# --------------------------------------------------------------------------- #
# 29. debug-endpoints
# --------------------------------------------------------------------------- #


def _debug_flag(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    line = ctx.line(line_no)
    if re.search(r"os\.environ|getenv|process\.env|env\(|ENV\[|\bconfig\.|settings\.|\$\{|\{\{|if\s+__name__|#\s*noqa|dev-only|development only", line, re.I):
        return None
    name = ctx.name.lower()
    if re.search(r"example|sample|template|\.dist$|\.tpl$|test|spec|local|dev", name) and "settings" not in name and "config" not in name:
        return make_hit(ctx, line_no, column=match.start() + 1, severity=Severity.LOW, confidence=45,
                        description="Debug mode enabled in a development/example file; ensure it never ships to production.")
    window = ctx.window(line_no, 6, 3)
    guard = re.search(r"if\s+(?:not\s+)?(?:settings\.)?(?:DEBUG|is_dev|dev|development|ENV|env|NODE_ENV|__name__)|environment\s*(?:==|!=)|production", window, re.I)
    return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by=guard.group(0) if guard else None, skip_sanitizer_check=True)


# --------------------------------------------------------------------------- #
# 30. documentation
# --------------------------------------------------------------------------- #

_DOCS_GUARD = re.compile(
    r"\bauth|login_required|basic_auth|BasicAuth|permission|Depends\(|protect|password|IsAuthenticated|IsAdminUser|"
    r"settings\.DEBUG|if\s+.*debug|docs_url\s*=\s*None|redoc_url\s*=\s*None|openapi_url\s*=\s*None|"
    r"NODE_ENV|process\.env|os\.environ|getenv|swaggerOptions.*auth|SWAGGER_UI_(?:AUTH|OAUTH)|public\s*=\s*False|"
    r"permission_classes|AllowAny\b.*#|is_staff|staff_member_required|admin_required|require_role|apiKeyAuth|"
    r"basicAuth|express-basic-auth|validate\s*:\s*\{|keycloak|okta|guard|middleware",
    re.I,
)


def _docs(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    line = ctx.line(line_no)
    if re.search(r"^\s*(?:import|from|require)\b|test_|spec\.|describe\(|README|\.md\b|curl |http\.get|requests\.get|fetch\(|axios|console\.log|print\(|logger", line, re.I):
        return None
    if re.search(r"docs_url\s*=\s*None|redoc_url\s*=\s*None|openapi_url\s*=\s*None|swagger\s*[:=]\s*false|enabled\s*[:=]\s*false", line, re.I):
        return None
    around = lookbehind(ctx, line_no, 8) + "\n" + line + "\n" + lookahead(ctx, line_no, 10)
    guard = _DOCS_GUARD.search(around)
    if guard and re.search(_DOCS_GUARD, line):
        return None
    return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by=guard.group(0) if guard else None,
                    skip_sanitizer_check=True, confidence=70 if not guard else 35)


def _spec_file(rule: Rule, ctx: FileContext) -> Iterator[Hit]:
    rel = ctx.rel_path.lower()
    if not re.search(r"(?:^|/)(?:static|public|www|htdocs|wwwroot|assets|dist|site)/", rel):
        return
    if not re.search(r"(?:swagger|openapi|api-?docs?|redoc)[^/]*\.(?:json|ya?ml)$", rel):
        return
    yield Hit(line=1, snippet=ctx.name, confidence=70, severity=Severity.LOW, skip_sanitizer_check=True,
              description="An OpenAPI/Swagger specification is published from a static web directory.")


# --------------------------------------------------------------------------- #
# 31. third-party-integrations
# --------------------------------------------------------------------------- #

_HTTP_CALLS = {"requests.get", "requests.post", "requests.put", "requests.delete", "requests.patch", "requests.head",
               "requests.request", "requests.options", "httpx.get", "httpx.post", "httpx.put", "httpx.delete",
               "httpx.patch", "httpx.request", "httpx.head", "urllib.request.urlopen", "urlopen", "urllib2.urlopen",
               "session.get", "session.post", "session.put", "session.delete", "session.request", "client.get",
               "client.post", "client.put", "client.delete", "client.request", "self.session.get", "self.session.post",
               "self.client.get", "self.client.post", "http.request", "aiohttp.request", "session.fetch"}
_SSRF_GUARD = re.compile(
    r"allowlist|whitelist|ALLOWED_HOSTS|ALLOWED_DOMAINS|ALLOWED_URLS|urlparse\(|validate_url|is_safe_url|ipaddress\.|"
    r"is_private|is_global|hostname\s+(?:in|not in)|netloc\s+(?:in|not in)|startswith\(\s*['\"]https://(?!\{)|"
    r"\.netloc\s*(?:==|!=|in)|resolve_and_check|safe_url|url_allowed|check_url|domain\s+(?:in|not in)|urljoin\(\s*BASE",
    re.I,
)


def _outbound_python(rule: Rule, ctx: FileContext) -> Iterator[Hit]:
    tree = ctx.tree
    if tree is None:
        return
    for call in iter_calls(tree):
        name = call_name(call)
        if name not in _HTTP_CALLS and not (name.endswith((".get", ".post", ".put", ".delete", ".patch", ".request")) and re.search(r"requests|httpx|session|client|http", name, re.I)):
            continue
        if name.startswith(("dict.", "os.environ", "cache.", "redis.", "r.", "self.cache", "settings.", "config.", "headers.", "params.", "data.", "json.", "kwargs.", "options.")):
            continue
        source = node_source(ctx, call)
        url_node = call.args[0] if call.args else keyword_value(call, "url")
        if url_node is None and name.startswith("requests.request") and len(call.args) > 1:
            url_node = call.args[1]
        # SSRF: URL derived from user input
        if url_node is not None and not is_constant_str(url_node):
            url_src = node_source(ctx, url_node)
            tainted = has_input(url_src) or node_tainted(ctx, url_node, lookback=25)
            if tainted:
                block = ctx.window(call.lineno, 20, 3)
                guard = _SSRF_GUARD.search(block)
                yield hit_from_node(ctx, call, name="Outbound request to user-controlled URL (SSRF)", cwe="CWE-918",
                                    severity=Severity.HIGH, confidence=90 if not guard else 45,
                                    mitigated_by=guard.group(0) if guard else None, skip_sanitizer_check=True,
                                    description=f"{name}() fetches a URL that originates from request data.")
        # Missing timeout
        if not has_keyword(call, "timeout") and "timeout" not in source and not (name.startswith("aiohttp") or name.endswith("fetch")):
            file_level = re.search(r"timeout\s*=|Timeout\(|HTTPAdapter|\.timeout\s*=|DEFAULT_TIMEOUT|socket\.setdefaulttimeout", ctx.text)
            yield hit_from_node(ctx, call, name="Outbound HTTP request without timeout", cwe="CWE-400",
                                severity=Severity.LOW, confidence=75 if not file_level else 35,
                                mitigated_by=file_level.group(0) if file_level else None, skip_sanitizer_check=True,
                                description=f"{name}() has no timeout; a slow third party can exhaust workers.")


_JS_SSRF = re.compile(
    r"\b(?:fetch|axios(?:\.(?:get|post|put|delete|patch|request|head))?|got(?:\.(?:get|post))?|superagent\.(?:get|post)|request(?:\.(?:get|post))?|needle\.(?:get|post)|http\.get|https\.get|http\.request|https\.request|urllib\.request|Http\.get|HttpClient\.(?:Get|Post)\w*|http\.NewRequest|file_get_contents|curl_init|curl_setopt|Net::HTTP\.get|open\(|URI\.open|RestTemplate|WebClient|HttpURLConnection|new\s+URL)\s*\(\s*(?P<arg>[^)]*)\)",
    re.I,
)


def _outbound_regex(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    arg = match.group("arg")
    line = ctx.line(line_no)
    if re.search(r"^\s*(?:import|from|require|#|//)", line):
        return None
    if re.fullmatch(r"\s*(?:'[^']*'|\"[^\"]*\"|`[^`$]*`)\s*(?:,.*)?", arg or ""):
        return None
    tainted = arg_tainted(ctx, line_no, arg or line, lookback=25)
    if not tainted:
        return None
    block = ctx.window(line_no, 20, 3)
    guard = _SSRF_GUARD.search(block)
    return make_hit(ctx, line_no, column=match.start() + 1, severity=Severity.HIGH, confidence=88 if not guard else 45,
                    mitigated_by=guard.group(0) if guard else None, skip_sanitizer_check=True)


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

RULES: tuple[Rule, ...] = (
    # ---- 7. api-endpoints ------------------------------------------------- #
    Rule(
        id="API-001",
        surface="api-endpoints",
        name="Unauthenticated API endpoint (Python)",
        description="A handler mounted under /api, /rest or /v* has no authentication decorator, dependency or in-body check.",
        severity=Severity.HIGH,
        cwe="CWE-306",
        confidence=80,
        extensions=(".py",),
        file_checker=_api_python,
        recommendation="Require authentication on every API route by default (router-level dependency / permission classes).",
        remediation="router = APIRouter(dependencies=[Depends(get_current_user)]) or @jwt_required() on each handler.",
    ),
    Rule(
        id="API-002",
        surface="api-endpoints",
        name="Unauthenticated API endpoint",
        description="An /api route is registered with a bare handler and no auth middleware in the chain.",
        severity=Severity.HIGH,
        cwe="CWE-306",
        confidence=80,
        extensions=(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go"),
        keywords=("/api", "/rest", "/v1", "/v2", "/v3", "/graphql"),
        patterns=(_JS_API_ROUTE, _GO_ROUTE),
        checker=_api_js,
        recommendation="Mount an authentication middleware on the API router before defining routes.",
        remediation="router.use(requireAuth); or app.post('/api/orders', requireAuth, handler)",
    ),
    Rule(
        id="API-003",
        surface="api-endpoints",
        name="API authentication explicitly disabled",
        description="Configuration marks API views/routes as anonymous or disables API keys.",
        severity=Severity.HIGH,
        cwe="CWE-306",
        confidence=85,
        extensions=CONFIG_EXTS,
        keywords=("allowany", "anonymous", "auth", "api_key_required", "authentication_classes", "public"),
        patterns=(
            r"permission_classes\s*=\s*[\[(]\s*AllowAny\s*[\])]",
            r"authentication_classes\s*=\s*[\[(]\s*[\])]",
            r"(?:API|api)_(?:KEY|AUTH)_REQUIRED\s*[:=]\s*(?:False|false|0)\b",
            r"(?:REQUIRE|require)_(?:AUTH|auth|API_KEY|api_key)\s*[:=]\s*(?:False|false|0)\b",
            r"anonymous(?:_access|Access)?\s*[:=]\s*(?:true|True|enabled)",
            r"allow_anonymous\s*[:=]\s*(?:true|True)",
            r"security\s*:\s*\[\s*\]\s*(?:#.*)?$",
            r"@csrf_exempt\s*$",
            r"authorizationType\s*:\s*['\"]?NONE",
            r"authorization_type\s*=\s*['\"]NONE['\"]",
            r"authorizer\s*:\s*none",
        ),
        negatives=(r"login|register|signup|health|public|webhook|docs|token|refresh|logout|forgot|reset"),
        context_before=3,
        context_after=8,
        recommendation="Apply authentication on every non-public API surface.",
        remediation="Remove AllowAny/csrf_exempt from endpoints that are not deliberately public and document those that are.",
    ),
    # ---- 9. webhooks ------------------------------------------------------ #
    Rule(
        id="WH-001",
        surface="webhooks",
        name="Webhook receiver without signature verification",
        description="An inbound webhook handler processes the payload without verifying an HMAC/signature header.",
        severity=Severity.HIGH,
        cwe="CWE-345",
        confidence=85,
        extensions=WEB_EXTS,
        keywords=("webhook", "hook", "/events", "/event", "/notify", "/callback/"),
        patterns=(_WEBHOOK_ROUTE,),
        negatives=(r"^\s*(?:import|from|require|#|//)", r"test_|spec\.|describe\(|\.md\b"),
        checker=_webhook,
        recommendation="Verify the provider signature (HMAC with a shared secret, constant-time compare) before trusting the payload.",
        remediation="expected = hmac.new(SECRET, request.data, sha256).hexdigest(); if not hmac.compare_digest(expected, sig): abort(400)",
    ),
    Rule(
        id="WH-002",
        surface="webhooks",
        name="Webhook signature verified with non-constant-time comparison",
        description="The signature is compared with == which leaks timing information.",
        severity=Severity.MEDIUM,
        cwe="CWE-208",
        confidence=85,
        extensions=WEB_EXTS,
        keywords=("signature", "hmac", "digest"),
        patterns=(
            r"\b\w*(?:signature|sig|hmac|digest)\w*\s*(?:==|!=|===|!==)\s*\w*(?:signature|sig|hmac|digest|expected|computed|header)\w*",
            r"\b(?:expected|computed|calculated)\w*\s*(?:==|!=|===|!==)\s*\w*(?:signature|sig|hmac|digest|header)\w*",
        ),
        negatives=(r"compare_digest|timingSafeEqual|hash_equals|secure_compare|constant_time|ConstantTimeCompare|crypto\.subtle\.timingSafeEqual|\bif\s+not\s+\w*(?:signature|sig)\w*\s*:|is None|== None|!= None|=== null|== null|=== undefined|\.length"),
        use_surface_indicators=False,
        recommendation="Use a constant-time comparison (hmac.compare_digest, crypto.timingSafeEqual, hash_equals).",
        remediation="if not hmac.compare_digest(expected_sig, received_sig): abort(400)",
    ),
    # ---- 28. monitoring --------------------------------------------------- #
    Rule(
        id="MON-001",
        surface="monitoring",
        name="Metrics/monitoring endpoint exposed without protection",
        description="A Prometheus/actuator/status endpoint is mounted with no authentication or network restriction nearby.",
        severity=Severity.MEDIUM,
        cwe="CWE-200",
        confidence=75,
        extensions=WEB_EXTS + (".yaml", ".yml", ".conf", ".properties", ".toml"),
        keywords=("/metrics", "/actuator", "/prometheus", "/debug/vars", "/debug/pprof", "/server-status", "/nginx_status", "/stats", "/health/detailed", "make_wsgi_app", "start_http_server", "metricsmiddleware", "prometheusmetrics", "promhttp", "expvar", "pprof", "exposure", "/_status", "/telemetry", "/monitoring", "/info"),
        patterns=(
            r"(?:route|get|path|url|mount|Handle|HandleFunc|location|add_url_rule|register|use|GET|Get|@app\.\w+)\s*\(\s*r?['\"`](?:/[\w-]+)*/(?:metrics|actuator(?:/\w+)?|prometheus|debug/vars|debug/pprof\w*|server-status|nginx_status|stats|health/detailed|_status|telemetry|monitoring|info|env|heapdump|threaddump|dump|trace|jolokia|beans|mappings|configprops)/?['\"`]",
            r"^\s*location\s+(?:=\s*)?/(?:metrics|server-status|nginx_status|status|actuator)",
            r"\bmake_wsgi_app\s*\(\s*\)|\bmake_asgi_app\s*\(\s*\)|\bstart_http_server\s*\(",
            r"\bpromhttp\.Handler\s*\(\s*\)",
            r"\bPrometheusMetrics\s*\(\s*app|\bMetricsMiddleware\b|prometheus_flask_exporter|PrometheusMiddleware\(|expose_metrics\(",
            r"management\.endpoints\.web\.exposure\.include\s*[:=]\s*['\"]?\*",
            r"management\.endpoint\.(?:env|heapdump|threaddump|shutdown|beans|mappings)\.enabled\s*[:=]\s*true",
            r"expvar\.Handler\s*\(|_\s+\"net/http/pprof\"|_\s+\"expvar\"",
            r"app\.use\(\s*['\"]/metrics['\"]",
            r"(?:metricsPath|metrics_path|metricsRoute)\s*[:=]\s*['\"]/\w+['\"]",
        ),
        negatives=(r"^\s*(?:import|from|require|#|//)", r"health['\"]|healthz|ping['\"]|readiness|liveness", r"scrape|scrape_configs|targets:"),
        checker=_metrics,
        recommendation="Restrict metrics endpoints to internal networks or protect them with authentication (token/basic auth).",
        remediation="Bind the metrics server to localhost or a dedicated port scraped over a private network; add basic-auth in Prometheus.",
    ),
    # ---- 29. debug-endpoints ---------------------------------------------- #
    Rule(
        id="DBG-001",
        surface="debug-endpoints",
        name="Debug mode enabled",
        description="Application debug mode is switched on, exposing stack traces, interactive consoles and internals.",
        severity=Severity.HIGH,
        cwe="CWE-489",
        confidence=90,
        extensions=CONFIG_EXTS + (".jsx", ".tsx", ".dockerfile", ".txt"),
        filename_patterns=(r"(?:^|/)(?:Dockerfile|Procfile|\.flaskenv|\.env(?:\.\w+)?)$",),
        keywords=("debug", "development", "display_errors", "devtools", "use_evalex", "use_debugger", "expose_php", "stacktrace", "detailed_errors", "custom_errors", "customerrors", "whoops", "toolbar"),
        patterns=(
            r"^\s*DEBUG\s*[:=]\s*(?:True|true|1|['\"](?:True|true|1|on|yes)['\"])\s*(?:#.*|//.*)?$",
            r"\.run\s*\([^)]*debug\s*=\s*True",
            r"app\.debug\s*=\s*True",
            r"(?:FLASK_DEBUG|DJANGO_DEBUG|APP_DEBUG|DEBUG_MODE|LARAVEL_DEBUG|RAILS_DEBUG|SPRING_DEBUG)\s*[:=]\s*['\"]?(?:1|true|True|on)['\"]?\s*$",
            r"FLASK_ENV\s*[:=]\s*['\"]?development['\"]?",
            r"^\s*ENV\s+(?:FLASK_DEBUG|APP_DEBUG|DEBUG|NODE_ENV)\s*=?\s*['\"]?(?:1|true|development)",
            r"(?:use_evalex|use_debugger|use_reloader)\s*=\s*True",
            r"display_errors\s*=\s*(?:On|1|true)|expose_php\s*=\s*On",
            r"['\"]?debug['\"]?\s*:\s*true\s*[,}]?\s*(?://.*)?$",
            r"spring\.devtools\.(?:restart|livereload)\.enabled\s*[:=]\s*true",
            r"server\.error\.include-stacktrace\s*[:=]\s*always|server\.error\.include-message\s*[:=]\s*always",
            r"config\.consider_all_requests_local\s*=\s*true|config\.action_dispatch\.show_exceptions\s*=\s*true",
            r"customErrors\s+mode\s*=\s*['\"]Off['\"]|<compilation[^>]*debug\s*=\s*['\"]true['\"]",
            r"detailedErrors\s*:\s*true|showStack\s*:\s*true|stackTrace\s*:\s*true|exposeStack\s*:\s*true",
            r"Whoops\\(?:Run|Handler)|Whoops::register|new\s+PrettyPageHandler",
            r"['\"]debug_toolbar['\"]|debug_toolbar\.urls|['\"]silk['\"]|DebugToolbarMiddleware",
            r"app\.use\(\s*errorhandler\(\s*\)|errorHandler\(\s*\{\s*(?:log|dumpExceptions)\s*:\s*true",
            r"GraphiQL\s*=\s*True|dev_tool\s*=\s*True",
            r"\bapp\.listen\([^)]*inspect|node\s+--inspect(?:-brk)?(?:=0\.0\.0\.0)?",
        ),
        negatives=(r"os\.environ|getenv|process\.env|env\(|ENV\[|\$\{|\{\{|#\s*noqa|DEBUG\s*=\s*False|config\.get|settings\.|logging\.|logger|level|log_level|LOG_LEVEL|loglevel|\bif\b.*debug|debug\s*=\s*args|argparse|--debug|verbose"),
        checker=_debug_flag,
        code_only=True,
        recommendation="Never enable debug mode in production; derive it from the environment with a safe default of False.",
        remediation="DEBUG = os.environ.get('DJANGO_DEBUG', '') == '1'  # defaults to False",
    ),
    Rule(
        id="DBG-002",
        surface="debug-endpoints",
        name="Debug/console route exposed",
        description="A route serving a debugger, console, shell or test harness is registered.",
        severity=Severity.HIGH,
        cwe="CWE-489",
        confidence=80,
        extensions=WEB_EXTS,
        keywords=("debug", "console", "shell", "__debug__", "phpinfo", "test", "dev", "playground", "pprof", "eval", "exec", "dump"),
        patterns=(
            r"(?:route|get|post|path|url|mount|Handle|HandleFunc|add_url_rule|register|use|GET|POST)\s*\(\s*r?['\"`](?:/[\w-]+)*/(?:__debug__|debug|_debug|console|_console|shell|phpinfo|dev-tools?|devtools|test-?(?:endpoint|route|api)?|_test|playground|dump|eval|exec|cmd|command|run|internal-?debug|diag(?:nostics)?)/?[^'\"`]*['\"`]",
            r"\bphpinfo\s*\(\s*\)",
            r"path\(\s*['\"]__debug__/['\"]",
            r"from\s+werkzeug\.debug\s+import\s+DebuggedApplication|DebuggedApplication\s*\(",
            r"flask_debugtoolbar|DebugToolbarExtension\s*\(",
            r"rack-mini-profiler|Rack::MiniProfiler|web-console|binding\.pry|byebug\b",
            r"\bpdb\.set_trace\s*\(|\bipdb\.set_trace\s*\(|\bbreakpoint\s*\(\s*\)",
            r"^\s*debugger\s*;?\s*$",
        ),
        negatives=(r"^\s*(?:import|from|require|#|//)", r"test_|spec\.|describe\(|\bit\(|jest|pytest|unittest|__tests__|/tests?/", r"debug\s*=\s*(?:False|false)", r"logger|logging|log\.debug|console\.debug|debug\(['\"]"),
        sanitizers=(r"if\s+(?:app\.)?(?:settings\.)?DEBUG", r"if\s+not\s+PRODUCTION", r"NODE_ENV\s*!==?\s*['\"]production", r"development", r"is_dev", r"os\.environ", r"getenv", r"process\.env", r"login_required", r"admin_required", r"staff_member_required", r"Depends\(", r"requireAuth", r"requireAdmin", r"isAdmin"),
        context_before=6,
        context_after=10,
        recommendation="Remove debug/console routes from production builds or gate them behind admin auth and environment checks.",
        remediation="Register debug toolbars/routes only when settings.DEBUG is True and strip breakpoints before release.",
    ),
    # ---- 30. documentation ------------------------------------------------ #
    Rule(
        id="DOC-001",
        surface="documentation",
        name="API documentation (Swagger/Redoc/OpenAPI) exposed without authorization",
        description="Interactive API documentation is mounted publicly, revealing every endpoint and schema.",
        severity=Severity.LOW,
        cwe="CWE-200",
        confidence=70,
        extensions=WEB_EXTS + (".yaml", ".yml", ".json", ".toml"),
        keywords=("swagger", "redoc", "openapi", "docs", "apispec", "flasgger", "drf_yasg", "spectacular", "scalar", "rapidoc", "graphiql", "api-docs", "springdoc", "springfox"),
        patterns=(
            r"\b(?:get_swagger_ui_html|get_redoc_html|swaggerUi\.(?:serve|setup)|swagger-ui-express|swaggerUI\(|SwaggerUI\(|swagger_ui\.|Swagger\(\s*app|Flasgger|flasgger|Redoc|ReDoc|apispec|springfox|springdoc|@EnableSwagger2|RapiDoc|scalar|apiReference)\b",
            r"(?:docs_url|redoc_url|openapi_url|swagger_url|swagger_ui_path|api_docs_path|docs_path|SWAGGER_URL|API_URL)\s*[:=]\s*['\"]/[^'\"]*['\"]",
            r"(?:route|get|path|url|mount|Handle|HandleFunc|add_url_rule|use|GET|re_path)\s*\(\s*r?['\"`](?:/[\w-]+)*/(?:docs|swagger|swagger-ui|swagger-ui\.html|redoc|openapi|openapi\.json|api-docs|api/docs|apidocs|graphiql|v\d/docs|documentation|spec|schema)/?[^'\"`]*['\"`]",
            r"get_schema_view\s*\(",
            r"SpectacularSwaggerView|SpectacularRedocView|SpectacularAPIView",
            r"springdoc\.(?:swagger-ui|api-docs)\.(?:enabled|path)\s*[:=]\s*(?:true|/)",
            r"@app\.get\(\s*['\"]/openapi\.json['\"]",
            r"swagger:\s*\{\s*(?:enabled\s*:\s*true|path\s*:)",
        ),
        negatives=(r"^\s*(?:import|from|require|#|//)", r"docs_url\s*=\s*None|redoc_url\s*=\s*None|openapi_url\s*=\s*None", r"test_|spec\.|describe\(|\.md\b|README|curl |requests\.get|fetch\(|axios|print\(|console\.log|logger|docs\.python|docs\.\w+\.(?:com|org|io)|://"),
        checker=_docs,
        recommendation="Serve API docs only in non-production environments or behind authentication.",
        remediation="FastAPI(docs_url=None, redoc_url=None) in production, or protect /docs with a Depends(verify_admin) dependency.",
    ),
    Rule(
        id="DOC-002",
        surface="documentation",
        name="OpenAPI specification published from a static directory",
        description="A swagger/openapi file lives under a public web root and will be served to anyone.",
        severity=Severity.LOW,
        cwe="CWE-200",
        confidence=70,
        extensions=(".json", ".yaml", ".yml"),
        file_checker=_spec_file,
        recommendation="Keep API specifications out of public static folders unless the API is intentionally public.",
        remediation="Move the spec into the application package and serve it from an authenticated route.",
    ),
    # ---- 31. third-party-integrations ------------------------------------ #
    Rule(
        id="TPI-001",
        surface="third-party-integrations",
        name="Outbound request without timeout / to user-controlled URL (Python)",
        description="requests/httpx/urllib calls lacking a timeout or fetching URLs derived from request data.",
        severity=Severity.HIGH,
        cwe="CWE-918",
        confidence=80,
        extensions=(".py",),
        file_checker=_outbound_python,
        recommendation="Always pass timeout=, and validate outbound URLs against an allow-list of hosts (resolve + block private ranges).",
        remediation="requests.get(url, timeout=(3, 10)) with url built from a fixed base and validated path segments.",
    ),
    Rule(
        id="TPI-002",
        surface="third-party-integrations",
        name="Outbound request to user-controlled URL (SSRF)",
        description="An HTTP client fetches a URL that originates from request parameters.",
        severity=Severity.HIGH,
        cwe="CWE-918",
        confidence=85,
        extensions=(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".rb", ".java", ".go", ".kt", ".cs"),
        keywords=("fetch(", "axios", "got(", "got.", "superagent", "request(", "request.", "needle", "http.get", "https.get", "http.request", "https.request", "file_get_contents", "curl_", "net::http", "open(", "resttemplate", "webclient", "httpurlconnection", "new url", "http.newrequest", "httpclient"),
        patterns=(_JS_SSRF,),
        negatives=(r"^\s*(?:import|from|require|#|//)", r"\.d\.ts"),
        checker=_outbound_regex,
        recommendation="Validate the destination host against an allow-list and block private/link-local address ranges.",
        remediation="const target = new URL(input); if (!ALLOWED_HOSTS.has(target.hostname)) throw new Error('blocked');",
    ),
    Rule(
        id="TPI-003",
        surface="third-party-integrations",
        name="HTTP client configured without timeout",
        description="A client instance is created without a timeout so a hanging third party can stall the service.",
        severity=Severity.LOW,
        cwe="CWE-400",
        confidence=70,
        extensions=(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".java", ".kt", ".cs", ".rb", ".php"),
        keywords=("axios.create", "http.client{}", "&http.client{}", "http.get(", "http.post(", "httpclient", "newhttpclient", "resttemplate(", "webclient.create", "net::http", "curl_init", "guzzle", "new client("),
        patterns=(
            r"axios\.create\s*\(\s*\{(?![^}]*timeout)[^}]*\}\s*\)",
            r"axios\.create\s*\(\s*\)",
            r"&?http\.Client\s*\{\s*\}",
            r"^\s*(?:resp|res|response|r)\s*,\s*(?:err|_)\s*:?=\s*http\.(?:Get|Post|Head|PostForm)\s*\(",
            r"HttpClient\.newHttpClient\s*\(\s*\)",
            r"new\s+RestTemplate\s*\(\s*\)",
            r"WebClient\.create\s*\(",
            r"new\s+HttpClient\s*\(\s*\)\s*;",
            r"new\s+GuzzleHttp\\Client\s*\(\s*\)|new\s+Client\s*\(\s*\[\s*\]\s*\)",
            r"Net::HTTP\.(?:get|post_form|start)\s*\(",
            r"curl_init\s*\(",
        ),
        negatives=(r"timeout|Timeout|CURLOPT_TIMEOUT|CURLOPT_CONNECTTIMEOUT|read_timeout|open_timeout"),
        sanitizers=(r"timeout", r"Timeout", r"CURLOPT_TIMEOUT", r"CURLOPT_CONNECTTIMEOUT", r"read_timeout", r"open_timeout", r"AbortController", r"signal\s*:", r"setConnectTimeout", r"setReadTimeout", r"connectTimeout", r"responseTimeout", r"http\.DefaultClient\.Timeout"),
        context_before=4,
        context_after=8,
        use_surface_indicators=False,
        recommendation="Configure connect and read timeouts on every outbound HTTP client.",
        remediation="axios.create({ timeout: 10000 }) / &http.Client{Timeout: 10 * time.Second} / curl_setopt($ch, CURLOPT_TIMEOUT, 10)",
    ),
)
