"""Frontend surface: Subresource Integrity on external assets and raw DOM
writes in JavaScript (surfaces 19, 20).
"""

from __future__ import annotations

import re

from attack_surface.analysis import arg_tainted, is_pure_literal, lookahead, lookbehind, make_hit
from attack_surface.models import FileContext, Hit, Rule, Severity

MARKUP_EXTS = (".html", ".htm", ".xhtml", ".php", ".ejs", ".hbs", ".handlebars", ".pug", ".jade", ".twig", ".erb",
               ".jinja", ".jinja2", ".j2", ".vue", ".svelte", ".jsx", ".tsx", ".astro", ".cshtml", ".razor", ".jsp",
               ".tpl", ".mustache", ".liquid", ".njk", ".md", ".mdx")
JS_EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".html", ".htm", ".ejs", ".hbs",
           ".php", ".erb", ".twig", ".jinja", ".jinja2", ".j2", ".astro", ".cshtml", ".jsp", ".njk")

# --------------------------------------------------------------------------- #
# 19. frontend-assets
# --------------------------------------------------------------------------- #

_EXTERNAL_SCRIPT = re.compile(
    r"<script\b[^>]*?\ssrc\s*=\s*['\"]?(?P<url>(?:https?:)?//[^'\"\s>]+)['\"]?[^>]*>",
    re.I | re.S,
)
_EXTERNAL_STYLE = re.compile(
    r"<link\b(?=[^>]*\brel\s*=\s*['\"]?(?:stylesheet|preload|modulepreload)\b)[^>]*?\shref\s*=\s*['\"]?(?P<url>(?:https?:)?//[^'\"\s>]+)['\"]?[^>]*>",
    re.I | re.S,
)


def _sri(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    tag = match.group(0)
    url = match.group("url")
    if re.search(r"\bintegrity\s*=", tag, re.I):
        return None
    if re.search(r"\{\{|\{%|<%|\$\{|@\w+\(|\bnonce\s*=", tag) and not re.search(r"cdn|unpkg|jsdelivr|cdnjs|googleapis|bootstrapcdn|cloudflare|jquery", url, re.I):
        return None
    if re.search(r"googletagmanager|google-analytics|gtag/js|connect\.facebook|platform\.twitter|hotjar|intercom|segment\.com|clarity\.ms|plausible|matomo|hcaptcha|recaptcha|maps\.googleapis|youtube\.com|player\.vimeo|stripe\.com/v3|js\.stripe|paypal\.com/sdk|checkout\.|braintreegateway|cdn\.auth0|accounts\.google|apis\.google|login\.microsoftonline|widget|chat|embed|beacon", url, re.I):
        # Dynamic third-party SDKs cannot carry SRI; still worth a low-severity note.
        return make_hit(ctx, line_no, column=match.start() + 1, severity=Severity.INFO, confidence=40,
                        name="Third-party SDK loaded without SRI (dynamic script)",
                        description=f"{url} is a dynamic vendor script that cannot use SRI; restrict it with CSP and review the vendor's controls.",
                        skip_sanitizer_check=True)
    insecure = url.lower().startswith("http://")
    if insecure:
        return make_hit(ctx, line_no, column=match.start() + 1, severity=Severity.HIGH, confidence=95,
                        name="External asset loaded over plaintext HTTP", cwe="CWE-319",
                        description=f"{url} is loaded over HTTP and can be replaced in transit.", skip_sanitizer_check=True)
    confidence = 90 if re.search(r"cdn|unpkg|jsdelivr|cdnjs|googleapis|bootstrapcdn|cloudflare|jquery|stackpath|maxcdn|fontawesome|kit\.|esm\.sh|skypack", url, re.I) else 70
    return make_hit(ctx, line_no, column=match.start() + 1, confidence=confidence, skip_sanitizer_check=True,
                    description=f"{url} is loaded from a third-party origin without an integrity attribute.")


# --------------------------------------------------------------------------- #
# 20. javascript-analysis
# --------------------------------------------------------------------------- #

_DOM_SINK = re.compile(
    r"(?:\.(?:innerHTML|outerHTML)\s*(?:=|\+=)(?!=)\s*(?P<a>.*)$"
    r"|document\.write(?:ln)?\s*\(\s*(?P<b>.*)$"
    r"|\.insertAdjacentHTML\s*\(\s*['\"][^'\"]*['\"]\s*,\s*(?P<c>.*)$"
    r"|\$\((?:[^)]*)\)\s*\.(?:html|append|prepend|after|before|replaceWith|wrap|wrapInner|appendTo|prependTo)\s*\(\s*(?P<d>[^)]*)\)"
    r"|\$\.parseHTML\s*\(\s*(?P<e>[^)]*)\)"
    r"|dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?P<f>[^}]*)\}"
    r"|__html\s*:\s*(?P<g>[^}]*)\}"
    r"|v-html\s*=\s*['\"](?P<h>[^'\"]*)['\"]"
    r"|\[innerHTML\]\s*=\s*['\"](?P<i>[^'\"]*)['\"]"
    r"|\{@html\s+(?P<j>[^}]*)\}"
    r"|bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(\s*(?P<k>[^)]*)\)"
    r"|\.(?:html|append|prepend)\s*\(\s*(?P<l>(?:`[^`]*\$\{|[^)'\"`][^)]*))\)"
    r"|Range\s*\.\s*createContextualFragment\s*\(\s*(?P<m>[^)]*)\)"
    r"|\.setHTMLUnsafe\s*\(\s*(?P<n>[^)]*)\)"
    r"|new\s+DOMParser\(\)\.parseFromString\s*\(\s*(?P<o>[^,]*),\s*['\"]text/html"
    r"|\.srcdoc\s*=\s*(?P<p>.*)$"
    r"|\.(?:href|src|action|formAction)\s*=\s*(?P<q>(?:`javascript:|['\"]javascript:).*)$"
    r"|(?:el|elem|element|node|div|span|container|target|root|\w+El|\w+Element|\w+Ref\.current)\.innerHTML\s*=\s*(?P<r>.*)$)",
    re.I,
)
_DOM_SANITIZER = re.compile(
    r"DOMPurify|sanitizeHtml|sanitize-html|sanitize\(|sanitizer\.|escapeHtml|escapeHTML|\bescape\(|encodeURIComponent|"
    r"createTextNode|textContent|innerText|he\.encode|he\.escape|filterXSS|\bxss\(|purify|\bclean\(|striptags|"
    r"Handlebars\.escapeExpression|_\.escape\(|lodash\.escape|validator\.escape|xss-filters|\bsafeHtml\b|"
    r"trustedTypes|policy\.createHTML|marked\.parse\([^)]*sanitize|renderToStaticMarkup|\bi18n\.t\(|\$t\(|"
    r"\bt\(['\"]|\bgettext\(|__\(",
    re.I,
)
_DOM_SOURCE = re.compile(
    r"location\.(?:hash|search|href|pathname)|document\.(?:URL|documentURI|referrer|cookie)|window\.name|"
    r"URLSearchParams|searchParams\.get|\bparams\.|req\.(?:query|body|params)|request\.|"
    r"localStorage\.getItem|sessionStorage\.getItem|postMessage|\bevent\.data\b|\bmessage\.data\b|e\.data\b|"
    r"\bprops\.|this\.props|\bstate\.|response\.(?:data|body|text)|res\.data|\bdata\.|\bjson\.|await\s+\w+\.(?:json|text)\(\)|"
    r"\.value\b|input|textarea|contenteditable|user|comment|message|content|body|title|name|description|query|search|term|html",
    re.I,
)


def _dom_write(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    line = ctx.line(line_no)
    if re.search(r"^\s*(?:import|from|require|#|//|\*)|\.d\.ts|eslint-disable|@ts-ignore|innerHTML\s*=\s*['\"]\s*['\"]\s*;?\s*$|innerHTML\s*=\s*['\"]{2}\s*(?:;|$)", line):
        return None
    payload = next((g for g in match.groups() if g), "") or ""
    payload = payload.strip().rstrip(";").strip()
    if not payload:
        return None
    if is_pure_literal(payload):
        return None
    if re.fullmatch(r"(?:`[^`$]*`|['\"][^'\"]*['\"])\s*(?:\+\s*(?:`[^`$]*`|['\"][^'\"]*['\"]))*", payload):
        return None
    if re.search(r"^\s*(?:''|\"\"|``|null|undefined|0|false|\[\]|{})\s*$", payload):
        return None
    statement = ctx.statement(line_no, 4)
    if _DOM_SANITIZER.search(statement):
        return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by=_DOM_SANITIZER.search(statement).group(0),
                        skip_sanitizer_check=True, confidence=35)
    window = lookbehind(ctx, line_no, 10) + "\n" + statement + "\n" + lookahead(ctx, line_no, 2)
    sanitizer = _DOM_SANITIZER.search(window)
    tainted = bool(re.search(r"location\.(?:hash|search|href)|document\.(?:URL|referrer|cookie)|window\.name|URLSearchParams|searchParams\.get|req\.(?:query|body|params)|request\.|postMessage|event\.data|e\.data|message\.data", window, re.I)) or arg_tainted(ctx, line_no, payload, lookback=15)
    dynamic = bool(re.search(r"\$\{|\+\s*\w|\w\s*\+|\(|\.", payload)) or bool(_DOM_SOURCE.search(payload))
    if not dynamic and not tainted:
        return None
    if tainted:
        severity, confidence = Severity.HIGH, 92
    elif re.search(r"fetch\(|axios|\.json\(\)|response|res\.data|data\.|api", window, re.I):
        severity, confidence = Severity.HIGH, 75
    else:
        severity, confidence = Severity.MEDIUM, 65
    return make_hit(ctx, line_no, column=match.start() + 1, severity=severity, confidence=confidence if not sanitizer else 35,
                    mitigated_by=sanitizer.group(0) if sanitizer else None, skip_sanitizer_check=True,
                    description="Untrusted or dynamic content is written to the DOM as HTML" + (" from a user-controlled source." if tainted else "."))


def _post_message_listener(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    block = lookahead(ctx, line_no, 15)
    if re.search(r"\.origin\b|event\.source|e\.source|origin\s*(?:===?|!==?)|ALLOWED_ORIGINS|allowedOrigins|trustedOrigins", block, re.I):
        return None
    return make_hit(ctx, line_no, column=match.start() + 1)


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

RULES: tuple[Rule, ...] = (
    # ---- 19. frontend-assets --------------------------------------------- #
    Rule(
        id="FE-001",
        surface="frontend-assets",
        name="External script loaded without Subresource Integrity",
        description="A <script> tag references a third-party/CDN origin without an integrity attribute; a compromised CDN can inject code.",
        severity=Severity.MEDIUM,
        cwe="CWE-353",
        confidence=85,
        extensions=MARKUP_EXTS,
        keywords=("<script",),
        multiline=True,
        patterns=(_EXTERNAL_SCRIPT,),
        checker=_sri,
        use_surface_indicators=False,
        recommendation="Add integrity=\"sha384-...\" and crossorigin=\"anonymous\" to every external script/stylesheet, or self-host the asset.",
        remediation="<script src=\"https://cdn.example.com/lib.js\" integrity=\"sha384-<hash>\" crossorigin=\"anonymous\"></script>",
    ),
    Rule(
        id="FE-002",
        surface="frontend-assets",
        name="External stylesheet loaded without Subresource Integrity",
        description="A <link rel=stylesheet> references a third-party origin without an integrity attribute (CSS can exfiltrate data and inject UI).",
        severity=Severity.LOW,
        cwe="CWE-353",
        confidence=80,
        extensions=MARKUP_EXTS,
        keywords=("<link",),
        multiline=True,
        patterns=(_EXTERNAL_STYLE,),
        checker=_sri,
        use_surface_indicators=False,
        recommendation="Add integrity and crossorigin attributes or self-host the stylesheet.",
        remediation="<link rel=\"stylesheet\" href=\"https://cdn.example.com/lib.css\" integrity=\"sha384-<hash>\" crossorigin=\"anonymous\">",
    ),
    Rule(
        id="FE-003",
        surface="frontend-assets",
        name="Frontend security headers / CSP weakened",
        description="Content-Security-Policy or related headers are configured permissively ('unsafe-inline', 'unsafe-eval', wildcard sources).",
        severity=Severity.MEDIUM,
        cwe="CWE-1021",
        confidence=85,
        extensions=MARKUP_EXTS + (".js", ".ts", ".py", ".rb", ".go", ".java", ".conf", ".json", ".yaml", ".yml", ".toml", ".htaccess", ".cs"),
        keywords=("content-security-policy", "unsafe-inline", "unsafe-eval", "x-frame-options", "frame-ancestors", "contentsecuritypolicy", "helmet"),
        patterns=(
            r"(?:script-src|default-src)[^;\"'\n]*'unsafe-eval'",
            r"(?:script-src|default-src)[^;\"'\n]*'unsafe-inline'(?![^;\"'\n]*'nonce-)",
            r"(?:script-src|default-src|object-src|frame-ancestors)[^;\"'\n]*\s\*\s*(?:;|['\"]|$)",
            r"(?:script-src|default-src)[^;\"'\n]*\s(?:https?:|data:|blob:)\s*(?:;|['\"]|$)",
            r"contentSecurityPolicy\s*:\s*false",
            r"helmet\.contentSecurityPolicy\s*\(\s*\{\s*directives\s*:\s*\{[^}]*(?:unsafe-inline|unsafe-eval)",
            r"X-Frame-Options['\"]?\s*[:,=]\s*['\"]?ALLOWALL",
            r"frame-ancestors\s+\*",
            r"frameguard\s*:\s*false",
            r"X_FRAME_OPTIONS\s*=\s*['\"]ALLOWALL['\"]",
        ),
        negatives=(r"^\s*(?:#|//|\*)", r"report-only|Report-Only|report_only"),
        use_surface_indicators=False,
        recommendation="Use a nonce/hash-based CSP without 'unsafe-inline'/'unsafe-eval' and restrict frame-ancestors.",
        remediation="Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-<random>'; object-src 'none'; frame-ancestors 'none'",
    ),
    # ---- 20. javascript-analysis ----------------------------------------- #
    Rule(
        id="JS-001",
        surface="javascript-analysis",
        name="Raw DOM write with dynamic content (innerHTML/document.write)",
        description="HTML is injected into the DOM from a dynamic value, enabling DOM-based XSS when the value is attacker-influenced.",
        severity=Severity.HIGH,
        cwe="CWE-79",
        confidence=80,
        extensions=JS_EXTS,
        keywords=("innerhtml", "outerhtml", "document.write", "insertadjacenthtml", ".html(", "append(", "prepend(", "dangerouslysetinnerhtml", "__html", "v-html", "@html", "bypasssecuritytrust", "parsehtml", "createcontextualfragment", "sethtmlunsafe", "parsefromstring", "srcdoc", "javascript:", ".after(", ".before(", "replacewith("),
        patterns=(_DOM_SINK,),
        checker=_dom_write,
        recommendation="Prefer textContent / framework bindings; sanitize any HTML with DOMPurify before insertion and enforce Trusted Types.",
        remediation="el.textContent = value; // or el.innerHTML = DOMPurify.sanitize(html)",
    ),
    Rule(
        id="JS-002",
        surface="javascript-analysis",
        name="postMessage without origin restriction",
        description="Messages are broadcast to any origin or received without validating event.origin.",
        severity=Severity.MEDIUM,
        cwe="CWE-346",
        confidence=85,
        extensions=JS_EXTS,
        keywords=("postmessage", "message"),
        patterns=(
            r"\.postMessage\s*\(\s*[^,]+,\s*['\"]\*['\"]",
            r"addEventListener\s*\(\s*['\"]message['\"]\s*,",
            r"window\.onmessage\s*=",
        ),
        negatives=(r"^\s*(?:import|from|require|#|//|\*)", r"worker\.|Worker\(|MessageChannel|port\.postMessage|BroadcastChannel|self\.postMessage|process\.on|ipcRenderer|chrome\.runtime"),
        checker=_post_message_listener,
        use_surface_indicators=False,
        recommendation="Always pass an explicit targetOrigin and verify event.origin against an allow-list in listeners.",
        remediation="window.addEventListener('message', e => { if (e.origin !== 'https://trusted.example.com') return; ... })",
    ),
    Rule(
        id="JS-003",
        surface="javascript-analysis",
        name="Sensitive data stored in browser storage",
        description="Tokens/passwords written to localStorage/sessionStorage are readable by any script on the origin (XSS => account takeover).",
        severity=Severity.MEDIUM,
        cwe="CWE-922",
        confidence=85,
        extensions=JS_EXTS,
        keywords=("localstorage", "sessionstorage"),
        patterns=(
            r"(?:localStorage|sessionStorage)\.setItem\s*\(\s*['\"`][^'\"`]*(?:token|jwt|password|passwd|secret|api[_-]?key|apikey|auth|session|credential|refresh|access|bearer|private|card|ssn)[^'\"`]*['\"`]",
            r"(?:localStorage|sessionStorage)\[\s*['\"`][^'\"`]*(?:token|jwt|password|secret|api[_-]?key|auth|credential)[^'\"`]*['\"`]\s*\]\s*=",
            r"(?:localStorage|sessionStorage)\.\w*(?:token|jwt|password|secret|apiKey|auth|credential)\w*\s*=",
        ),
        negatives=(r"^\s*(?:import|from|require|#|//|\*)", r"removeItem|getItem|theme|locale|lang|csrf|xsrf|preference|consent|onboarding|tour|seen|dismissed"),
        use_surface_indicators=False,
        recommendation="Keep session tokens in HttpOnly, Secure, SameSite cookies; if a token must live in JS memory, never persist it to storage.",
        remediation="Use a cookie-based session or an in-memory access token with a refresh flow via HttpOnly cookie.",
    ),
    Rule(
        id="JS-004",
        surface="javascript-analysis",
        name="Dangerous URL / code sink in JavaScript",
        description="Client-side code evaluates strings or navigates to attacker-influenced URLs (javascript: URLs, eval-like sinks, open redirect via location).",
        severity=Severity.HIGH,
        cwe="CWE-79",
        confidence=80,
        extensions=JS_EXTS,
        keywords=("javascript:", "settimeout", "setinterval", "eval(", "function(", "execscript", "location", "open("),
        patterns=(
            r"(?:href|src|action|location(?:\.href)?)\s*=\s*(?:`javascript:|['\"]javascript:[^'\"]*['\"]\s*\+|\w+\s*\+\s*['\"]javascript:)",
            r"\b(?:setTimeout|setInterval)\s*\(\s*(?:['\"`][^'\"`]*['\"`]\s*\+\s*\w|`[^`]*\$\{)",
            r"\bexecScript\s*\(",
            r"window\.open\s*\(\s*(?:location\.(?:hash|search)|decodeURIComponent\(|new\s+URLSearchParams|params\.|searchParams\.get)",
            r"location(?:\.href|\.assign\(|\.replace\()?\s*=?\s*\(?\s*(?:decodeURIComponent\(\s*)?(?:location\.hash|location\.search|new\s+URLSearchParams|searchParams\.get|document\.referrer|window\.name)",
        ),
        negatives=(r"^\s*(?:import|from|require|#|//|\*)", r"\.d\.ts", r"startsWith\(\s*['\"]/(?!/)|new\s+URL\(|isSafeUrl|isRelative|allowlist|ALLOWED"),
        sanitizers=(r"startsWith\(\s*['\"]/(?!/)", r"new\s+URL\(", r"isSafeUrl", r"isRelative", r"allowlist", r"ALLOWED", r"encodeURIComponent", r"sanitizeUrl", r"\.origin\s*===?"),
        recommendation="Never build javascript: URLs; validate navigation targets against same-origin/relative-path rules.",
        remediation="const target = new URL(next, location.origin); if (target.origin !== location.origin) target = '/';",
    ),
)
