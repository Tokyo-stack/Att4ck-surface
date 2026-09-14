"""Infrastructure surface: cloud storage, cache services, message queues,
logging, dependencies, subdomains, DNS, server configuration and containers
(surfaces 23, 25, 26, 27, 32, 35, 36, 37, 38).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator

from attack_surface.analysis import (
    PII_DATA,
    SENSITIVE_DATA,
    arg_tainted,
    has_input,
    lookahead,
    lookbehind,
    make_hit,
    strip_strings,
    version_lt,
)
from attack_surface.models import FileContext, Hit, Rule, Severity

CODE_EXTS = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".rb", ".java", ".go", ".cs", ".kt", ".scala", ".swift", ".dart")
CONFIG_EXTS = (".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".xml", ".tf", ".hcl", ".tfvars", ".env", ".txt", ".sh")
IAC_EXTS = (".tf", ".hcl", ".json", ".yaml", ".yml", ".py", ".ts", ".js", ".go", ".rb", ".xml", ".toml", ".sh", ".bicep", ".tfvars")

# --------------------------------------------------------------------------- #
# 23. cloud-storage
# --------------------------------------------------------------------------- #


def _public_principal(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    block = lookbehind(ctx, line_no, 8) + "\n" + ctx.line(line_no) + "\n" + lookahead(ctx, line_no, 8)
    if re.search(r"[\"']?Effect[\"']?\s*[:=]\s*[\"']Deny[\"']", block):
        return None
    if re.search(r"Condition|aws:SourceArn|aws:SourceVpce|aws:SourceVpc|aws:PrincipalOrgID|aws:Referer|aws:SecureTransport|cloudfront\.amazonaws\.com|OriginAccessIdentity|origin_access_identity", block, re.I):
        return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by="Condition/OAI restricts the principal", skip_sanitizer_check=True, confidence=40)
    actions = re.search(r"[\"']?Actions?[\"']?\s*[:=]\s*\[?\s*[\"']([^\"']+)", block)
    action = actions.group(1) if actions else ""
    severity = Severity.CRITICAL if re.search(r"\*|Put|Delete|Write|Update|Create", action) else Severity.HIGH
    return make_hit(ctx, line_no, column=match.start() + 1, severity=severity, skip_sanitizer_check=True,
                    description=f"Policy grants '{action or 'unknown'}' to every principal (*), making the resource public.")


# --------------------------------------------------------------------------- #
# 25. cache-services
# --------------------------------------------------------------------------- #

_CACHE_SET = re.compile(
    r"\b(?P<client>redis|r|rdb|rds|cache|client|redis_client|redisClient|store|mc|memcache|memcached|conn|cache_client|cacheClient|kv|self\.redis|self\.cache|this\.redis|this\.cache|app\.cache|self\.client)\s*\.\s*(?P<op>set|hset|hmset|mset|lpush|rpush|sadd|setnx|add|replace|append)\s*\(",
)
_TTL = re.compile(r"\bex\s*=|\bpx\s*=|\bexat\s*=|\bpxat\s*=|\bttl\b|['\"]EX['\"]|['\"]PX['\"]|\bEX\b|\bPX\b|timeout\s*=|expire|setex|\.expire\(|expiry|expires|expiration|max_age|maxAge|keepttl|KEEPTTL|time\s*=|\bexptime|\bexpiretime", re.I)
_CACHE_SENSITIVE = re.compile(r"token|password|passwd|secret|session|card|cvv|ssn|jwt|credential|api[_-]?key|private|otp|pin\b|auth|refresh|bearer|cookie|access", re.I)
_CACHE_PROTECT = re.compile(r"encrypt|fernet|cipher|aes|hash|hmac|sha256|bcrypt|digest|sign\(|seal|kms", re.I)


def _cache_set(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    line = ctx.line(line_no)
    if re.search(r"^\s*(?:import|from|require|#|//)|Set\(|\.set\(\s*['\"](?:Content-|X-|Cache-Control|Authorization)|headers\.set|res\.set\(|response\.set\(|map\.set|Map\(|WeakMap|localStorage|sessionStorage|cookies\.set|\.set\(\s*\{|\.set\(\s*\[|form\.|state\.|store\.set\(\s*['\"](?:theme|locale)|\bSet\b|setState|\.set\(\s*\w+\s*\)\s*;?\s*$", line):
        return None
    if match.group("client") in {"client", "conn", "store", "kv", "self.client"} and not re.search(r"redis|memcache|cache|ttl|\bex=|setex", ctx.window(line_no, 30, 0), re.I):
        return None
    statement = ctx.statement(line_no, 5)
    following = lookahead(ctx, line_no, 3)
    has_ttl = bool(_TTL.search(statement) or re.search(r"\.expire\(|\.expireat\(|\.pexpire\(|\.persist\(", following))
    sensitive = _CACHE_SENSITIVE.search(statement)
    protected = _CACHE_PROTECT.search(statement + "\n" + lookbehind(ctx, line_no, 6))
    if has_ttl and not sensitive:
        return None
    if sensitive and not protected:
        return make_hit(ctx, line_no, column=match.start() + 1, severity=Severity.MEDIUM if has_ttl else Severity.HIGH, confidence=80,
                        name="Sensitive value cached in plaintext" + ("" if has_ttl else " without expiry"),
                        description=f"'{sensitive.group(0)}' data is written to the cache" + (" without a TTL" if not has_ttl else "") + " and without encryption/hashing.",
                        skip_sanitizer_check=True)
    if sensitive and protected:
        return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by=protected.group(0), confidence=30, skip_sanitizer_check=True,
                        severity=Severity.LOW)
    return make_hit(ctx, line_no, column=match.start() + 1, severity=Severity.LOW, confidence=65, skip_sanitizer_check=True,
                    name="Cache key set without expiry",
                    description=f"{match.group('client')}.{match.group('op')}() stores data with no TTL, allowing unbounded growth and stale sensitive data.")


def _cache_connection(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    statement = ctx.statement(line_no, 8)
    if re.search(r"localhost|127\.0\.0\.1|::1|host\s*=\s*['\"]redis['\"]|@redis:|@cache:|@memcached:", statement) and not re.search(r"\bprod|production", ctx.rel_path, re.I):
        return make_hit(ctx, line_no, column=match.start() + 1, severity=Severity.INFO, confidence=30, skip_sanitizer_check=True,
                        description="Cache connection to a local/link-local host without auth or TLS (acceptable for local development only).")
    if re.search(r"rediss://|ssl\s*=\s*True|ssl:\s*true|tls\s*[:=]|password\s*[=:]|auth\s*[=:]|\bpassword\b|username\s*=|credential|AUTH\s|:[^@/\s'\"]+@|sasl|SASL|\bcert", statement, re.I):
        return None
    if re.search(r"os\.environ|getenv|process\.env|\$\{|\{\{|config\.|settings\.", statement):
        return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by="configuration-driven connection", confidence=30, skip_sanitizer_check=True, severity=Severity.LOW)
    return make_hit(ctx, line_no, column=match.start() + 1, skip_sanitizer_check=True)


# --------------------------------------------------------------------------- #
# 26. message-queues
# --------------------------------------------------------------------------- #

_DESER = re.compile(
    r"\b(?:pickle|cPickle|_pickle|dill|cloudpickle|marshal|shelve|jsonpickle)\.(?:loads?|Unpickler|decode)\s*\(|"
    r"\bjsonpickle\.decode\s*\(|\byaml\.(?:load|unsafe_load|load_all)\s*\(|"
    r"\bunserialize\s*\(|\bMarshal\.load\s*\(|\bYAML\.(?:load|unsafe_load)\s*\(|\bPsych\.(?:load|unsafe_load)\s*\(|"
    r"new\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)|XMLDecoder|\bXStream\b|\bSerializationUtils\.deserialize|"
    r"BinaryFormatter|\bLosFormatter\b|\bNetDataContractSerializer\b|SoapFormatter|JavaScriptSerializer[^\n]*TypeResolver|"
    r"TypeNameHandling\.(?:All|Auto|Objects|Arrays)|node-serialize|serialize\.unserialize|\bv8\.deserialize\s*\(|"
    r"\bphp_unserialize|\bunmarshal\.(?:Unmarshal|Decode)|gob\.NewDecoder|\bmsgpack\.(?:unpackb|loads)\s*\([^)]*raw\s*=\s*False",
    re.I,
)
_QUEUE_CONTEXT = re.compile(
    r"kafka|celery|rabbit|pika|amqp|\bsqs\b|pubsub|pub_sub|\bqueue\b|consumer|subscribe|on_message|basic_consume|"
    r"\bchannel\b|\bmessage\b|\bmsg\b|payload|\bbody\b|\bevent\b|\btask\b|\bjob\b|\bworker\b|\bzmq\b|\bnats\b|mqtt|"
    r"redis.*(?:brpop|blpop|subscribe|listen)|\bstream\b|\bkinesis\b|\bbull\b|\bbullmq\b|sidekiq|resque|rq\.|dramatiq|"
    r"faust|nsq|activemq|jms|servicebus|eventhub|\brecv\b|\bsocket\b|\brequest\b|\breq\b|\bdata\b",
    re.I,
)
_DESER_SAFE = re.compile(r"\bhmac\b|compare_digest|signature|\bverify\b|itsdangerous|\bsigned\b|\btrusted\b|json\.loads|SafeLoader|safe_load|RestrictedUnpickler|find_class|allowlist|whitelist|safe_classes|permitted_classes|ValidatingObjectInputStream|ObjectInputFilter|setObjectInputFilter|\ballowed_classes", re.I)


def _deserialize(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    line = ctx.line(line_no)
    if re.search(r"^\s*(?:import|from|require|#|//|\*)|\.d\.ts|test_|spec\.|describe\(", line):
        return None
    if re.search(r"yaml\.(?:load|load_all)", match.group(0)) and re.search(r"SafeLoader|BaseLoader|safe_load", ctx.statement(line_no, 3)):
        return None
    if re.search(r"pickle\.(?:dumps?|Pickler)|\.dump\(|serialize\(", line) and not re.search(r"loads?\(", line):
        return None
    block = lookbehind(ctx, line_no, 15) + "\n" + line + "\n" + lookahead(ctx, line_no, 5)
    queue = _QUEUE_CONTEXT.search(block) or _QUEUE_CONTEXT.search(ctx.rel_path)
    tainted = has_input(line) or arg_tainted(ctx, line_no, line, lookback=20) or bool(re.search(r"\b(?:message|msg|body|payload|event|task|job|data|recv|frame|record|value)\b", line, re.I))
    safe = _DESER_SAFE.search(block)
    if safe and re.search(r"RestrictedUnpickler|find_class|ValidatingObjectInputStream|ObjectInputFilter|setObjectInputFilter|permitted_classes|allowed_classes|safe_classes", safe.group(0), re.I):
        return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by=safe.group(0), confidence=30, severity=Severity.MEDIUM, skip_sanitizer_check=True)
    if queue or tainted:
        severity, confidence = Severity.CRITICAL, 92
        desc = "Untrusted message/payload data is deserialised with a format that can execute arbitrary code."
    else:
        severity, confidence = Severity.HIGH, 70
        desc = "Native object deserialisation is used; any attacker-controlled input reaching it yields remote code execution."
    return make_hit(ctx, line_no, column=match.start() + 1, severity=severity, confidence=confidence if not safe else 45,
                    mitigated_by=safe.group(0) if safe else None, skip_sanitizer_check=True, description=desc)


# --------------------------------------------------------------------------- #
# 27. logging
# --------------------------------------------------------------------------- #

_LOG_CALL = re.compile(
    r"\b(?:log(?:ger|ging)?|LOG|LOGGER|_log|_logger|self\.log(?:ger)?|this\.log(?:ger)?|app\.log(?:ger)?|current_app\.logger|console|winston|pino|bunyan|log4j|slf4j|syslog|Log|NSLog|Timber|Serilog|Log4Net|System\.out|System\.err|Console|error_log|Rails\.logger|logger)\s*\.?\s*(?:debug|info|warn(?:ing)?|error|critical|exception|fatal|log|println|print|printf|write(?:line)?|trace|verbose|v|d|i|w|e|notice|Information|Warning|Error|Debug|Fatal|WriteLine|Write)\s*\("
    r"|\bprint\s*\(|\bprintf\s*\(|\becho\s+|\bputs\s+|\bfmt\.Print(?:ln|f)?\s*\(|\blog\.Print(?:ln|f)?\s*\(|\bSystem\.out\.print(?:ln)?\s*\(|\berror_log\s*\(|\bvar_dump\s*\(|\bprint_r\s*\(|\bconsole\.(?:log|info|warn|error|debug|table|dir)\s*\(",
)
_LOG_MASK = re.compile(r"\bmask|redact|scrub|obfuscat|\*{3,}|\bhash(?:ed|_)|len\(|\.length\b|last4|\[:4\]|\[-4:\]|filter|sanitize|censor|hide|\bsecure_log|\[REDACTED\]|\bsha\d*\(|digest|truncate|\bbool\(|is None|!= null|=== undefined|\?\?|exists|present|missing|invalid|required|expired|not found|reset requested|has_password|password_set|\.id\b|user\.id|user_id|\bemail\s*=\s*\w+\.email", re.I)
_LOG_SENSITIVE = re.compile(rf"\b\w*{SENSITIVE_DATA}\w*\b", re.I)
_LOG_PII = re.compile(rf"\b\w*{PII_DATA}\w*\b", re.I)


def _log_sensitive(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    statement = ctx.statement(line_no, 4)
    if re.search(r"^\s*(?:import|from|require|#|//|\*)|test_|spec\.|describe\(|\.d\.ts", statement):
        return None
    stripped = strip_strings(statement, keep_interpolation=True)
    body = stripped[match.end() - (len(ctx.line(line_no)) - len(ctx.line(line_no).lstrip())) - 1:] if False else stripped
    call_body = body[body.find("(") + 1:] if "(" in body else body
    sensitive = _LOG_SENSITIVE.search(call_body)
    pii = None if sensitive else _LOG_PII.search(call_body)
    hit_match = sensitive or pii
    if not hit_match:
        return None
    ident = hit_match.group(0)
    if re.search(r"(?:_id|Id|ID|_count|Count|_len|Length|_type|Type|_name|Name|_field|_key_id|KeyId|_url|Url|_path|Path|_hash|Hash|_set|_enabled|Enabled|_required|Required|_valid|Valid|_changed|Changed|_reset|Reset|_expired|Expired|_error|Error|_status|Status|_policy|Policy|_strength|_rules|_attempts|Attempts|_updated|Updated|_created|_at|_ok|_exists|_missing|_provided|_present|_length|_format|_check|Check|_prefix|_suffix|_masked|Masked|_redacted|_last4|_preview|Preview|_header|Header|_hint|Hint|_label|Label|_cookie_name|_option|Option|_config|Config|_setting|Setting|_size|_ttl|_expiry|_expires|_days|_minutes|_seconds)$", ident):
        return None
    if ident.lower() in {"authorization", "cookie", "token", "session", "email", "phone", "pin", "auth", "credentials", "otp"} and not re.search(rf"[.\[{{,+:]\s*['\"]?{re.escape(ident)}\b|\b{re.escape(ident)}\s*[\]}},)+]|\${{\s*{re.escape(ident)}|{{\s*{re.escape(ident)}", call_body):
        return None
    mask = _LOG_MASK.search(statement)
    if mask and re.search(re.escape(mask.group(0)), call_body):
        return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by=mask.group(0), confidence=30, skip_sanitizer_check=True, severity=Severity.LOW)
    if sensitive:
        severity, confidence = Severity.HIGH, 85
        desc = f"Credential/secret-like value '{ident}' is written to logs in plaintext."
    else:
        severity, confidence = Severity.MEDIUM, 70
        desc = f"Personal data field '{ident}' is written to logs; PII in logs violates minimisation requirements (GDPR/PCI)."
    return make_hit(ctx, line_no, column=match.start() + 1, severity=severity, confidence=confidence, skip_sanitizer_check=True, description=desc)


# --------------------------------------------------------------------------- #
# 32. dependencies
# --------------------------------------------------------------------------- #

#: package -> (minimum version considered patched, headline CVE/advisory)
KNOWN_VULNERABLE: dict[str, tuple[str, str]] = {
    # Python
    "django": ("4.2.11", "multiple CVEs incl. CVE-2024-24680/CVE-2023-41164"),
    "flask": ("2.3.2", "CVE-2023-30861 session cookie leak"),
    "werkzeug": ("3.0.3", "CVE-2024-34069 debugger RCE"),
    "jinja2": ("3.1.4", "CVE-2024-22195 / CVE-2024-34064 XSS"),
    "requests": ("2.32.0", "CVE-2024-35195 verify bypass"),
    "urllib3": ("2.2.2", "CVE-2024-37891 / CVE-2023-45803"),
    "pyyaml": ("5.4", "CVE-2020-14343 arbitrary code execution"),
    "cryptography": ("42.0.4", "CVE-2024-26130 / CVE-2023-49083"),
    "pillow": ("10.3.0", "CVE-2024-28219 buffer overflow"),
    "paramiko": ("3.4.0", "CVE-2023-48795 Terrapin"),
    "sqlparse": ("0.5.0", "CVE-2024-4340 DoS"),
    "aiohttp": ("3.9.4", "CVE-2024-30251 / CVE-2024-23334"),
    "tornado": ("6.4.1", "CVE-2024-52804"),
    "certifi": ("2023.7.22", "removed e-Tugra root"),
    "setuptools": ("70.0.0", "CVE-2024-6345 RCE"),
    "pip": ("23.3", "CVE-2023-5752"),
    "lxml": ("4.9.1", "CVE-2022-2309"),
    "numpy": ("1.22.0", "CVE-2021-41496"),
    "pycryptodome": ("3.19.1", "CVE-2023-52323"),
    "pyjwt": ("2.4.0", "CVE-2022-29217 key confusion"),
    "python-jose": ("3.4.0", "CVE-2024-33663 algorithm confusion"),
    "gunicorn": ("22.0.0", "CVE-2024-1135 request smuggling"),
    "twisted": ("24.7.0", "CVE-2024-41671"),
    "fastapi": ("0.109.1", "CVE-2024-24762 ReDoS"),
    "starlette": ("0.40.0", "CVE-2024-47874 DoS"),
    "sqlalchemy": ("1.3.0", "CVE-2019-7164 SQL injection"),
    "celery": ("5.2.2", "CVE-2021-23727"),
    "redis": ("4.5.4", "CVE-2023-28859"),
    "httpx": ("0.23.0", "CVE-2021-41945"),
    "markdown2": ("2.4.0", "CVE-2021-26813"),
    "bleach": ("6.0.0", "CVE-2021-23980 mutation XSS"),
    "ansible": ("2.10.0", "multiple"),
    "psycopg2": ("2.8.0", "outdated"),
    "pymongo": ("4.6.3", "CVE-2024-5629"),
    "langchain": ("0.0.317", "CVE-2023-46229 SSRF"),
    "transformers": ("4.38.0", "CVE-2024-3568 deserialization"),
    "torch": ("2.2.0", "CVE-2024-31580"),
    "tensorflow": ("2.12.1", "multiple 2023 CVEs"),
    "scrapy": ("2.11.1", "CVE-2024-3572"),
    "black": ("24.3.0", "CVE-2024-21503 ReDoS"),
    "idna": ("3.7", "CVE-2024-3651 DoS"),
    "zipp": ("3.19.1", "CVE-2024-5569"),
    "jsonschema": ("4.0.0", "outdated"),
    "pydantic": ("1.10.13", "CVE-2024-3772 ReDoS"),
    "wheel": ("0.38.1", "CVE-2022-40898"),
    "future": ("0.18.3", "CVE-2022-40899"),
    "oauthlib": ("3.2.2", "CVE-2022-36087"),
    "mako": ("1.2.2", "CVE-2022-40023"),
    "markupsafe": ("2.0.0", "outdated"),
    "protobuf": ("3.20.2", "CVE-2022-1941"),
    "grpcio": ("1.53.2", "CVE-2023-32732"),
    "waitress": ("3.0.1", "CVE-2024-49768"),
    "sentry-sdk": ("1.14.0", "CVE-2023-28117"),
    "mlflow": ("2.9.2", "multiple path traversal CVEs"),
    "vyper": ("0.4.0", "multiple"),
    "flask-cors": ("4.0.2", "CVE-2024-6221"),
    "flask-caching": ("2.3.0", "CVE-2021-33026"),
    "python-multipart": ("0.0.18", "CVE-2024-53981"),
    "pyopenssl": ("23.2.0", "CVE-2023-38325"),
    "rsa": ("4.7", "CVE-2020-25658"),
    "ecdsa": ("0.19.0", "CVE-2024-23342"),
    "pysaml2": ("6.5.0", "CVE-2021-21239"),
    "ldap3": ("2.9.1", "outdated"),
    "reportlab": ("3.6.13", "CVE-2023-33733 RCE"),
    "nltk": ("3.9", "CVE-2024-39705"),
    "openpyxl": ("3.0.10", "outdated"),
    "html5lib": ("1.1", "outdated"),
    "lxml-html-clean": ("0.4.0", "CVE-2024-52997"),
    "babel": ("2.9.1", "CVE-2021-42771"),
    "ipython": ("8.10.0", "CVE-2023-24816"),
    "jupyter-server": ("2.11.2", "CVE-2023-49080"),
    "notebook": ("6.4.12", "CVE-2022-29238"),
    "pyramid": ("1.10.5", "outdated"),
    "bottle": ("0.12.25", "CVE-2022-31799"),
    "tensorflow-cpu": ("2.12.1", "multiple 2023 CVEs"),
    "django-rest-framework": ("3.15.2", "CVE-2024-21520"),
    "djangorestframework": ("3.15.2", "CVE-2024-21520 XSS"),
    # JavaScript
    "lodash": ("4.17.21", "CVE-2021-23337 prototype pollution"),
    "express": ("4.20.0", "CVE-2024-43796 XSS / CVE-2024-29041 redirect"),
    "axios": ("1.7.4", "CVE-2024-39338 SSRF / CVE-2023-45857"),
    "jquery": ("3.5.0", "CVE-2020-11022/11023 XSS"),
    "minimist": ("1.2.6", "CVE-2021-44906"),
    "node-fetch": ("2.6.7", "CVE-2022-0235"),
    "moment": ("2.29.4", "CVE-2022-31129 ReDoS"),
    "jsonwebtoken": ("9.0.0", "CVE-2022-23529/23539/23540"),
    "ws": ("8.17.1", "CVE-2024-37890 DoS"),
    "semver": ("7.5.2", "CVE-2022-25883 ReDoS"),
    "tar": ("6.2.1", "CVE-2024-28863"),
    "path-to-regexp": ("8.0.0", "CVE-2024-45296 ReDoS"),
    "body-parser": ("1.20.3", "CVE-2024-45590 DoS"),
    "send": ("0.19.0", "CVE-2024-43799"),
    "serve-static": ("1.16.0", "CVE-2024-43800"),
    "cookie": ("0.7.0", "CVE-2024-47764"),
    "next": ("14.2.25", "CVE-2025-29927 middleware bypass"),
    "react": ("16.0.0", "outdated"),
    "vue": ("2.7.0", "outdated"),
    "angular": ("1.8.0", "CVE-2020-7676 XSS"),
    "socket.io": ("4.6.2", "CVE-2023-32695"),
    "mongoose": ("8.8.3", "CVE-2024-53900 search injection"),
    "sequelize": ("6.28.1", "CVE-2023-25813 SQL injection"),
    "handlebars": ("4.7.7", "CVE-2021-23369 RCE"),
    "ejs": ("3.1.10", "CVE-2024-33883"),
    "pug": ("3.0.3", "CVE-2024-36361"),
    "marked": ("4.0.10", "CVE-2022-21680 ReDoS"),
    "dompurify": ("3.1.3", "CVE-2024-45801 mXSS"),
    "underscore": ("1.13.6", "CVE-2021-23358"),
    "async": ("3.2.2", "CVE-2021-43138"),
    "qs": ("6.10.3", "CVE-2022-24999"),
    "yaml": ("2.2.2", "CVE-2023-2251"),
    "js-yaml": ("3.13.1", "CVE-2019-10746"),
    "serialize-javascript": ("6.0.2", "CVE-2024-11831 XSS"),
    "ip": ("2.0.1", "CVE-2024-29415 SSRF"),
    "braces": ("3.0.3", "CVE-2024-4068 DoS"),
    "micromatch": ("4.0.8", "CVE-2024-4067 ReDoS"),
    "vite": ("5.4.12", "CVE-2025-30208 file read"),
    "webpack": ("5.94.0", "CVE-2024-43788 XSS"),
    "postcss": ("8.4.31", "CVE-2023-44270"),
    "follow-redirects": ("1.15.6", "CVE-2024-28849"),
    "undici": ("6.21.1", "CVE-2025-22150"),
    "got": ("11.8.5", "CVE-2022-33987 redirect to UNIX socket"),
    "request": ("999", "deprecated / CVE-2023-28155 SSRF"),
    "validator": ("13.7.0", "CVE-2021-3765 ReDoS"),
    "bcrypt": ("5.0.0", "CVE-2020-7689"),
    "passport": ("0.6.0", "CVE-2022-25896 session fixation"),
    "helmet": ("4.0.0", "outdated"),
    "cors": ("2.8.5", "outdated"),
    "multer": ("1.4.5-lts.1", "CVE-2022-24434 DoS"),
    "sharp": ("0.32.6", "CVE-2023-4863 libwebp"),
    "electron": ("28.3.2", "multiple"),
    "puppeteer": ("22.0.0", "outdated chromium"),
    "xml2js": ("0.5.0", "CVE-2023-0842 prototype pollution"),
    "fast-xml-parser": ("4.4.1", "CVE-2024-41818 ReDoS"),
    "nodemailer": ("6.9.9", "CVE-2024-27302? ReDoS"),
    "uuid": ("7.0.0", "CVE-2020-8267 (v3)"),
    "debug": ("4.3.1", "CVE-2017-16137 ReDoS"),
    "shell-quote": ("1.7.3", "CVE-2021-42740 RCE"),
    "node-forge": ("1.3.0", "CVE-2022-24771/24772/24773 signature bypass"),
    "crypto-js": ("4.2.0", "CVE-2023-46233 weak PBKDF2"),
    "elliptic": ("6.6.1", "CVE-2024-48949"),
    "ajv": ("6.12.3", "CVE-2020-15366"),
    "tough-cookie": ("4.1.3", "CVE-2023-26136"),
    "word-wrap": ("1.2.4", "CVE-2023-26115"),
    "@babel/traverse": ("7.23.2", "CVE-2023-45133 arbitrary code execution"),
    "@nestjs/core": ("9.0.0", "outdated"),
    "koa": ("2.15.4", "CVE-2025-25200"),
    "fastify": ("4.28.1", "CVE-2024-41818/41919"),
    "hapi": ("21.0.0", "outdated"),
    "@hapi/hoek": ("9.0.3", "CVE-2020-36604"),
    "jose": ("4.15.5", "CVE-2024-28176 DoS"),
    "openid-client": ("5.6.5", "outdated"),
    "next-auth": ("4.24.5", "CVE-2023-48309"),
    "prisma": ("5.0.0", "outdated"),
    "typeorm": ("0.3.0", "CVE-2022-33171 SQLi"),
    "knex": ("2.4.0", "CVE-2016-20018 SQLi"),
    "mysql": ("2.18.1", "outdated"),
    "pg": ("8.11.0", "outdated"),
    "sqlite3": ("5.1.7", "CVE-2022-43441 RCE"),
    "ioredis": ("5.3.0", "outdated"),
    "aws-sdk": ("2.1691.0", "outdated"),
    "@aws-sdk/client-s3": ("3.0.0", "outdated"),
    "firebase": ("9.0.0", "outdated"),
    "stripe": ("8.0.0", "outdated"),
    "moment-timezone": ("0.5.35", "CVE-2022-31129"),
    "dayjs": ("1.11.0", "outdated"),
    "chalk": ("4.0.0", "outdated"),
    "commander": ("7.0.0", "outdated"),
    "yargs-parser": ("18.1.2", "CVE-2020-7608 prototype pollution"),
    "y18n": ("5.0.5", "CVE-2020-7774"),
    "ini": ("1.3.6", "CVE-2020-7788"),
    "glob-parent": ("5.1.2", "CVE-2020-28469 ReDoS"),
    "trim-newlines": ("3.0.1", "CVE-2021-33623"),
    "nth-check": ("2.0.1", "CVE-2021-3803"),
    "ansi-regex": ("5.0.1", "CVE-2021-3807"),
    "json5": ("2.2.2", "CVE-2022-46175"),
    "decode-uri-component": ("0.2.1", "CVE-2022-38900"),
    "loader-utils": ("2.0.4", "CVE-2022-37601"),
    "terser": ("5.14.2", "CVE-2022-25858"),
    "http-cache-semantics": ("4.1.1", "CVE-2022-25881"),
    "xmldom": ("0.6.0", "CVE-2021-32796"),
    "@xmldom/xmldom": ("0.8.4", "CVE-2022-39353"),
    "jszip": ("3.8.0", "CVE-2021-23413 zip slip"),
    "adm-zip": ("0.5.9", "CVE-2018-1002204"),
    "archiver": ("5.0.0", "outdated"),
    "socket.io-parser": ("4.2.3", "CVE-2023-32695"),
    "engine.io": ("6.4.2", "CVE-2023-31125"),
    "express-fileupload": ("1.4.1", "CVE-2022-27140"),
    "formidable": ("2.1.2", "CVE-2022-29622"),
    "busboy": ("1.0.0", "outdated"),
    "dicer": ("999", "CVE-2022-24434 unfixed"),
    "ua-parser-js": ("1.0.33", "CVE-2022-25927 ReDoS"),
    "bootstrap": ("4.3.1", "CVE-2019-8331 XSS"),
    "swiper": ("8.0.0", "outdated"),
    "three": ("0.125.0", "CVE-2020-28496"),
    "highlight.js": ("10.4.1", "CVE-2020-26237"),
    "prismjs": ("1.27.0", "CVE-2022-23647 XSS"),
    "katex": ("0.16.10", "CVE-2024-28243"),
    "mermaid": ("10.9.3", "CVE-2024-?? XSS"),
    "quill": ("2.0.0", "CVE-2021-3163 XSS"),
    "tinymce": ("6.8.1", "CVE-2024-29881 XSS"),
    "ckeditor4": ("4.24.0", "CVE-2024-24816"),
    "@ckeditor/ckeditor5": ("35.0.0", "outdated"),
    "sanitize-html": ("2.12.1", "CVE-2024-21501"),
    "xss": ("1.0.15", "outdated"),
    "markdown-it": ("12.3.2", "CVE-2022-21670"),
    "showdown": ("2.0.0", "outdated"),
    "pdfjs-dist": ("4.2.67", "CVE-2024-4367 arbitrary JS"),
    "pdf-lib": ("1.17.0", "outdated"),
    "canvas": ("2.11.2", "outdated"),
    # PHP
    "laravel/framework": ("10.48.0", "multiple"),
    "symfony/symfony": ("6.4.0", "multiple"),
    "symfony/http-foundation": ("6.4.0", "multiple"),
    "guzzlehttp/guzzle": ("7.4.5", "CVE-2022-31042/31043"),
    "monolog/monolog": ("2.0.0", "outdated"),
    "phpmailer/phpmailer": ("6.5.0", "CVE-2021-3603"),
    "twig/twig": ("3.11.2", "CVE-2024-51754"),
    "league/flysystem": ("2.1.1", "CVE-2021-32708"),
    "phpunit/phpunit": ("9.0.0", "CVE-2017-9841 (dev RCE)"),
    "firebase/php-jwt": ("6.0.0", "CVE-2021-46743"),
    "smarty/smarty": ("4.5.3", "CVE-2024-35226 code injection"),
    "phpseclib/phpseclib": ("3.0.34", "CVE-2023-49316"),
    "dompdf/dompdf": ("2.0.4", "CVE-2023-24813 / RCE"),
    "tecnickcom/tcpdf": ("6.6.5", "multiple"),
    "wordpress": ("6.5.5", "multiple"),
    "drupal/core": ("10.2.0", "multiple"),
    "typo3/cms-core": ("12.4.0", "multiple"),
    "zendframework/zendframework": ("999", "abandoned"),
    "codeigniter4/framework": ("4.4.0", "multiple"),
    # Ruby
    "rails": ("7.0.8.4", "multiple"),
    "actionpack": ("7.0.8.4", "CVE-2024-26142 / 26143"),
    "activerecord": ("7.0.8.4", "CVE-2024-?? SQLi"),
    "activestorage": ("7.0.8.4", "outdated"),
    "nokogiri": ("1.16.5", "multiple libxml2 CVEs"),
    "rack": ("2.2.8.1", "CVE-2024-25126 / 26141 / 26146"),
    "puma": ("6.4.2", "CVE-2024-21647"),
    "devise": ("4.9.0", "outdated"),
    "sinatra": ("3.0.4", "CVE-2022-45442"),
    "rexml": ("3.3.9", "CVE-2024-49761 ReDoS"),
    "loofah": ("2.19.1", "CVE-2022-23514/23515/23516"),
    "rails-html-sanitizer": ("1.4.4", "CVE-2022-23517"),
    "json": ("2.3.0", "CVE-2020-10663"),
    "jwt": ("2.5.0", "outdated"),
    "omniauth": ("2.0.0", "CVE-2015-9284 CSRF"),
    "rubyzip": ("1.3.0", "CVE-2019-16892"),
    "kramdown": ("2.3.1", "CVE-2021-28834"),
    "redcarpet": ("3.5.1", "CVE-2020-26298"),
    "sidekiq": ("6.4.0", "CVE-2022-23837"),
    "resque": ("2.6.0", "outdated"),
    "activesupport": ("7.0.8.4", "CVE-2023-38037"),
    "actionview": ("7.0.8.4", "outdated"),
    "globalid": ("1.0.1", "CVE-2023-22799 ReDoS"),
    "sanitize": ("6.0.2", "CVE-2023-36823"),
    "faraday": ("1.0.0", "outdated"),
    # Java / Go / .NET (Maven/go.mod/csproj)
    "log4j-core": ("2.17.1", "CVE-2021-44228 Log4Shell"),
    "org.apache.logging.log4j:log4j-core": ("2.17.1", "CVE-2021-44228 Log4Shell"),
    "spring-core": ("5.3.18", "CVE-2022-22965 Spring4Shell"),
    "org.springframework:spring-core": ("5.3.18", "CVE-2022-22965 Spring4Shell"),
    "spring-boot": ("2.7.18", "multiple"),
    "org.springframework.boot:spring-boot": ("2.7.18", "multiple"),
    "jackson-databind": ("2.13.4.2", "CVE-2022-42003/42004"),
    "com.fasterxml.jackson.core:jackson-databind": ("2.13.4.2", "CVE-2022-42003/42004"),
    "commons-text": ("1.10.0", "CVE-2022-42889 Text4Shell"),
    "org.apache.commons:commons-text": ("1.10.0", "CVE-2022-42889 Text4Shell"),
    "commons-collections": ("3.2.2", "CVE-2015-6420 deserialization"),
    "commons-fileupload": ("1.5", "CVE-2023-24998"),
    "struts2-core": ("6.3.0.2", "CVE-2023-50164"),
    "org.apache.struts:struts2-core": ("6.3.0.2", "CVE-2023-50164"),
    "snakeyaml": ("2.0", "CVE-2022-1471 RCE"),
    "org.yaml:snakeyaml": ("2.0", "CVE-2022-1471 RCE"),
    "spring-security-core": ("5.7.11", "multiple"),
    "tomcat-embed-core": ("9.0.90", "multiple"),
    "netty-all": ("4.1.100", "CVE-2023-44487"),
    "io.netty:netty-all": ("4.1.100", "CVE-2023-44487"),
    "gson": ("2.8.9", "CVE-2022-25647"),
    "com.google.code.gson:gson": ("2.8.9", "CVE-2022-25647"),
    "guava": ("32.0.0", "CVE-2023-2976"),
    "com.google.guava:guava": ("32.0.0", "CVE-2023-2976"),
    "xstream": ("1.4.20", "multiple RCE"),
    "com.thoughtworks.xstream:xstream": ("1.4.20", "multiple RCE"),
    "hibernate-core": ("5.6.15", "CVE-2020-25638 SQLi"),
    "jjwt": ("0.11.5", "outdated"),
    "okhttp": ("4.9.2", "CVE-2021-0341"),
    "com.squareup.okhttp3:okhttp": ("4.9.2", "CVE-2021-0341"),
    "bcprov-jdk15on": ("1.70", "CVE-2020-15522"),
    "shiro-core": ("1.13.0", "multiple auth bypass"),
    "org.apache.shiro:shiro-core": ("1.13.0", "multiple auth bypass"),
    "golang.org/x/crypto": ("0.17.0", "CVE-2023-48795 Terrapin"),
    "golang.org/x/net": ("0.23.0", "CVE-2023-45288 HTTP/2"),
    "golang.org/x/text": ("0.3.8", "CVE-2022-32149"),
    "github.com/gin-gonic/gin": ("1.9.1", "CVE-2023-29401"),
    "github.com/gorilla/websocket": ("1.5.0", "outdated"),
    "github.com/dgrijalva/jwt-go": ("999", "CVE-2020-26160 unmaintained"),
    "github.com/golang-jwt/jwt": ("4.5.1", "CVE-2024-51744"),
    "github.com/golang-jwt/jwt/v4": ("4.5.1", "CVE-2024-51744"),
    "github.com/labstack/echo/v4": ("4.9.0", "CVE-2022-40083"),
    "github.com/gofiber/fiber/v2": ("2.52.5", "CVE-2024-25124"),
    "gopkg.in/yaml.v2": ("2.2.8", "CVE-2019-11254"),
    "gopkg.in/yaml.v3": ("3.0.1", "CVE-2022-28948"),
    "github.com/aws/aws-sdk-go": ("1.34.0", "CVE-2020-8911"),
    "github.com/docker/docker": ("24.0.9", "multiple"),
    "github.com/hashicorp/go-getter": ("1.7.4", "CVE-2024-3817"),
    "github.com/lib/pq": ("1.10.0", "outdated"),
    "github.com/go-sql-driver/mysql": ("1.7.0", "outdated"),
    "github.com/microcosm-cc/bluemonday": ("1.0.23", "CVE-2021-42576"),
    "github.com/russross/blackfriday": ("1.5.2", "outdated"),
    "github.com/mattermost/mattermost-server": ("9.5.0", "multiple"),
    "google.golang.org/grpc": ("1.56.3", "CVE-2023-44487"),
    "google.golang.org/protobuf": ("1.33.0", "CVE-2024-24786"),
    "github.com/emicklei/go-restful": ("3.10.0", "CVE-2022-1996 CORS bypass"),
    "github.com/tidwall/gjson": ("1.9.3", "CVE-2021-42248"),
    "github.com/buger/jsonparser": ("1.1.1", "CVE-2020-35381"),
    "github.com/ulikunitz/xz": ("0.5.8", "CVE-2021-29482"),
    "github.com/opencontainers/runc": ("1.1.12", "CVE-2024-21626"),
    "newtonsoft.json": ("13.0.1", "CVE-2024-21907 DoS"),
    "system.text.json": ("8.0.4", "CVE-2024-30105"),
    "microsoft.aspnetcore.app": ("8.0.0", "multiple"),
    "system.drawing.common": ("4.7.2", "CVE-2021-24112"),
    "sharpziplib": ("1.3.3", "CVE-2021-32840"),
    "log4net": ("2.0.10", "CVE-2018-1285 XXE"),
    "npgsql": ("8.0.3", "CVE-2024-32655 SQLi"),
    "bouncycastle.cryptography": ("2.2.1", "multiple"),
    "identitymodel": ("6.0.0", "outdated"),
    "microsoft.identitymodel.tokens": ("6.34.0", "CVE-2024-21319"),
    "system.identitymodel.tokens.jwt": ("6.34.0", "CVE-2024-21319"),
    "restsharp": ("112.0.0", "CVE-2024-45302"),
    "magick.net": ("13.0.0", "outdated"),
    "azure.identity": ("1.11.0", "CVE-2024-29992"),
    "microsoft.data.sqlclient": ("5.1.3", "CVE-2024-0056"),
    "system.data.sqlclient": ("4.8.6", "CVE-2024-0056"),
    "yamldotnet": ("13.0.0", "outdated"),
    "dotnetzip": ("999", "CVE-2024-48510 unmaintained"),
    "moment.js": ("2.29.4", "CVE-2022-31129"),
}

_REQ_LINE = re.compile(r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._\-]*)\s*(?P<extras>\[[^\]]*\])?\s*(?P<op>===|==|~=|!=|>=|<=|>|<|\^|~)?\s*(?P<ver>[A-Za-z0-9.*+!\-]+)?(?P<rest>.*)$")
_LOCKFILES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "bun.lockb", "bun.lock")


def _has_lockfile(ctx: FileContext) -> bool:
    parent = ctx.path.parent
    try:
        return any((parent / name).exists() for name in _LOCKFILES)
    except OSError:
        return False


def _check_known(name: str, version: str | None) -> tuple[str, str] | None:
    key = name.lower()
    entry = KNOWN_VULNERABLE.get(key)
    if entry is None or version is None:
        return None
    minimum, advisory = entry
    if version_lt(version, minimum):
        return minimum, advisory
    return None


def _requirements(rule: Rule, ctx: FileContext) -> Iterator[Hit]:
    name_l = ctx.name.lower()
    is_req = bool(re.search(r"requirements[\w.-]*\.txt$|constraints[\w.-]*\.txt$|^requirements/.*\.txt$", ctx.rel_path.lower())) or re.search(r"(?:^|/)requirements/[^/]+\.txt$", ctx.rel_path.lower()) is not None
    is_pipfile = name_l == "pipfile"
    is_pyproject = name_l == "pyproject.toml"
    is_setup = name_l in {"setup.py", "setup.cfg"}
    is_gemfile = name_l == "gemfile"
    is_composer = name_l == "composer.json"
    is_cargo = name_l == "cargo.toml"
    is_pom = name_l == "pom.xml"
    is_gradle = name_l.endswith((".gradle", ".gradle.kts"))
    is_gomod = name_l == "go.mod"
    is_csproj = name_l.endswith((".csproj", ".fsproj", ".vbproj", "packages.config", "directory.packages.props"))
    is_pubspec = name_l == "pubspec.yaml"
    if not any((is_req, is_pipfile, is_pyproject, is_setup, is_gemfile, is_composer, is_cargo, is_pom, is_gradle, is_gomod, is_csproj, is_pubspec)):
        return

    def emit(line_no: int, name: str, version: str | None, kind: str, severity: Severity, confidence: int, description: str) -> Hit:
        return Hit(line=line_no, snippet=ctx.line(line_no), severity=severity, confidence=confidence, name=kind, description=description, skip_sanitizer_check=True)

    def known(line_no: int, name: str, version: str | None) -> Iterator[Hit]:
        result = _check_known(name, version)
        if result:
            minimum, advisory = result
            yield emit(line_no, name, version, "Outdated dependency with known vulnerability", Severity.HIGH, 90,
                       f"{name} {version} is below {minimum} ({advisory}).")

    if is_req:
        for idx, raw in enumerate(ctx.lines, start=1):
            line = raw.split(" #")[0].strip()
            if not line or line.startswith(("#", "-r", "--requirement", "-c", "--constraint", "-e ", "--editable")):
                continue
            if line.startswith(("-i ", "--index-url", "--extra-index-url", "--trusted-host", "--find-links", "-f ")):
                if re.search(r"http://", line):
                    yield emit(idx, "index", None, "Insecure package index over HTTP", Severity.HIGH, 95,
                               "Packages are fetched over plaintext HTTP and can be replaced in transit.")
                if "--trusted-host" in line:
                    yield emit(idx, "index", None, "TLS verification disabled for package index", Severity.MEDIUM, 90,
                               "--trusted-host disables certificate validation for the index host.")
                continue
            if re.match(r"(?:git\+|hg\+|svn\+|bzr\+|https?://|file:)", line):
                if not re.search(r"@[A-Za-z0-9._\-/]+(?:#|$)|@v?\d|#egg=.*==", line):
                    yield emit(idx, line, None, "VCS/URL dependency not pinned to a commit or tag", Severity.MEDIUM, 85,
                               "Unpinned VCS dependencies resolve to a moving branch; pin to a commit SHA.")
                continue
            match = _REQ_LINE.match(line)
            if not match:
                continue
            name, op, ver = match.group("name"), match.group("op"), match.group("ver")
            if op is None:
                yield emit(idx, name, None, "Unpinned dependency", Severity.MEDIUM, 90,
                           f"{name} has no version specifier; builds are not reproducible and silently pick up any release.")
            elif op in {">=", ">", "~=", "<", "<=", "!=", "^", "~"}:
                yield emit(idx, name, ver, "Loosely pinned dependency", Severity.LOW, 75,
                           f"{name} uses '{op}{ver}' which allows newer, unreviewed versions.")
            elif op in {"==", "==="} and ver:
                yield from known(idx, name, ver)
        return

    if is_pipfile:
        in_packages = False
        for idx, raw in enumerate(ctx.lines, start=1):
            line = raw.strip()
            if line.startswith("["):
                in_packages = line in {"[packages]", "[dev-packages]"}
                continue
            if not in_packages or not line or line.startswith("#"):
                continue
            match = re.match(r"^\"?(?P<name>[A-Za-z0-9._\-]+)\"?\s*=\s*(?P<spec>.+)$", line)
            if not match:
                continue
            name, spec = match.group("name"), match.group("spec").strip()
            if spec in {'"*"', "'*'", "*"} or re.search(r"version\s*=\s*\"\*\"", spec):
                yield emit(idx, name, None, "Unpinned dependency", Severity.MEDIUM, 90, f"{name} = \"*\" accepts any version.")
            elif re.search(r"\"(?:>=|>|~=|<)", spec):
                yield emit(idx, name, None, "Loosely pinned dependency", Severity.LOW, 70, f"{name} uses an open range {spec}.")
            else:
                ver = re.search(r"==\s*([\w.]+)", spec)
                if ver:
                    yield from known(idx, name, ver.group(1))
        return

    if is_pyproject or is_setup:
        for idx, raw in enumerate(ctx.lines, start=1):
            line = raw.strip().rstrip(",")
            match = re.match(r"^[\"'](?P<name>[A-Za-z0-9][A-Za-z0-9._\-]*)(?:\[[^\]]*\])?\s*(?P<op>==|>=|~=|>|<|!=)?\s*(?P<ver>[\w.*]+)?[^\"']*[\"']$", line)
            if match:
                name, op, ver = match.group("name"), match.group("op"), match.group("ver")
                if name.lower() in {"python", "setuptools", "wheel", "poetry", "hatchling", "flit_core", "flit-core", "pdm-backend", "poetry-core", "setuptools-scm", "maturin"} and not op:
                    continue
                if op is None:
                    yield emit(idx, name, None, "Unpinned dependency", Severity.LOW, 70, f"{name} is declared without any version constraint.")
                elif op == "==" and ver:
                    yield from known(idx, name, ver)
                continue
            match = re.match(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._\-]*)\s*=\s*[\"'](?P<spec>[^\"']*)[\"']\s*$", line)
            if match and re.search(r"^\[tool\.poetry\.(?:dev-)?dependencies\]|^\[tool\.poetry\.group\.\w+\.dependencies\]|^\[project\.optional-dependencies\]", "\n".join(ctx.lines[max(0, idx - 40):idx]), re.M):
                name, spec = match.group("name"), match.group("spec")
                if name.lower() == "python":
                    continue
                if spec == "*":
                    yield emit(idx, name, None, "Unpinned dependency", Severity.MEDIUM, 90, f"{name} = \"*\" accepts any version.")
                elif re.match(r"^\d", spec):
                    yield from known(idx, name, spec)
                elif re.match(r"^[\^~]\d", spec):
                    yield from known(idx, name, spec[1:])
        return

    if is_gemfile:
        for idx, raw in enumerate(ctx.lines, start=1):
            line = raw.split("#")[0].strip()
            match = re.match(r"^gem\s+[\"'](?P<name>[\w\-]+)[\"']\s*(?:,\s*[\"'](?P<spec>[^\"']+)[\"'])?", line)
            if not match:
                if re.search(r"^source\s+[\"']http://", line):
                    yield emit(idx, "source", None, "Insecure gem source over HTTP", Severity.HIGH, 95, "Gems are fetched over plaintext HTTP.")
                continue
            name, spec = match.group("name"), match.group("spec")
            if spec is None:
                if re.search(r"git:|github:|path:", line) and not re.search(r"ref:|tag:", line):
                    yield emit(idx, name, None, "VCS gem not pinned to a ref", Severity.MEDIUM, 80, f"gem '{name}' tracks a moving git branch.")
                elif not re.search(r"path:", line):
                    yield emit(idx, name, None, "Unpinned dependency", Severity.LOW, 65, f"gem '{name}' has no version constraint (Gemfile.lock governs installs but upgrades are unbounded).")
            else:
                ver = re.search(r"(\d[\w.]*)", spec)
                if ver and re.match(r"^(?:=\s*)?\d", spec.strip()) or ver and spec.strip().startswith("~>"):
                    yield from known(idx, name, ver.group(1))
        return

    if is_composer:
        try:
            data = json.loads(ctx.text)
        except ValueError:
            data = {}
        for section in ("require", "require-dev"):
            deps = data.get(section, {}) if isinstance(data, dict) else {}
            if not isinstance(deps, dict):
                continue
            for name, spec in deps.items():
                if name in {"php"} or name.startswith("ext-"):
                    continue
                line_no = next((i for i, ln in enumerate(ctx.lines, start=1) if f'"{name}"' in ln), 1)
                spec_s = str(spec)
                if spec_s in {"*", "@dev", "dev-master", "dev-main", "dev-develop"} or spec_s.startswith("dev-") or spec_s.endswith("@dev"):
                    yield emit(line_no, name, None, "Unpinned dependency", Severity.MEDIUM, 90, f"{name}: \"{spec_s}\" resolves to any/development version.")
                else:
                    ver = re.search(r"(\d[\w.]*)", spec_s)
                    if ver:
                        yield from known(line_no, name, ver.group(1))
        return

    if is_cargo:
        in_deps = False
        for idx, raw in enumerate(ctx.lines, start=1):
            line = raw.strip()
            if line.startswith("["):
                in_deps = "dependencies" in line
                continue
            if not in_deps or not line or line.startswith("#"):
                continue
            match = re.match(r"^(?P<name>[\w\-]+)\s*=\s*(?P<spec>.+)$", line)
            if not match:
                continue
            name, spec = match.group("name"), match.group("spec")
            if spec.strip() in {'"*"', "'*'"} or re.search(r"version\s*=\s*\"\*\"", spec):
                yield emit(idx, name, None, "Unpinned dependency", Severity.MEDIUM, 90, f"{name} = \"*\" accepts any version.")
            elif re.search(r"git\s*=", spec) and not re.search(r"rev\s*=|tag\s*=", spec):
                yield emit(idx, name, None, "VCS crate not pinned to a rev/tag", Severity.MEDIUM, 85, f"{name} tracks a moving git branch.")
        return

    if is_pom:
        for idx, raw in enumerate(ctx.lines, start=1):
            if re.search(r"<version>\s*(?:LATEST|RELEASE|\[.*,\s*\)|\(.*\))\s*</version>", raw):
                yield emit(idx, "artifact", None, "Unpinned Maven dependency", Severity.MEDIUM, 90, "LATEST/RELEASE/open ranges resolve to arbitrary versions.")
            elif re.search(r"<url>\s*http://", raw):
                yield emit(idx, "repository", None, "Insecure Maven repository over HTTP", Severity.HIGH, 95, "Artifacts are fetched over plaintext HTTP.")
        text = ctx.text
        for match in re.finditer(r"<groupId>\s*([\w.\-]+)\s*</groupId>\s*<artifactId>\s*([\w.\-]+)\s*</artifactId>\s*(?:<[^>]+>[^<]*</[^>]+>\s*)*?<version>\s*([\w.\-]+)\s*</version>", text):
            group, artifact, version = match.groups()
            if version.startswith("$"):
                continue
            line_no = ctx.line_at_offset(match.start())
            for key in (f"{group}:{artifact}", artifact):
                result = _check_known(key, version)
                if result:
                    minimum, advisory = result
                    yield emit(line_no, key, version, "Outdated dependency with known vulnerability", Severity.HIGH, 90,
                               f"{group}:{artifact} {version} is below {minimum} ({advisory}).")
                    break
        return

    if is_gradle:
        for idx, raw in enumerate(ctx.lines, start=1):
            match = re.search(r"[\"'](?P<group>[\w.\-]+):(?P<artifact>[\w.\-]+):(?P<ver>[\w.\-+]+)[\"']", raw)
            if not match:
                if re.search(r"url\s*[= ]\s*[\"']http://", raw):
                    yield emit(idx, "repository", None, "Insecure Gradle repository over HTTP", Severity.HIGH, 95, "Artifacts are fetched over plaintext HTTP.")
                continue
            group, artifact, ver = match.group("group"), match.group("artifact"), match.group("ver")
            if ver in {"+", "latest.release", "latest.integration"} or ver.endswith(".+") or ver.endswith("+"):
                yield emit(idx, artifact, None, "Unpinned Gradle dependency", Severity.MEDIUM, 90, f"{group}:{artifact}:{ver} uses a dynamic version.")
                continue
            for key in (f"{group}:{artifact}", artifact):
                result = _check_known(key, ver)
                if result:
                    minimum, advisory = result
                    yield emit(idx, key, ver, "Outdated dependency with known vulnerability", Severity.HIGH, 90,
                               f"{group}:{artifact} {ver} is below {minimum} ({advisory}).")
                    break
        return

    if is_gomod:
        for idx, raw in enumerate(ctx.lines, start=1):
            match = re.match(r"^\s*(?P<name>[\w.\-/]+)\s+v(?P<ver>[\w.\-+]+)", raw)
            if not match or raw.strip().startswith(("module", "go ", "//")):
                continue
            name, ver = match.group("name"), match.group("ver")
            if re.search(r"-0\.\d{14}-[0-9a-f]{12}", ver) and "// indirect" not in raw:
                yield emit(idx, name, ver, "Pseudo-version (untagged commit) dependency", Severity.LOW, 60, f"{name} pins an untagged commit; prefer released versions.")
            yield from known(idx, name, ver.split("-")[0])
        return

    if is_csproj:
        for idx, raw in enumerate(ctx.lines, start=1):
            match = re.search(r"<PackageReference\s+Include\s*=\s*\"(?P<name>[\w.\-]+)\"(?:\s+Version\s*=\s*\"(?P<ver>[^\"]*)\")?|<package\s+id\s*=\s*\"(?P<name2>[\w.\-]+)\"\s+version\s*=\s*\"(?P<ver2>[^\"]*)\"|<PackageVersion\s+Include\s*=\s*\"(?P<name3>[\w.\-]+)\"\s+Version\s*=\s*\"(?P<ver3>[^\"]*)\"", raw, re.I)
            if not match:
                continue
            name = match.group("name") or match.group("name2") or match.group("name3")
            ver = match.group("ver") or match.group("ver2") or match.group("ver3")
            if ver is None or ver == "*" or ver.endswith("*") or ver.startswith("["):
                if "Directory.Packages.props" not in ctx.rel_path and ver is None and "<PackageVersion" not in raw and re.search(r"ManagePackageVersionsCentrally", "\n".join(ctx.lines[:30])) is None:
                    yield emit(idx, name, None, "Unpinned NuGet dependency", Severity.MEDIUM, 85, f"{name} uses a floating version ({ver or 'none'}).")
                elif ver and (ver == "*" or ver.endswith("*")):
                    yield emit(idx, name, None, "Unpinned NuGet dependency", Severity.MEDIUM, 85, f"{name} uses a floating version ({ver}).")
                continue
            yield from known(idx, name, ver)
        return

    if is_pubspec:
        for idx, raw in enumerate(ctx.lines, start=1):
            match = re.match(r"^\s{2}(?P<name>[\w]+):\s*(?P<spec>any|\^?[\d.]+.*)?$", raw)
            if match and (match.group("spec") or "").strip() == "any":
                yield emit(idx, match.group("name"), None, "Unpinned dependency", Severity.MEDIUM, 90, f"{match.group('name')}: any accepts every version.")


def _package_json(rule: Rule, ctx: FileContext) -> Iterator[Hit]:
    if ctx.name != "package.json":
        return
    try:
        data = json.loads(ctx.text)
    except ValueError:
        return
    if not isinstance(data, dict):
        return
    lockfile = _has_lockfile(ctx)
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            spec_s = str(spec).strip()
            line_no = next((i for i, ln in enumerate(ctx.lines, start=1) if f'"{name}"' in ln and section not in ln), 1)
            if spec_s in {"*", "latest", "", "x", "X", "next", "canary", "beta", "alpha", "dev"} or spec_s.startswith((">", "git", "github:", "http://", "file:")) and not re.search(r"#(?:semver:|[a-f0-9]{7,}|v?\d)", spec_s):
                severity = Severity.MEDIUM if section in {"dependencies", "peerDependencies"} else Severity.LOW
                yield Hit(line=line_no, snippet=ctx.line(line_no), severity=severity, confidence=90, name="Unpinned npm dependency", skip_sanitizer_check=True,
                          description=f"{name}: \"{spec_s or '(empty)'}\" resolves to an arbitrary version or moving branch.")
                continue
            if spec_s.startswith("http://"):
                yield Hit(line=line_no, snippet=ctx.line(line_no), severity=Severity.HIGH, confidence=95, name="Dependency fetched over HTTP", skip_sanitizer_check=True,
                          description=f"{name} is downloaded from a plaintext URL.")
                continue
            if spec_s.startswith(("^", "~")) and not lockfile:
                yield Hit(line=line_no, snippet=ctx.line(line_no), severity=Severity.LOW, confidence=60, name="Semver range without lockfile", skip_sanitizer_check=True,
                          description=f"{name}: \"{spec_s}\" floats and no lockfile was found next to package.json.")
            ver = re.search(r"(\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?)", spec_s)
            if ver:
                result = _check_known(name, ver.group(1))
                if result:
                    minimum, advisory = result
                    yield Hit(line=line_no, snippet=ctx.line(line_no), severity=Severity.HIGH, confidence=88, name="Outdated dependency with known vulnerability", skip_sanitizer_check=True,
                              description=f"{name} {spec_s} is below {minimum} ({advisory}).")


# --------------------------------------------------------------------------- #
# 35. subdomains
# --------------------------------------------------------------------------- #

_SUBDOMAIN = re.compile(
    r"(?:https?://|wss?://|//|@|[\s\"'`=(,])(?P<host>(?:[\w-]+\.)*?(?:(?:dev|development|devel|staging|stage|stg|test|testing|qa|uat|sandbox|sbx|preprod|pre-prod|preproduction|internal|int|intranet|corp|beta|alpha|canary|preview|demo|lab|labs|local|nightly|experimental|old|legacy|v\d-old|backup|admin|jenkins|gitlab|grafana|kibana|jira|confluence|vpn|bastion|jump|db|database|mysql|postgres|redis|rabbit|kafka|elastic|es|vault|consul|nexus|artifactory|sonar|sentry)(?:[\w-]*)\.[\w-]+\.(?:com|net|org|io|dev|app|co|cloud|internal|local|lan|corp|xyz|me|ai|tech|site|online|info|biz|us|uk|de|fr|eu|in|jp|br|ca|au)|[\w-]+[.-](?:dev|staging|stage|stg|test|qa|uat|sandbox|preprod|internal|beta|canary|preview)\.[\w-]+\.(?:com|net|org|io|dev|app|co|cloud|internal|local|lan|corp|xyz|me|ai|tech|site|online|info|biz|us|uk|de|fr|eu|in|jp|br|ca|au)))\b",
    re.I,
)


def _subdomain(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    host = match.group("host").lower()
    line = ctx.line(line_no)
    if re.search(r"example\.(?:com|org|net)|localhost|\.local$|\.lan$|test\.com$|\.test$|w3\.org|schema\.org|mozilla\.org|github\.com|npmjs|pypi|readthedocs|stackoverflow", host):
        return None
    if re.search(r"os\.environ|getenv|process\.env|\$\{|\{\{|<[^>]+>|xxx|todo|placeholder", line, re.I):
        return None
    path_l = ctx.rel_path.lower()
    doc_or_test = bool(re.search(r"readme|changelog|docs?/|\.md$|\.rst$|test|spec|fixture|mock|example|sample|\.env\.example|hosts$", path_l))
    is_config = bool(re.search(r"\.(?:env|ini|cfg|conf|toml|ya?ml|json|properties|tf|tfvars)$", path_l))
    infra = bool(re.search(r"^(?:admin|jenkins|gitlab|grafana|kibana|jira|confluence|vpn|bastion|jump|db|database|mysql|postgres|redis|rabbit|kafka|elastic|es|vault|consul|nexus|artifactory|sonar|sentry|internal|intranet|corp)[.-]", host))
    severity = Severity.MEDIUM if infra else Severity.LOW
    confidence = 80 if not doc_or_test else 45
    if is_config and re.search(r"dev|staging|stage|stg|test|qa|uat|sandbox|preprod|local", path_l) and not infra:
        confidence -= 20
    kind = "Internal infrastructure hostname" if infra else "Non-production environment hostname"
    return make_hit(ctx, line_no, column=match.start("host") + 1, severity=severity, confidence=max(25, confidence), skip_sanitizer_check=True,
                    name=f"{kind} hardcoded in source",
                    description=f"'{host}' reveals a {'management/internal system' if infra else 'staging/development environment'} that attackers can enumerate and target.")


# --------------------------------------------------------------------------- #
# 36. dns
# --------------------------------------------------------------------------- #

_DNS_CALL = re.compile(
    r"\b(?P<fn>socket\.gethostbyname(?:_ex)?|socket\.getaddrinfo|socket\.gethostbyaddr|dns\.resolver\.(?:resolve|query)|resolver\.(?:resolve|query)|dns\.(?:lookup|resolve|resolve4|resolve6|resolveAny|resolveCname|resolveMx|resolveTxt|resolveSrv|resolveNs|reverse)|dns\.promises\.(?:lookup|resolve\w*)|dnsPromises\.(?:lookup|resolve\w*)|Dns\.GetHost(?:Addresses|Entry)(?:Async)?|InetAddress\.getByName|InetAddress\.getAllByName|net\.LookupHost|net\.LookupIP|net\.LookupAddr|net\.LookupCNAME|net\.LookupMX|net\.LookupTXT|net\.LookupSRV|resolver\.LookupIPAddr|resolver\.LookupHost|gethostbyname|gethostbyname2|getaddrinfo|dns_get_record|checkdnsrr|Resolv\.getaddress(?:es)?|Resolv::DNS|Addrinfo\.getaddrinfo|Socket\.gethostbyname|Socket\.getaddrinfo|ares_gethostbyname|c-ares|Net::DNS|inet_aton\(gethostbyname|res_query|res_search|getnameinfo)\s*\(",
)
_DNS_GUARD = re.compile(
    r"want_dnssec\s*=\s*True|dnssec|\bdoh\b|\bdot\b|https://dns|dns\.google|cloudflare-dns|\bDoH\b|DNS-over|allowlist|whitelist|ALLOWED_HOSTS|ALLOWED_DOMAINS|validate_host|validateHost|"
    r"hostname\s+(?:in|not in)|host\s+(?:in|not in)|\bin\s+ALLOWED|is_private|is_global|is_loopback|is_link_local|ipaddress\.ip_address|ip_address\(|isPrivate|isLoopback|IsPrivate\(\)|IsLoopback\(\)|"
    r"private_ranges|blocked_ranges|BLOCKED_NETWORKS|re\.(?:match|fullmatch)\(|idna|punycode|\.endswith\(\s*['\"]\.|endsWith\(\s*['\"]\.|HasSuffix\(",
    re.I,
)


def _dns_resolution(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    line = ctx.line(line_no)
    if re.search(r"^\s*(?:import|from|require|#|//|\*)|test_|spec\.|describe\(|\.d\.ts", line):
        return None
    fn = match.group("fn")
    statement = ctx.statement(line_no, 4)
    args = statement[statement.find("(") + 1:]
    if re.fullmatch(r"\s*(?:'[^']*'|\"[^\"]*\")\s*(?:,.*)?", args.split("\n")[0].rstrip(")") + ")") and not re.search(r"\+|\$\{|f['\"]|\.format|%", args):
        return None
    tainted = has_input(args) or arg_tainted(ctx, line_no, args, lookback=25)
    block = lookbehind(ctx, line_no, 15) + "\n" + statement + "\n" + lookahead(ctx, line_no, 15)
    guard = _DNS_GUARD.search(block)
    rebinding = bool(re.search(r"is_private|is_global|is_loopback|ipaddress\.ip_address|ip_address\(|isPrivate|IsPrivate|IsLoopback|private_ranges|blocked_ranges|BLOCKED_NETWORKS|startswith\(\s*['\"](?:10\.|192\.168|172\.|127\.)", block, re.I)) and bool(re.search(r"requests\.(?:get|post)|urlopen|httpx\.|fetch\(|axios|http\.Get|Net::HTTP|curl|socket\.connect|net\.Dial|\.connect\(", lookahead(ctx, line_no, 25), re.I))
    if rebinding:
        return make_hit(ctx, line_no, column=match.start() + 1, severity=Severity.MEDIUM, confidence=75, skip_sanitizer_check=True,
                        name="DNS rebinding: resolved address validated then hostname reused", cwe="CWE-367",
                        description=f"{fn}() result is checked against private ranges but the subsequent connection resolves the hostname again (TOCTOU / DNS rebinding).")
    if tainted:
        return make_hit(ctx, line_no, column=match.start() + 1, severity=Severity.HIGH if not guard else Severity.MEDIUM, confidence=85 if not guard else 45,
                        mitigated_by=guard.group(0) if guard else None, skip_sanitizer_check=True,
                        name="DNS resolution of user-controlled hostname",
                        description=f"{fn}() resolves a hostname taken from request data, enabling SSRF pivoting, internal host enumeration and DNS exfiltration.")
    if guard:
        return None
    return make_hit(ctx, line_no, column=match.start() + 1, severity=Severity.LOW, confidence=55, skip_sanitizer_check=True,
                    name="Unvalidated DNS resolution",
                    description=f"{fn}() trusts DNS answers without DNSSEC validation, timeouts or result allow-listing.")


# --------------------------------------------------------------------------- #
# 37. server-config
# --------------------------------------------------------------------------- #


def _cors(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    line = ctx.line(line_no)
    if re.search(r"^\s*(?:import|from|require|#|//|\*)|test_|spec\.|describe\(", line):
        return None
    block = lookbehind(ctx, line_no, 8) + "\n" + ctx.statement(line_no, 8) + "\n" + lookahead(ctx, line_no, 8)
    credentials = re.search(r"allow_credentials\s*=\s*True|credentials\s*:\s*true|Access-Control-Allow-Credentials['\"]?\s*[:,=]\s*['\"]?true|supports_credentials\s*=\s*True|CORS_ALLOW_CREDENTIALS\s*=\s*True|AllowCredentials\s*(?:=|:)\s*true|allowCredentials\s*\(\s*true|\.AllowCredentials\(\)|Credentials\s*:\s*true|allowCredentials\s*=\s*['\"]?true", block, re.I)
    reflected = re.search(r"Access-Control-Allow-Origin['\"]?\s*[:,=\]]+\s*(?:request\.headers|req\.headers|req\.get\(\s*['\"]origin|origin\b|r\.Header\.Get\(\s*['\"]Origin|\$_SERVER\[['\"]HTTP_ORIGIN)", block, re.I)
    if reflected and not re.search(r"\bin\s+ALLOWED|ALLOWED_ORIGINS|allowlist|whitelist|origins\.includes|\.has\(\s*origin|origin\s+in\s|\bif\s+origin\s*(?:==|in)|allowed_origins", block, re.I):
        return make_hit(ctx, line_no, column=match.start() + 1, severity=Severity.HIGH, confidence=90, skip_sanitizer_check=True,
                        name="CORS origin reflected without validation",
                        description="The request Origin header is echoed back in Access-Control-Allow-Origin, which is equivalent to '*' but also works with credentials.")
    if credentials:
        return make_hit(ctx, line_no, column=match.start() + 1, severity=Severity.HIGH, confidence=92, skip_sanitizer_check=True,
                        name="CORS wildcard origin combined with credentials",
                        description="Allow-Origin '*' (or reflected) together with Allow-Credentials lets any site perform authenticated cross-origin requests.")
    guard = re.search(r"NODE_ENV\s*!==?\s*['\"]production|if\s+(?:app\.)?debug|os\.environ|getenv|process\.env|settings\.DEBUG|development", block, re.I)
    return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by=guard.group(0) if guard else None, skip_sanitizer_check=True)


# --------------------------------------------------------------------------- #
# 38. containers
# --------------------------------------------------------------------------- #

_DOCKERFILE_NAME = (r"(?:^|/)(?:Dockerfile|Containerfile)(?:[.\-][\w.\-]+)?$", r"\.dockerfile$")
_COMPOSE_NAME = (r"(?:^|/)(?:docker-)?compose[\w.\-]*\.ya?ml$", r"(?:^|/)docker-compose[\w.\-]*\.ya?ml$")


def _dockerfile(rule: Rule, ctx: FileContext) -> Iterator[Hit]:
    if not any(re.search(p, ctx.rel_path, re.I) for p in _DOCKERFILE_NAME):
        return
    lines = ctx.lines
    joined: list[tuple[int, str]] = []
    buffer = ""
    start = 0
    for idx, raw in enumerate(lines, start=1):
        stripped = raw.rstrip()
        if not buffer:
            start = idx
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        buffer += stripped
        joined.append((start, buffer))
        buffer = ""
    if buffer:
        joined.append((start, buffer))

    stages: list[tuple[int, str, str | None]] = []
    user_set_nonroot = False
    last_user_root = False
    for line_no, text in joined:
        instr = text.strip()
        if not instr or instr.startswith("#"):
            continue
        upper = instr.split(None, 1)[0].upper()
        rest = instr[len(upper):].strip() if len(instr) > len(upper) else ""
        match upper:
            case "FROM":
                match = re.match(r"(?:--platform=\S+\s+)?(?P<image>[^\s]+)(?:\s+AS\s+(?P<alias>\S+))?", rest, re.I)
                if match:
                    image = match.group("image")
                    stages.append((line_no, image, match.group("alias")))
                    if image.lower() == "scratch" or any(image == alias for _, _, alias in stages[:-1] if alias):
                        continue
                    if "@sha256:" in image:
                        continue
                    if ":" not in image.split("/")[-1] or image.endswith(":latest"):
                        yield Hit(line=line_no, snippet=lines[line_no - 1], severity=Severity.MEDIUM, confidence=95, skip_sanitizer_check=True,
                                  name="Base image not pinned (latest/no tag)", cwe="CWE-1104",
                                  description=f"FROM {image} resolves to a moving image; builds are not reproducible and can silently pull compromised layers.")
                    elif re.search(r":(?:\d+|\d+\.\d+|stable|edge|rolling|nightly|dev|master|main|current|lts|alpine|slim|bullseye|bookworm|jammy|focal)$", image, re.I):
                        yield Hit(line=line_no, snippet=lines[line_no - 1], severity=Severity.LOW, confidence=70, skip_sanitizer_check=True,
                                  name="Base image pinned to a floating tag", cwe="CWE-1104",
                                  description=f"FROM {image} uses a major/channel tag; pin to a full version or digest (@sha256:...).")
                user_set_nonroot = False
                last_user_root = False
            case "USER":
                user = rest.split(":")[0].strip().strip("'\"")
                if user in {"root", "0"}:
                    last_user_root = True
                    user_set_nonroot = False
                    yield Hit(line=line_no, snippet=lines[line_no - 1], severity=Severity.HIGH, confidence=95, skip_sanitizer_check=True,
                              name="Container explicitly runs as root", cwe="CWE-250",
                              description="USER root makes every process in the container run with uid 0; a compromise gives full container (and often host) privileges.")
                else:
                    user_set_nonroot = True
                    last_user_root = False
            case "RUN":
                if re.search(r"(?:curl|wget)\s+[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b", rest):
                    yield Hit(line=line_no, snippet=lines[line_no - 1], severity=Severity.MEDIUM, confidence=90, skip_sanitizer_check=True,
                              name="Remote script piped into shell", cwe="CWE-494",
                              description="curl|sh executes unverified remote code at build time.")
                if re.search(r"chmod\s+(?:-R\s+)?(?:777|a\+rwx|o\+w|666)\b", rest):
                    yield Hit(line=line_no, snippet=lines[line_no - 1], severity=Severity.MEDIUM, confidence=90, skip_sanitizer_check=True,
                              name="World-writable permissions set in image", cwe="CWE-732")
                if re.search(r"\bsudo\b", rest):
                    yield Hit(line=line_no, snippet=lines[line_no - 1], severity=Severity.LOW, confidence=70, skip_sanitizer_check=True,
                              name="sudo used inside container build", cwe="CWE-250",
                              description="sudo inside images hints at privilege juggling; run steps as the build user instead.")
                if re.search(r"(?:pip|pip3)\s+install\s+(?![^\n]*(?:==|-r\s|--requirement|\.\s*$|\./|/))[^\n]*\b[a-zA-Z][\w\-]+\b", rest) and not re.search(r"==|-r\s|requirements|\.\[|^\s*\.$|/", rest):
                    yield Hit(line=line_no, snippet=lines[line_no - 1], severity=Severity.LOW, confidence=65, skip_sanitizer_check=True,
                              name="Unpinned package install in image", cwe="CWE-1104",
                              description="pip install without version pins makes image builds non-reproducible.")
                if re.search(r"apt-get\s+install(?![^\n]*--no-install-recommends)", rest) and re.search(r"\b\w+=\S+", rest) is None and re.search(r"ssh|telnet|netcat|nmap|gdb|strace", rest):
                    yield Hit(line=line_no, snippet=lines[line_no - 1], severity=Severity.LOW, confidence=60, skip_sanitizer_check=True,
                              name="Debug/network tooling installed in image", cwe="CWE-1104")
                if re.search(r"--insecure|-k\s|--no-check-certificate|PIP_TRUSTED_HOST|--trusted-host|NODE_TLS_REJECT_UNAUTHORIZED=0|GIT_SSL_NO_VERIFY", rest):
                    yield Hit(line=line_no, snippet=lines[line_no - 1], severity=Severity.MEDIUM, confidence=90, skip_sanitizer_check=True,
                              name="TLS verification disabled during build", cwe="CWE-295")
            case "ENV" | "ARG":
                match = re.match(r"(?P<key>[\w.\-]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIAL)[\w.\-]*)\s*=?\s*[\"']?(?P<value>[^\"'\s]{6,})", rest, re.I)
                if match and not re.match(r"^(?:\$|\{|<|\"?\"?$)", match.group("value")) and not re.search(r"example|changeme|placeholder|xxx|\*{3}|your[_-]|dummy|_FILE$|_PATH$", match.group("value") + match.group("key"), re.I):
                    yield Hit(line=line_no, snippet=lines[line_no - 1], severity=Severity.HIGH, confidence=88, skip_sanitizer_check=True,
                              name=f"Secret baked into image via {upper}", cwe="CWE-798",
                              description=f"{upper} {match.group('key')} embeds a credential in image layers/history where anyone with pull access can read it.")
            case "ADD":
                if re.search(r"\bhttps?://", rest):
                    yield Hit(line=line_no, snippet=lines[line_no - 1], severity=Severity.LOW, confidence=80, skip_sanitizer_check=True,
                              name="ADD from remote URL", cwe="CWE-494",
                              description="ADD <url> fetches unverified content; use RUN curl with checksum verification or COPY.")
            case "EXPOSE":
                if re.search(r"\b(?:22|23|2375|2376|3389|5900)\b", rest):
                    yield Hit(line=line_no, snippet=lines[line_no - 1], severity=Severity.MEDIUM, confidence=80, skip_sanitizer_check=True,
                              name="Management port exposed from container", cwe="CWE-284",
                              description=f"EXPOSE {rest} publishes SSH/Docker/RDP/VNC style management ports.")
            case "COPY":
                if re.search(r"(?:^|\s)\.env(?:\s|$)|id_rsa|\.pem\b|\.aws/|credentials", rest):
                    yield Hit(line=line_no, snippet=lines[line_no - 1], severity=Severity.HIGH, confidence=85, skip_sanitizer_check=True,
                              name="Secret file copied into image", cwe="CWE-538")
            case "HEALTHCHECK":
                pass
    if stages and not user_set_nonroot and not last_user_root:
        final_from_line = stages[-1][0]
        yield Hit(line=final_from_line, snippet=lines[final_from_line - 1], severity=Severity.MEDIUM, confidence=85, skip_sanitizer_check=True,
                  name="Container runs as root (no USER instruction)", cwe="CWE-250",
                  description="No non-root USER is set in the final stage, so the entrypoint runs as uid 0 by default.")


_K8S_OR_COMPOSE = re.compile(
    r"^\s*(?:-\s*)?(?:privileged\s*:\s*true|user\s*:\s*['\"]?(?:root|0)(?::\d+)?['\"]?\s*$|network_mode\s*:\s*['\"]?host|pid\s*:\s*['\"]?host|ipc\s*:\s*['\"]?host|"
    r"hostNetwork\s*:\s*true|hostPID\s*:\s*true|hostIPC\s*:\s*true|runAsUser\s*:\s*0\b|runAsNonRoot\s*:\s*false|allowPrivilegeEscalation\s*:\s*true|readOnlyRootFilesystem\s*:\s*false|"
    r"-\s*/var/run/docker\.sock|/var/run/docker\.sock:|-\s*(?:SYS_ADMIN|ALL|NET_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH)\s*$|cap_add\s*:\s*\[\s*['\"]?(?:SYS_ADMIN|ALL)|"
    r"seccomp\s*:\s*unconfined|apparmor\s*:\s*unconfined|security_opt\s*:\s*\[\s*['\"]?(?:seccomp|apparmor)[:=]unconfined|hostPath\s*:|automountServiceAccountToken\s*:\s*true|"
    r"image\s*:\s*['\"]?[\w./\-]+(?::latest)?['\"]?\s*$|imagePullPolicy\s*:\s*Always\s*$|"
    r"(?:MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|MYSQL_PASSWORD|REDIS_PASSWORD|RABBITMQ_DEFAULT_PASS|MONGO_INITDB_ROOT_PASSWORD|GF_SECURITY_ADMIN_PASSWORD|MINIO_ROOT_PASSWORD|ELASTIC_PASSWORD|KEYCLOAK_ADMIN_PASSWORD|DB_PASSWORD|SECRET_KEY|API_KEY|JWT_SECRET)\s*[:=]\s*['\"]?(?!\$)[^\s'\"]{4,}|"
    r"MYSQL_ALLOW_EMPTY_PASSWORD\s*[:=]\s*['\"]?(?:yes|true|1)|POSTGRES_HOST_AUTH_METHOD\s*[:=]\s*['\"]?trust|ALLOW_EMPTY_PASSWORD\s*[:=]\s*['\"]?yes|"
    r"ports\s*:\s*$|-\s*['\"]?(?:0\.0\.0\.0:)?(?:2375|2376|22|3306|5432|6379|27017|9200|5601|15672|8080|9090|3000)\s*:\s*\d+['\"]?\s*$)",
    re.I,
)


def _compose_k8s(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    rel = ctx.rel_path
    text_head = "\n".join(ctx.lines[:60])
    is_compose = any(re.search(p, rel, re.I) for p in _COMPOSE_NAME) or re.search(r"^\s*services\s*:\s*$", ctx.text, re.M) is not None
    is_k8s = bool(re.search(r"^\s*kind\s*:\s*(?:Pod|Deployment|DaemonSet|StatefulSet|Job|CronJob|ReplicaSet|ReplicationController)\b|^\s*apiVersion\s*:", text_head, re.M)) or re.search(r"(?:^|/)(?:k8s|kubernetes|manifests?|helm|charts?|templates|deploy(?:ment)?s?)/", rel, re.I) is not None
    if not (is_compose or is_k8s):
        return None
    line = ctx.line(line_no).strip()
    low = line.lower()
    if low.startswith("ports:"):
        return None
    if re.search(r"^\s*(?:-\s*)?image\s*:", line, re.I):
        image = re.sub(r"^\s*(?:-\s*)?image\s*:\s*", "", line).strip("'\" ")
        if "@sha256:" in image or "${" in image or "{{" in image:
            return None
        if ":" in image.split("/")[-1] and not image.endswith(":latest"):
            return None
        return make_hit(ctx, line_no, column=match.start() + 1, severity=Severity.MEDIUM, confidence=90, skip_sanitizer_check=True,
                        name="Container image not pinned (latest/no tag)", cwe="CWE-1104",
                        description=f"image: {image} resolves to a moving tag.")
    if re.search(r"imagePullPolicy", line):
        return None
    if re.search(r"^\s*-\s*['\"]?(?:0\.0\.0\.0:)?(?:2375|2376|22|3306|5432|6379|27017|9200|5601|15672|8080|9090|3000)\s*:", line):
        if not re.search(r"^\s*-\s*['\"]?(?:0\.0\.0\.0:)?(?:2375|2376|3306|5432|6379|27017|9200|15672)\s*:", line):
            return None
        if re.search(r"127\.0\.0\.1:", line):
            return None
        return make_hit(ctx, line_no, column=match.start() + 1, severity=Severity.MEDIUM, confidence=75, skip_sanitizer_check=True,
                        name="Datastore/management port published on all interfaces", cwe="CWE-284",
                        description="Publishing database/broker/Docker API ports without a host binding exposes them beyond the compose network.")
    if re.search(r"PASSWORD|SECRET|API_KEY|JWT", line, re.I) and re.search(r"[:=]", line):
        if re.search(r"\$\{|\$\w|\{\{|secretKeyRef|valueFrom|_FILE|/run/secrets", line):
            return None
        value = re.split(r"[:=]", line, maxsplit=1)[1].strip().strip("'\"")
        if re.search(r"example|changeme|placeholder|xxx|\*{3}|your[_-]|dummy|password$|secret$", value, re.I) and len(value) < 12:
            return make_hit(ctx, line_no, column=match.start() + 1, severity=Severity.MEDIUM, confidence=70, skip_sanitizer_check=True,
                            name="Default/weak credential in container configuration", cwe="CWE-1392",
                            description=f"Service credential is set to a well-known default ('{value}').")
        return make_hit(ctx, line_no, column=match.start() + 1, severity=Severity.HIGH, confidence=85, skip_sanitizer_check=True,
                        name="Plaintext credential in container configuration", cwe="CWE-798",
                        description="Service credential is written literally in the manifest instead of a secret reference.")
    if re.search(r"ALLOW_EMPTY_PASSWORD|HOST_AUTH_METHOD", line, re.I):
        return make_hit(ctx, line_no, column=match.start() + 1, severity=Severity.HIGH, confidence=95, skip_sanitizer_check=True,
                        name="Datastore started without authentication", cwe="CWE-306")
    if re.search(r"hostPath\s*:", line):
        following = lookahead(ctx, line_no, 3)
        if not re.search(r"path\s*:\s*/(?:var/run/docker\.sock|etc|root|home|var/lib|proc|sys|dev)\b|path\s*:\s*/\s*$", following):
            return None
        return make_hit(ctx, line_no, column=match.start() + 1, severity=Severity.HIGH, confidence=85, skip_sanitizer_check=True,
                        name="Sensitive host path mounted into pod", cwe="CWE-668")
    severity = Severity.HIGH if re.search(r"privileged|docker\.sock|SYS_ADMIN|\bALL\b|host(?:Network|PID|IPC)|network_mode|pid\s*:|ipc\s*:|unconfined|allowPrivilegeEscalation", line, re.I) else Severity.MEDIUM
    return make_hit(ctx, line_no, column=match.start() + 1, severity=severity, skip_sanitizer_check=True,
                    name="Insecure container runtime setting", cwe="CWE-250",
                    description=f"'{line}' weakens container isolation (privileged mode, host namespaces, root user, dangerous capabilities or missing pull-policy pinning).")


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

RULES: tuple[Rule, ...] = (
    # ---- 23. cloud-storage ----------------------------------------------- #
    Rule(
        id="CS-001",
        surface="cloud-storage",
        name="Public object storage ACL",
        description="A bucket/object is configured with a public-read or public-read-write ACL.",
        severity=Severity.HIGH,
        cwe="CWE-732",
        confidence=92,
        extensions=IAC_EXTS + (".cs", ".java", ".php", ".kt"),
        keywords=("public-read", "publicread", "public_read", "authenticated-read", "allusers", "allauthenticatedusers", "public_access", "container_access_type", "allow_blob_public_access", "public_network_access", "uniform_bucket_level_access", "blockpublic", "block_public", "ignore_public", "restrict_public", "predefinedacl", "predefined_acl"),
        patterns=(
            r"(?:ACL|acl|Acl|x-amz-acl|CannedACL|canned_acl|predefinedAcl|predefined_acl|PredefinedAcl|default_acl|object_acl|bucket_acl)['\"]?\s*[:=]\s*['\"]?(?:public-read(?:-write)?|PublicRead(?:Write)?|authenticated-read|AuthenticatedRead|bucket-owner-full-control\s*['\"]?\s*,\s*['\"]?public)",
            r"['\"](?:public-read(?:-write)?|PublicReadWrite)['\"]",
            r"(?:block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets|BlockPublicAcls|BlockPublicPolicy|IgnorePublicAcls|RestrictPublicBuckets)['\"]?\s*[:=]\s*(?:false|False|FALSE)\b",
            r"\ballUsers\b|\ballAuthenticatedUsers\b",
            r"(?:container_access_type|containerAccessType|PublicAccess|public_access)\s*[:=]\s*['\"]?(?:blob|container|Blob|Container)['\"]?",
            r"(?:allow_blob_public_access|allowBlobPublicAccess|AllowBlobPublicAccess|public_network_access_enabled)\s*[:=]\s*(?:true|True)\b",
            r"uniform_bucket_level_access\s*=\s*false",
            r"(?:acl|ACL)\s*=\s*['\"]?public",
            r"make_public\s*\(|makePublic\s*\(|\.public\s*=\s*true|public\s*:\s*true\s*[,}]\s*(?://.*)?$",
            r"website\s*\{|s3_bucket_website_configuration|WebsiteConfiguration",
        ),
        negatives=(r"^\s*(?:#|//|\*)", r"private|Deny|BlockPublic\w*\s*[:=]\s*true|block_public_\w+\s*=\s*true|test_|spec\.", r"public\s*:\s*true.*(?:route|page|endpoint|api|url|path|view|static|assets|cdn)"),
        sanitizers=(r"\bCondition\b", r"aws:SourceArn", r"aws:SourceVpce", r"aws:Referer", r"aws:SecureTransport", r"CloudFront", r"OriginAccessIdentity", r"origin_access", r"private", r"BlockPublicAcls\s*[:=]\s*true", r"block_public_acls\s*=\s*true", r"website"),
        context_before=6,
        context_after=6,
        recommendation="Keep buckets private with public-access blocks enabled; serve public assets through a CDN with an origin access identity.",
        remediation="acl = \"private\" + aws_s3_bucket_public_access_block { block_public_acls = true ... } (or CloudFront OAC in front of the bucket).",
    ),
    Rule(
        id="CS-002",
        surface="cloud-storage",
        name="Storage policy grants access to any principal",
        description="An IAM/bucket policy statement allows actions for Principal '*' without restricting conditions.",
        severity=Severity.HIGH,
        cwe="CWE-284",
        confidence=90,
        extensions=IAC_EXTS + (".cs", ".java", ".php", ".kt"),
        keywords=("principal", "\"aws\": \"*\"", "principals"),
        patterns=(
            r"[\"']?Principal[\"']?\s*[:=]\s*[\"']\*[\"']",
            r"[\"']?Principal[\"']?\s*[:=]\s*\{\s*[\"']?AWS[\"']?\s*[:=]\s*(?:\[\s*)?[\"']\*[\"']",
            r"principals\s*\{[^}]*identifiers\s*=\s*\[\s*\"\*\"",
            r"identifiers\s*=\s*\[\s*\"\*\"\s*\]",
            r"Principal\s*:\s*['\"]\*['\"]",
            r"\"(?:Principal|principal)\"\s*:\s*\"\*\"",
            r"AnyPrincipal\(\)|new\s+iam\.AnyPrincipal|StarPrincipal|iam\.StarPrincipal",
            r"member\s*=\s*[\"']allUsers[\"']|members\s*=\s*\[[^\]]*[\"']allUsers[\"']",
        ),
        negatives=(r"^\s*(?:#|//|\*)", r"test_|spec\."),
        checker=_public_principal,
        recommendation="Restrict principals to specific accounts/roles and add Conditions (aws:SourceArn, aws:SourceVpce).",
        remediation="\"Principal\": {\"AWS\": \"arn:aws:iam::123456789012:role/app\"} — remove wildcards unless the bucket is intentionally public and read-only.",
    ),
    Rule(
        id="CS-003",
        surface="cloud-storage",
        name="Object storage without encryption, versioning or logging",
        description="Bucket resources are declared with server-side encryption, versioning or access logging explicitly disabled.",
        severity=Severity.MEDIUM,
        cwe="CWE-311",
        confidence=85,
        extensions=(".tf", ".hcl", ".json", ".yaml", ".yml", ".py", ".ts", ".js", ".bicep"),
        keywords=("versioning", "encryption", "sse", "logging", "kms", "bucketencryption", "force_destroy", "enable_https_traffic_only", "https_only", "public"),
        patterns=(
            r"versioning\s*\{\s*enabled\s*=\s*false|versioning_configuration\s*\{\s*status\s*=\s*\"(?:Disabled|Suspended)\"|versioned\s*:\s*false",
            r"server_side_encryption_configuration\s*=\s*null|encryption\s*:\s*(?:s3\.BucketEncryption\.UNENCRYPTED|BucketEncryption\.UNENCRYPTED|\"none\"|none)",
            r"(?:enable_https_traffic_only|https_only|enforce_ssl|enforceSSL|supportsHttpsTrafficOnly)\s*[:=]\s*(?:false|False)\b",
            r"(?:min_tls_version|minimum_tls_version|minimumTlsVersion)\s*[:=]\s*['\"]?TLS1_[01]\b",
            r"force_destroy\s*=\s*true",
            r"(?:logging|access_logs?|server_access_logging)\s*[:=]\s*(?:null|false|\{\s*enabled\s*=\s*false)",
            r"sse_algorithm\s*=\s*\"AES256\"\s*(?:#.*)?$(?![\s\S]*kms)",
            r"block_public_access\s*:\s*(?:s3\.BlockPublicAccess\.BLOCK_ACLS|BlockPublicAccess\.BLOCK_ACLS)\b",
        ),
        negatives=(r"^\s*(?:#|//|\*)",),
        use_surface_indicators=False,
        recommendation="Enable SSE-KMS encryption, versioning, TLS-only policies and access logging on every bucket.",
        remediation="aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = \"aws:kms\"; versioning_configuration { status = \"Enabled\" }; bucket policy denying aws:SecureTransport=false.",
    ),
    # ---- 25. cache-services ---------------------------------------------- #
    Rule(
        id="CACHE-001",
        surface="cache-services",
        name="Cache key set without expiry or with plaintext sensitive data",
        description="Values are written to Redis/Memcached with no TTL (unbounded growth, stale secrets) or contain sensitive data that is not encrypted/hashed.",
        severity=Severity.MEDIUM,
        cwe="CWE-312",
        confidence=75,
        extensions=CODE_EXTS,
        keywords=(".set(", ".hset(", ".hmset(", ".mset(", ".lpush(", ".rpush(", ".sadd(", ".setnx(", ".add(", ".replace(", ".append("),
        patterns=(_CACHE_SET,),
        negatives=(r"^\s*(?:import|from|require|#|//|\*)",),
        checker=_cache_set,
        recommendation="Always set a TTL (ex=/setex/expire) and never cache credentials, tokens or card data in plaintext.",
        remediation="redis.set(key, value, ex=300); for session/token material store only a hash (sha256) or an encrypted blob.",
    ),
    Rule(
        id="CACHE-002",
        surface="cache-services",
        name="Cache service connection without authentication or TLS",
        description="Redis/Memcached client connects to a remote host without a password/ACL or encrypted transport.",
        severity=Severity.MEDIUM,
        cwe="CWE-319",
        confidence=80,
        extensions=CODE_EXTS + CONFIG_EXTS,
        keywords=("redis", "memcache", "memcached", "createclient", "strictredis", "redis://", "ioredis", "pymemcache", "bmemcached"),
        patterns=(
            r"\b(?:redis\.(?:Redis|StrictRedis|from_url|asyncio\.Redis|asyncio\.from_url)|Redis\.from_url|StrictRedis|aioredis\.(?:from_url|create_redis_pool)|createClient|new\s+Redis|new\s+IORedis|redis\.createClient|redis\.NewClient|redis\.NewUniversalClient|Redis::new|Redis\.new|new\s+Predis\\Client|RedisClient\.Create|ConnectionMultiplexer\.Connect|Jedis\(|JedisPool\(|LettuceConnectionFactory|memcache\.Client|pymemcache\.(?:Client|client\.base\.Client|client\.hash\.HashClient)|bmemcached\.Client|new\s+Memcached|Memcached\(|MemcachedClient\()\s*\(",
            r"\bredis://(?!:)[^@\s'\"]+(?::\d+)?(?:/\d+)?['\"]?",
            r"(?:REDIS|MEMCACHED|CACHE)_(?:URL|HOST|SERVERS?)\s*[:=]\s*['\"]?(?:redis://)?(?!localhost|127\.0\.0\.1|\$|\{)[\w.\-]+(?::\d+)?",
            r"(?:REDIS|CACHE)_(?:PASSWORD|AUTH)\s*[:=]\s*['\"]?\s*$",
            r"requirepass\s*['\"]?\s*$|protected-mode\s+no|^\s*bind\s+0\.0\.0\.0",
        ),
        negatives=(r"^\s*(?:import|from|require|#|//|\*)", r"rediss://|ssl\s*=\s*True|tls\s*:|password\s*[=:]|:\S+@|auth\s*[=:]|requirepass\s+\S+"),
        checker=_cache_connection,
        recommendation="Require authentication (ACL user/password) and TLS (rediss://) for cache connections; never expose caches on public interfaces.",
        remediation="redis.Redis.from_url('rediss://:password@cache.internal:6380/0') with protected-mode yes and bind to private addresses.",
    ),
    # ---- 26. message-queues ---------------------------------------------- #
    Rule(
        id="MQ-001",
        surface="message-queues",
        name="Insecure deserialization of message/payload data",
        description="pickle/marshal/yaml.load/unserialize/ObjectInputStream style deserialisers are applied to queue messages or other untrusted payloads.",
        severity=Severity.CRITICAL,
        cwe="CWE-502",
        confidence=90,
        extensions=CODE_EXTS,
        keywords=("pickle", "marshal", "shelve", "dill", "jsonpickle", "yaml.load", "yaml.unsafe_load", "unserialize", "marshal.load", "yaml.load", "psych", "objectinputstream", "readobject", "xmldecoder", "xstream", "deserialize", "binaryformatter", "losformatter", "netdatacontract", "soapformatter", "typenamehandling", "node-serialize", "v8.deserialize", "gob.newdecoder", "msgpack", "typeresolver"),
        patterns=(_DESER,),
        checker=_deserialize,
        recommendation="Use JSON/Protobuf/MessagePack (raw) schemas for queue payloads; if native serialisation is unavoidable, sign payloads (HMAC) and restrict allowed classes.",
        remediation="body = json.loads(message.body); CELERY: accept_content = ['json'], task_serializer = 'json'.",
    ),
    Rule(
        id="MQ-002",
        surface="message-queues",
        name="Message broker/worker configured with insecure serializer or transport",
        description="Celery/Kombu/RQ/Sidekiq settings accept pickle payloads, or brokers are reached without authentication/TLS.",
        severity=Severity.HIGH,
        cwe="CWE-502",
        confidence=90,
        extensions=CODE_EXTS + CONFIG_EXTS,
        keywords=("accept_content", "task_serializer", "result_serializer", "event_serializer", "serializer", "pickle", "broker_url", "amqp://", "kafka", "sasl", "security_protocol", "ssl", "verify_ssl", "broker_use_ssl", "cert_reqs"),
        patterns=(
            r"(?:CELERY_)?(?:accept_content|ACCEPT_CONTENT)\s*[:=]\s*\[[^\]]*['\"]pickle['\"]",
            r"(?:CELERY_)?(?:task_serializer|TASK_SERIALIZER|result_serializer|RESULT_SERIALIZER|event_serializer|EVENT_SERIALIZER)\s*[:=]\s*['\"](?:pickle|yaml|msgpack)['\"]",
            r"serializer\s*[:=]\s*['\"]pickle['\"]",
            r"\bamqps?://(?!:)[^@\s'\"]+(?::\d+)?(?:/[^\s'\"]*)?['\"]?\s*$",
            r"(?:BROKER_URL|broker_url|CELERY_BROKER_URL)\s*[:=]\s*['\"](?:amqp|redis)://(?![^@\s'\"]*@)(?!localhost|127\.0\.0\.1|\$|\{)",
            r"broker_use_ssl\s*[:=]\s*(?:False|false|None)",
            r"security_protocol\s*[:=]\s*['\"]PLAINTEXT['\"]",
            r"sasl_mechanism\s*[:=]\s*['\"]PLAIN['\"](?![\s\S]{0,200}security_protocol\s*[:=]\s*['\"]SASL_SSL)",
            r"ssl_check_hostname\s*[:=]\s*(?:False|false)|ssl_cert_reqs\s*[:=]\s*(?:ssl\.)?CERT_NONE|verify_ssl\s*[:=]\s*(?:False|false)",
            r"(?:sqs|sns)\.(?:create_queue|create_topic)\([^)]*Policy[^)]*\"\*\"",
            r"rabbitmq_default_user\s*[:=]\s*['\"]?guest|RABBITMQ_DEFAULT_USER\s*[:=]\s*['\"]?guest|loopback_users\s*=\s*none",
            r"Redis\.new\([^)]*\)\s*$|Sidekiq\.configure_\w+\s*do\s*\|\w+\|\s*$",
        ),
        negatives=(r"^\s*(?:import|from|require|#|//|\*)", r"os\.environ|getenv|process\.env|\$\{|\{\{|accept_content\s*[:=]\s*\[\s*['\"]json['\"]\s*\]"),
        sanitizers=(r"amqps://", r"rediss://", r"broker_use_ssl\s*=\s*\{", r"ssl\s*=\s*True", r"SASL_SSL", r"cert_reqs\s*=\s*ssl\.CERT_REQUIRED", r"\bhmac\b", r"signature"),
        context_before=4,
        context_after=4,
        recommendation="Accept only JSON payloads, use TLS + authenticated broker connections and avoid default broker accounts.",
        remediation="accept_content = ['json']; broker_url = 'amqps://user:pass@broker:5671//'; security_protocol = 'SASL_SSL'.",
    ),
    # ---- 27. logging ------------------------------------------------------ #
    Rule(
        id="LOG-001",
        surface="logging",
        name="Sensitive data or PII written to logs",
        description="Passwords, tokens, card data, session identifiers or personal data are interpolated into log/print output.",
        severity=Severity.HIGH,
        cwe="CWE-532",
        confidence=80,
        extensions=CODE_EXTS + (".sh", ".ps1"),
        keywords=("log", "print", "echo", "puts", "console", "fmt.", "system.out", "system.err", "nslog", "var_dump", "print_r", "error_log", "winston", "pino", "bunyan", "serilog", "timber", "trace", "debug", "info", "warn", "error"),
        patterns=(_LOG_CALL,),
        negatives=(r"^\s*(?:import|from|require|#|//|\*)", r"\.d\.ts"),
        checker=_log_sensitive,
        recommendation="Never log credentials or full PII; log identifiers and redact/mask sensitive fields with a logging filter.",
        remediation="logger.info('login attempt user_id=%s', user.id)  # not the password/email; add a redaction filter for token/secret keys.",
    ),
    Rule(
        id="LOG-002",
        surface="logging",
        name="Insecure logging configuration",
        description="Logging is configured in ways that leak data or lose evidence: DEBUG level in production, request bodies/headers dumped, world-readable log files, disabled audit logs, log injection from user input.",
        severity=Severity.MEDIUM,
        cwe="CWE-532",
        confidence=80,
        extensions=CODE_EXTS + CONFIG_EXTS,
        keywords=("level", "log_level", "loglevel", "logging", "debug", "chmod", "0777", "0666", "audit", "log_request_body", "logrequestbody", "log_headers", "trace", "logger", "syslog", "http://"),
        patterns=(
            r"(?:LOG_LEVEL|LOGLEVEL|log_level|logLevel|logging\.level(?:\.\w+)?|level)\s*[:=]\s*['\"]?(?:DEBUG|TRACE|debug|trace|ALL|all|verbose|silly)['\"]?\s*(?:#.*|//.*)?$",
            r"(?:setLevel|set_level|basicConfig)\s*\([^)]*(?:logging\.)?(?:DEBUG|NOTSET)\b",
            r"log_request_body\s*[:=]\s*(?:true|True)|logRequestBody\s*[:=]\s*true|log_headers\s*[:=]\s*(?:true|True)|dump_headers\s*[:=]\s*true|(?:LOG|log)_REQUESTS?_BODY\s*[:=]\s*(?:true|1)",
            r"morgan\s*\(\s*['\"](?:combined|dev)['\"][^)]*\{[^}]*(?:req\.body|request\.body)",
            r"(?:audit|AUDIT)_?(?:log|LOG|logging|LOGGING|enabled|ENABLED)\s*[:=]\s*(?:false|False|0|off|disabled)\b",
            r"chmod\s+(?:-R\s+)?(?:777|666|o\+r|a\+r)\s+[^\n]*\.log\b|(?:os\.chmod|chmod)\s*\([^)]*\.log[^)]*0o?(?:777|666|644)",
            r"(?:filename|file|path)\s*[:=]\s*['\"](?:\.?/)?(?:public|static|www|htdocs|wwwroot)/[^'\"]*\.log['\"]",
            r"logger?\.\w+\s*\(\s*(?:f['\"][^'\"]*\{(?:request\.(?:args|form|headers|json|data)|req\.(?:query|body|headers|params))[^}]*\}|['\"][^'\"]*['\"]\s*(?:%|\+)\s*(?:request\.(?:args|form|headers|json|data)|req\.(?:query|body|headers|params)|\$_(?:GET|POST|REQUEST))|(?:request\.(?:args|form|headers|json|data)|req\.(?:query|body|headers|params)|\$_(?:GET|POST|REQUEST))\s*[,)])",
            r"(?:syslog|SyslogHandler|syslog_server|LOGSTASH_HOST|logstash|fluentd|remote_log|papertrail|splunk|datadog)[\w.]*\s*[:=(]\s*['\"]?(?:udp|http)://",
            r"handlers\.SysLogHandler\s*\(\s*address\s*=\s*\([^)]*\)\s*,\s*socktype\s*=\s*socket\.SOCK_DGRAM",
            r"disable_existing_loggers\s*[:=]\s*(?:True|true)",
            r"(?:logging|log)\.(?:disable|off)\s*\(|LOG_DISABLED\s*[:=]\s*(?:true|True|1)",
        ),
        negatives=(r"^\s*(?:import|from|require|#|//|\*)", r"os\.environ|getenv|process\.env|\$\{|\{\{|if\s+.*(?:debug|dev|test)|test_|spec\.|LOG_LEVEL\s*[:=]\s*os", r"\.example|\.sample|local|dev\.|development"),
        use_surface_indicators=False,
        recommendation="Run INFO/WARN in production, never dump request bodies/headers, protect log files (0640) and keep audit logs enabled; ship logs over TLS.",
        remediation="LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO'); disable body logging middleware in production; use rsyslog/TLS or HTTPS log shippers.",
    ),
    # ---- 32. dependencies ------------------------------------------------- #
    Rule(
        id="DEP-001",
        surface="dependencies",
        name="Unpinned, loosely pinned or vulnerable dependency",
        description="Dependency manifests declare packages without exact versions, from moving VCS refs, insecure indexes, or at versions with known vulnerabilities.",
        severity=Severity.MEDIUM,
        cwe="CWE-1104",
        confidence=85,
        filename_patterns=(r"(?:^|/)requirements[\w.\-]*\.txt$", r"(?:^|/)requirements/[^/]+\.txt$", r"(?:^|/)constraints[\w.\-]*\.txt$", r"(?:^|/)Pipfile$",
                           r"(?:^|/)pyproject\.toml$", r"(?:^|/)setup\.(?:py|cfg)$", r"(?:^|/)Gemfile$", r"(?:^|/)composer\.json$", r"(?:^|/)Cargo\.toml$",
                           r"(?:^|/)pom\.xml$", r"(?:^|/)build\.gradle(?:\.kts)?$", r"(?:^|/)go\.mod$", r"(?:^|/)[\w.\-]+\.(?:csproj|fsproj|vbproj)$",
                           r"(?:^|/)packages\.config$", r"(?:^|/)Directory\.Packages\.props$", r"(?:^|/)pubspec\.yaml$"),
        file_checker=_requirements,
        recommendation="Pin exact versions (or use lockfiles), pin VCS refs to commits, use HTTPS indexes and upgrade vulnerable packages.",
        remediation="requests==2.32.3 in requirements.txt; use pip-compile/poetry.lock; run pip-audit / npm audit / osv-scanner in CI.",
    ),
    Rule(
        id="DEP-002",
        surface="dependencies",
        name="Unpinned or vulnerable npm dependency",
        description="package.json declares wildcard/latest/git dependencies, plaintext download URLs, or versions below known-fixed releases.",
        severity=Severity.MEDIUM,
        cwe="CWE-1104",
        confidence=88,
        filename_patterns=(r"(?:^|/)package\.json$",),
        file_checker=_package_json,
        recommendation="Commit a lockfile, avoid '*'/'latest'/branch references and keep dependencies current (npm audit, Dependabot/Renovate).",
        remediation="\"lodash\": \"4.17.21\" with package-lock.json committed; npm ci in CI.",
    ),
    Rule(
        id="DEP-003",
        surface="dependencies",
        name="Insecure package manager configuration",
        description="Registry/index settings disable TLS verification, use HTTP mirrors, run arbitrary install scripts or trust unsigned packages.",
        severity=Severity.HIGH,
        cwe="CWE-494",
        confidence=90,
        extensions=(".npmrc", ".yarnrc", ".yml", ".yaml", ".toml", ".cfg", ".conf", ".ini", ".sh", ".txt", ".json"),
        filename_patterns=(r"(?:^|/)\.npmrc$", r"(?:^|/)\.yarnrc(?:\.yml)?$", r"(?:^|/)pip\.conf$", r"(?:^|/)pip\.ini$", r"(?:^|/)\.pip/pip\.conf$", r"(?:^|/)\.condarc$",
                           r"(?:^|/)\.gemrc$", r"(?:^|/)\.cargo/config(?:\.toml)?$", r"(?:^|/)nuget\.config$", r"(?:^|/)NuGet\.Config$", r"(?:^|/)\.bundle/config$", r"(?:^|/)composer\.json$", r"(?:^|/)\.pypirc$"),
        keywords=("strict-ssl", "registry", "index-url", "trusted-host", "ssl_verify", "verify_ssl", "unsafe-perm", "ignore-scripts", "allow_untrusted", "http://", "insecure", "secure-protocol", "cafile", "noproxy", "npm_config"),
        patterns=(
            r"strict-ssl\s*=\s*false|strictSSL\s*[:=]\s*false|npm_config_strict_ssl\s*=\s*false",
            r"(?:registry|index-url|extra-index-url|source|url|repository|repositories\.\w+\.url|feed|mirror|channel)\s*[:=]\s*['\"]?http://(?!localhost|127\.0\.0\.1)",
            r"trusted-host\s*=|--trusted-host",
            r"(?:ssl_verify|verify_ssl|ssl-verify|ssl_verify_peer|sslverify)\s*[:=]\s*(?:false|False|no|0)\b",
            r"unsafe-perm\s*=\s*true",
            r"(?:allow_untrusted|allow-untrusted|allow_insecure|allow-insecure|insecure)\s*[:=]\s*(?:true|1)\b",
            r"\"?secure-http\"?\s*:\s*false",
            r"BUNDLE_SSL_VERIFY_MODE\s*[:=]\s*['\"]?0",
            r"<add\s+key\s*=\s*\"[^\"]*\"\s+value\s*=\s*\"http://",
            r"always-auth\s*=\s*true\s*$(?![\s\S]*_authToken)",
            r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0",
            r"pip\s+install\s+[^\n]*--(?:trusted-host|index-url\s+http://|no-verify)",
            r"npm\s+(?:install|i|ci)\s+[^\n]*--(?:unsafe-perm|no-strict-ssl)",
        ),
        negatives=(r"^\s*(?:#|//|;)",),
        use_surface_indicators=False,
        recommendation="Fetch packages only over verified HTTPS, keep strict-ssl on and avoid unsafe-perm/untrusted flags.",
        remediation="registry=https://registry.npmjs.org/ ; strict-ssl=true ; remove --trusted-host and use an internal HTTPS mirror with a proper CA.",
    ),
    # ---- 35. subdomains --------------------------------------------------- #
    Rule(
        id="SUB-001",
        surface="subdomains",
        name="Staging/development/internal hostname hardcoded",
        description="Non-production or internal hostnames reveal infrastructure that is often less protected and can be enumerated by attackers.",
        severity=Severity.LOW,
        cwe="CWE-200",
        confidence=75,
        extensions=CODE_EXTS + CONFIG_EXTS + (".html", ".md", ".rst", ".vue", ".svelte", ".jsx", ".tsx", ".graphql", ".http", ".rest"),
        keywords=("dev", "staging", "stage", "stg", "test", "qa", "uat", "sandbox", "sbx", "preprod", "pre-prod", "internal", "intranet", "corp", "beta", "alpha", "canary", "preview", "demo", "lab", "nightly", "experimental", "old", "legacy", "backup", "admin", "jenkins", "gitlab", "grafana", "kibana", "jira", "confluence", "vpn", "bastion", "jump", "db.", "database", "mysql", "postgres", "redis", "rabbit", "kafka", "elastic", "vault", "consul", "nexus", "artifactory", "sonar", "sentry"),
        patterns=(_SUBDOMAIN,),
        negatives=(r"^\s*(?:import|from|require)\b",),
        checker=_subdomain,
        scan_comments=True,
        recommendation="Load environment-specific hosts from configuration and keep internal hostnames out of shipped code and public repositories.",
        remediation="API_BASE_URL = os.environ['API_BASE_URL'] with per-environment values injected at deploy time.",
    ),
    Rule(
        id="SUB-002",
        surface="subdomains",
        name="Internal IP address hardcoded",
        description="Private/link-local addresses expose internal network layout and often point at unauthenticated internal services.",
        severity=Severity.LOW,
        cwe="CWE-200",
        confidence=65,
        extensions=CODE_EXTS + CONFIG_EXTS + (".html", ".vue", ".svelte", ".jsx", ".tsx"),
        keywords=("10.", "192.168.", "172.", "169.254.", "fd", "fc"),
        patterns=(
            r"(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})(?![\d.])",
            r"(?<![\w:])f[cd][0-9a-f]{2}:(?:[0-9a-f]{0,4}:){1,6}[0-9a-f]{1,4}(?![\w:])",
        ),
        negatives=(r"^\s*(?:import|from|require)\b", r"10\.0\.0\.0/|192\.168\.0\.0/|172\.16\.0\.0/|/(?:8|12|16)\b|cidr|subnet|netmask|range|private_ranges|BLOCKED|allowlist|whitelist|ipaddress|is_private|rfc1918|version\s*[:=]|\bv?10\.\d+\.\d+\b\s*(?:#|//|$)|python\s*3|node\s*1|\d+\.\d+\.\d+\.\d+\.\d+|test_|spec\.|example|docker-compose|compose\.|Vagrantfile|hosts$|\.env\.example|README|\.md$"),
        use_surface_indicators=False,
        recommendation="Resolve internal endpoints through service discovery/configuration rather than hardcoding addresses.",
        remediation="Use DNS names or environment variables (INTERNAL_API_URL) instead of literal RFC1918 addresses.",
    ),
    # ---- 36. dns ---------------------------------------------------------- #
    Rule(
        id="DNS-001",
        surface="dns",
        name="Insecure DNS resolution",
        description="Hostname resolution of user-controlled names, DNS-rebinding prone validation, or resolution without DNSSEC/allow-listing.",
        severity=Severity.MEDIUM,
        cwe="CWE-350",
        confidence=75,
        extensions=CODE_EXTS,
        keywords=("gethostbyname", "getaddrinfo", "gethostbyaddr", "resolver", "dns.", "lookup", "getbyname", "getallbyname", "gethostaddresses", "gethostentry", "lookuphost", "lookupip", "lookupaddr", "lookupcname", "lookupmx", "lookuptxt", "lookupsrv", "dns_get_record", "checkdnsrr", "resolv", "addrinfo", "getnameinfo", "res_query", "res_search", "c-ares", "net::dns"),
        patterns=(_DNS_CALL,),
        checker=_dns_resolution,
        recommendation="Validate hostnames against an allow-list, pin the resolved IP for the actual connection (reject private ranges), use DoT/DoH or DNSSEC-validating resolvers and set timeouts.",
        remediation="ip = resolve(host); if ipaddress.ip_address(ip).is_private: reject; connect to ip with Host header = host (prevents rebinding).",
    ),
    Rule(
        id="DNS-002",
        surface="dns",
        name="Insecure DNS resolver configuration",
        description="Custom resolvers are configured with plaintext public servers, DNSSEC disabled, permissive dynamic updates, zone transfers to any host or wildcard records.",
        severity=Severity.MEDIUM,
        cwe="CWE-350",
        confidence=85,
        extensions=CODE_EXTS + CONFIG_EXTS + (".zone", ".db", ".bind"),
        keywords=("nameserver", "nameservers", "setservers", "dnssec", "allow-transfer", "allow-update", "allow-recursion", "recursion", "want_dnssec", "resolv.conf", "dns.google", "8.8.8.8", "1.1.1.1", "use_tcp", "edns", "zone", "cname", "rebind", "stop-dns-rebind", "rebind-domain-ok", "private-address", "dnsmasq", "unbound", "bind"),
        patterns=(
            r"(?:nameservers?|setServers|set_servers|dns\.setServers|resolver\.nameservers|DNS_SERVERS?)\s*[:=(]\s*\[?\s*['\"]?(?:8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1|9\.9\.9\.9|208\.67\.222\.222)",
            r"(?:dnssec|dnssec-validation|dnssec-enable|validate_dnssec|want_dnssec|DNSSEC_VALIDATION)\s*[:=]\s*(?:no|off|false|False|0)\b",
            r"allow-transfer\s*\{\s*any\s*;?\s*\}",
            r"allow-update\s*\{\s*any\s*;?\s*\}",
            r"allow-recursion\s*\{\s*any\s*;?\s*\}|recursion\s+yes\s*;(?![\s\S]{0,300}allow-recursion)",
            r"allow-query\s*\{\s*any\s*;?\s*\}\s*(?:#|//|$)",
            r"^\s*\*\s+(?:IN\s+)?(?:A|AAAA|CNAME)\s+\S+",
            r"(?:stop-dns-rebind|rebind-protection|private-address)\s*[:=]?\s*(?:no|false|off|0)\b|rebind-domain-ok\s*=\s*/?\*",
            r"(?:use_tcp|tcp_only|force_tcp)\s*=\s*False|resolver\.use_edns\s*\(\s*-1",
            r"(?:dnsPolicy|dns_policy)\s*:\s*['\"]?Default['\"]?\s*$",
            r"(?:hostNetwork|host_network)\s*:\s*true[\s\S]{0,200}dnsPolicy\s*:\s*(?!ClusterFirstWithHostNet)",
            r"ndots\s*:\s*['\"]?[5-9]\b",
            r"(?:CAA|caa)\s+0\s+issue\s+['\"];['\"]",
        ),
        negatives=(r"^\s*(?:import|from|require|#|//|\*|;)", r"test_|spec\.", r"https://dns|dns\.google/dns-query|cloudflare-dns\.com/dns-query|\bdoh\b|\bdot\b|tls|853"),
        sanitizers=(r"https://dns", r"dns\.google/dns-query", r"cloudflare-dns\.com", r"\bDoH\b", r"\bDoT\b", r"tls", r"\b853\b", r"dnssec\s*[:=]?\s*(?:yes|true|True|1)", r"want_dnssec\s*=\s*True", r"allow-transfer\s*\{\s*(?:none|key|\d)"),
        context_before=6,
        context_after=6,
        use_surface_indicators=False,
        recommendation="Use encrypted (DoT/DoH) or DNSSEC-validating resolvers, restrict zone transfers/updates to specific hosts, enable rebinding protection and avoid wildcard records.",
        remediation="allow-transfer { key tsig-key; }; dnssec-validation auto; resolver = dns.resolver.Resolver(); resolver.nameservers = ['<internal-dot-resolver>']; resolver.use_tcp = True.",
    ),
    # ---- 37. server-config ------------------------------------------------ #
    Rule(
        id="SRV-001",
        surface="server-config",
        name="Wide CORS wildcard (Access-Control-Allow-Origin: *)",
        description="Cross-origin access is granted to every origin; combined with credentials or reflected origins this exposes authenticated APIs to any website.",
        severity=Severity.MEDIUM,
        cwe="CWE-942",
        confidence=90,
        extensions=CODE_EXTS + CONFIG_EXTS + (".htaccess", ".vcl", ".caddyfile"),
        filename_patterns=(r"(?:^|/)(?:nginx|apache|httpd|caddy|Caddyfile|haproxy|traefik|envoy|\.htaccess|web\.config|vercel\.json|netlify\.toml|_headers|serverless\.ya?ml|template\.ya?ml|firebase\.json|now\.json|_redirects)[\w.\-]*$",),
        keywords=("access-control-allow-origin", "cors", "origin", "allow_origins", "allowed_origins", "allowedorigins", "alloworigin", "cors_origin_allow_all", "cors_allow_all_origins", "allowallorigins", "add_header", "header set", "header always"),
        patterns=(
            r"Access-Control-Allow-Origin['\"]?\s*[:,=\]]+\s*['\"]?\*['\"]?",
            r"add_header\s+['\"]?Access-Control-Allow-Origin['\"]?\s+['\"]?\*|Header\s+(?:always\s+)?(?:set|add|append)\s+['\"]?Access-Control-Allow-Origin['\"]?\s+['\"]?\*",
            r"\bCORS\s*\(\s*app\s*\)|\bCORS\s*\(\s*app\s*,\s*(?:resources\s*=\s*\{[^}]*\})?\s*\)|\bcors\s*\(\s*\)|app\.use\(\s*cors\(\s*\)\s*\)",
            r"(?:origins?|allow_origins?|allowed_origins?|allowedOrigins?|allowOrigins?|AllowOrigins?|CORS_ORIGINS?|CORS_ALLOWED_ORIGINS|CORS_ORIGIN_WHITELIST|cors_allowed_origins|origin_allow_list)['\"]?\s*[:=(]\s*\[?\s*['\"]\*['\"]",
            r"(?:origin|Origin)\s*:\s*(?:true|\*|['\"]\*['\"]|\[\s*['\"]\*['\"]\s*\])\s*[,}]",
            r"(?:CORS_ORIGIN_ALLOW_ALL|CORS_ALLOW_ALL_ORIGINS|CORS_ALLOW_ALL|cors_allow_all|AllowAllOrigins|allow_all_origins|allowAnyOrigin)\s*[:=(]?\s*(?:True|true|1|\(\s*\))",
            r"\.AllowAnyOrigin\s*\(\s*\)|allowedOrigins\s*\(\s*['\"]\*['\"]\s*\)|allowedOriginPatterns\s*\(\s*['\"]\*['\"]\s*\)|@CrossOrigin\s*(?:\(\s*\)|\(\s*origins?\s*=\s*['\"]\*['\"])|AllowOrigins\s*:\s*\[\]string\{\s*\"\*\"\s*\}|AllowAllOrigins\s*:\s*true|cors\.Default\(\)|cors\.New\(cors\.Config\{\s*AllowAllOrigins",
            r"rack-cors[\s\S]{0,200}origins\s+['\"]\*['\"]|origins\s+['\"]\*['\"]\s*$",
            r"Access-Control-Allow-Origin['\"]?\s*[:,=\]]+\s*(?:request\.headers|req\.headers|req\.get\(\s*['\"]origin|r\.Header\.Get\(\s*['\"]Origin|\$_SERVER\[['\"]HTTP_ORIGIN|origin\b)",
            r"(?:allowedHeaders|allowed_headers|allow_headers|AllowHeaders|expose_headers|exposedHeaders)\s*[:=(]\s*\[?\s*['\"]\*['\"]\s*\]?\s*,?\s*(?:$|//|#)",
        ),
        negatives=(r"^\s*(?:import|from|require|#|//|\*)", r"test_|spec\.|describe\(|\.md\b|README", r"origins?\s*[:=]\s*\[?\s*['\"]https?://"),
        checker=_cors,
        recommendation="Allow only an explicit list of trusted origins; never combine wildcard/reflected origins with credentials.",
        remediation="CORS(app, origins=['https://app.example.com'], supports_credentials=True); app.use(cors({ origin: ['https://app.example.com'] }))",
    ),
    Rule(
        id="SRV-002",
        surface="server-config",
        name="Insecure web server configuration",
        description="Server settings disclose versions, enable directory listing, use obsolete TLS/ciphers, disable HSTS or serve sensitive files.",
        severity=Severity.MEDIUM,
        cwe="CWE-16",
        confidence=85,
        extensions=(".conf", ".htaccess", ".ini", ".xml", ".toml", ".yaml", ".yml", ".json", ".vcl", ".caddyfile", ".py", ".js", ".ts", ".rb", ".go", ".php", ".cs"),
        filename_patterns=(r"(?:^|/)(?:nginx|apache|httpd|caddy|Caddyfile|haproxy|traefik|envoy|lighttpd|\.htaccess|web\.config|php\.ini|php-fpm|ssl|tls|security|server|vhost|sites?-(?:available|enabled))[\w.\-]*$",),
        keywords=("server_tokens", "servertokens", "serversignature", "expose_php", "autoindex", "indexes", "ssl_protocols", "sslprotocol", "ssl_ciphers", "sslciphersuite", "tls", "hsts", "strict-transport-security", "x-powered-by", "x-frame-options", "x-content-type-options", "removeserverheader", "server: ", "poweredby", "allow_url_include", "allow_url_fopen", "register_globals", "disable_functions", "open_basedir", "display_errors", "cgi.fix_pathinfo", "listen", "error_page", "location ~", "deny all", "helmet", "hidepoweredby", "ssl_verify_client", "proxy_pass http://", "trust proxy", "x-forwarded"),
        patterns=(
            r"server_tokens\s+on|ServerTokens\s+(?:Full|OS|Major|Minor|Min|Minimal)|ServerSignature\s+On|expose_php\s*=\s*On|X-Powered-By\s*:\s*\S+|(?:x-powered-by|hidePoweredBy|hide_powered_by)\s*[:=]\s*(?:false|off)|removeServerHeader\s*=\s*['\"]false['\"]",
            r"ssl_protocols\s+[^;\n]*\b(?:SSLv2|SSLv3|TLSv1|TLSv1\.1)\b|SSLProtocol\s+(?!.*-SSLv3)[^\n]*\b(?:all|SSLv3|TLSv1|TLSv1\.1)\b(?!.*-TLSv1)|(?:min_version|MinVersion|minVersion|ssl_version|PROTOCOL)\s*[:=]\s*['\"]?(?:TLSv?1(?:\.0|_0)?|TLSv?1\.1|TLSv?1_1|SSLv3|ssl\.PROTOCOL_TLSv1(?:_1)?|tls\.VersionTLS10|tls\.VersionTLS11|SslProtocols\.Tls\b|SslProtocols\.Tls11)",
            r"ssl_ciphers\s+[^;\n]*\b(?:RC4|DES|3DES|MD5|NULL|EXPORT|aNULL|eNULL|LOW)\b|SSLCipherSuite\s+[^\n]*\b(?:RC4|DES|MD5|NULL|EXPORT|LOW)\b",
            r"(?:ssl_prefer_server_ciphers\s+off|SSLHonorCipherOrder\s+off)",
            r"(?:hsts|HSTS|strict_transport_security|StrictTransportSecurity)\s*[:=(]\s*(?:false|off|0|null|disabled)\b|Strict-Transport-Security['\"]?\s*[:=]\s*['\"]?max-age=0",
            r"allow_url_include\s*=\s*On|register_globals\s*=\s*On|cgi\.fix_pathinfo\s*=\s*1|disable_functions\s*=\s*$|open_basedir\s*=\s*$|safe_mode\s*=\s*Off|enable_dl\s*=\s*On|allow_url_fopen\s*=\s*On",
            r"ssl_verify_client\s+off\s*;\s*(?:#.*)?$|proxy_ssl_verify\s+off|proxy_ssl_verify\s+off|SSLVerifyClient\s+none|SSLProxyVerify\s+none|SSLProxyCheckPeerName\s+off",
            r"(?:trust\s*proxy|trustProxy|TRUST_PROXY|trusted_proxies|TrustedProxies|proxy_trusted_hosts)\s*[:=(,]\s*(?:true|['\"]\*['\"]|\*|['\"]0\.0\.0\.0/0['\"]|\[\s*['\"]0\.0\.0\.0/0['\"]|\[\s*['\"]\*['\"]|all\b)",
            r"(?:X-Frame-Options|x_frame_options|frameguard)\s*[:=(]\s*(?:false|off|null|['\"]?ALLOW-FROM\s+\*|['\"]?ALLOWALL)",
            r"(?:xContentTypeOptions|X-Content-Type-Options|noSniff|nosniff)\s*[:=(]\s*(?:false|off|null)",
            r"(?:contentSecurityPolicy|referrerPolicy|xssFilter|dnsPrefetchControl|hidePoweredBy|frameguard|hsts|ieNoOpen|noSniff)\s*:\s*false",
            r"helmet\s*\(\s*\{\s*\}\s*\)\s*;?\s*(?://.*)?$",
            r"location\s+~\s*\\?\.(?:git|svn|env|htaccess|htpasswd|ini|log|sql|bak)\b[^{]*\{\s*(?:allow\s+all|autoindex\s+on)",
            r"^\s*listen\s+(?:0\.0\.0\.0:)?(?:\d+\s+)?(?!.*ssl)(?:80|8080)\s*;?\s*$(?![\s\S]{0,400}return\s+301)",
            r"(?:error_page|ErrorDocument)\s+\d{3}\s+[^\n]*(?:\$request_uri|%\{REQUEST_URI\})",
            r"proxy_pass\s+http://(?!127\.0\.0\.1|localhost|unix:|\$|[\w\-]+(?::\d+)?\s*;)",
            r"(?:AllowOverride\s+All|Options\s+[^\n]*\+?(?:ExecCGI|Includes|FollowSymLinks)\s*$)",
            r"<Directory\s+/>\s*[\s\S]{0,80}(?:Require\s+all\s+granted|Allow\s+from\s+all)",
            r"(?:DEBUG|debug)\s*[:=]\s*(?:True|true)[\s\S]{0,40}(?:SECURE_SSL_REDIRECT|SESSION_COOKIE_SECURE)\s*=\s*False",
            r"SECURE_(?:SSL_REDIRECT|HSTS_SECONDS|CONTENT_TYPE_NOSNIFF|BROWSER_XSS_FILTER)\s*=\s*(?:False|0)\b|X_FRAME_OPTIONS\s*=\s*['\"]ALLOWALL['\"]|SECURE_PROXY_SSL_HEADER\s*=\s*\(\s*['\"]HTTP_X_FORWARDED_PROTO['\"]\s*,\s*['\"]https['\"]\s*\)(?![\s\S]{0,200}(?:trusted|proxy))",
            r"config\.force_ssl\s*=\s*false|config\.ssl_options\s*=\s*\{\s*hsts\s*:\s*false",
            r"ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]\s*\]",
            r"app\.config\[['\"]TRUSTED_HOSTS['\"]\]\s*=\s*\[?\s*['\"]\*['\"]|TrustedHostMiddleware\([^)]*allowed_hosts\s*=\s*\[\s*['\"]\*['\"]\s*\]",
            r"http\.ListenAndServe\s*\(\s*['\"]:\d+['\"]",
            r"(?:MaxHeaderBytes|ReadHeaderTimeout|ReadTimeout|WriteTimeout|IdleTimeout)\s*:\s*0\b",
            r"client_max_body_size\s+(?:0|\d{4,}[mg])\b|LimitRequestBody\s+0\b|MAX_CONTENT_LENGTH\s*=\s*None|(?:limit|bodyLimit|maxBodySize)\s*:\s*['\"]?(?:0|\d{4,}mb|Infinity)",
        ),
        negatives=(r"^\s*(?:#|//|\*|;)", r"test_|spec\.|example|README|\.md\b", r"ssl_protocols\s+TLSv1\.2\s+TLSv1\.3\s*;|ssl_protocols\s+TLSv1\.3\s*;|SSLProtocol\s+-all\s+\+TLSv1\.[23]|SSLProtocol\s+all\s+-SSLv3\s+-TLSv1\s+-TLSv1\.1", r"HTTP_X_FORWARDED_PROTO.*(?:#|//).*(?:proxy|behind)"),
        sanitizers=(r"return\s+301", r"redirect\s+scheme\s+https", r"ssl_protocols\s+TLSv1\.2", r"SSLProtocol\s+-all", r"Strict-Transport-Security", r"add_header\s+X-Frame-Options", r"server_tokens\s+off", r"ServerTokens\s+Prod", r"os\.environ", r"getenv", r"process\.env", r"NODE_ENV", r"DEBUG"),
        context_before=8,
        context_after=8,
        use_surface_indicators=False,
        recommendation="Hide server version headers, enforce TLS 1.2+ with strong ciphers, enable HSTS and security headers, restrict ALLOWED_HOSTS/trusted proxies and disable directory listing.",
        remediation="server_tokens off; ssl_protocols TLSv1.2 TLSv1.3; add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always; ALLOWED_HOSTS = ['app.example.com']",
    ),
    # ---- 38. containers --------------------------------------------------- #
    Rule(
        id="CNT-001",
        surface="containers",
        name="Dockerfile misconfiguration (latest tag / root user / build-time secrets)",
        description="Dockerfile uses unpinned base images, runs as root, bakes secrets into layers, pipes remote scripts into a shell or disables TLS during build.",
        severity=Severity.MEDIUM,
        cwe="CWE-250",
        confidence=90,
        filename_patterns=_DOCKERFILE_NAME,
        file_checker=_dockerfile,
        recommendation="Pin base images to digests, create and switch to a non-root USER, pass secrets with --mount=type=secret and verify downloaded artifacts.",
        remediation="FROM python:3.12.4-slim@sha256:<digest>\nRUN useradd -r app\nUSER app\nRUN --mount=type=secret,id=pip ... (never ENV SECRET=...)",
    ),
    Rule(
        id="CNT-002",
        surface="containers",
        name="Insecure container orchestration setting (compose / Kubernetes)",
        description="Compose files or Kubernetes manifests grant privileged mode, host namespaces, root users, dangerous capabilities, unpinned images, plaintext credentials or publish datastore ports.",
        severity=Severity.HIGH,
        cwe="CWE-250",
        confidence=88,
        extensions=(".yaml", ".yml", ".json"),
        filename_patterns=_COMPOSE_NAME + (r"(?:^|/)(?:k8s|kubernetes|manifests?|helm|charts?|deploy(?:ment)?s?|templates)/[^/]+\.ya?ml$",
                                           r"(?:^|/)(?:deployment|pod|daemonset|statefulset|job|cronjob)[\w.\-]*\.ya?ml$", r"(?:^|/)values[\w.\-]*\.ya?ml$"),
        keywords=("privileged", "user:", "network_mode", "pid:", "ipc:", "hostnetwork", "hostpid", "hostipc", "runasuser", "runasnonroot", "allowprivilegeescalation", "readonlyrootfilesystem", "docker.sock", "sys_admin", "net_admin", "sys_ptrace", "cap_add", "- all", "seccomp", "apparmor", "hostpath", "automountserviceaccounttoken", "image:", "imagepullpolicy", "password", "secret", "api_key", "jwt", "allow_empty_password", "host_auth_method", "ports:", "- \"", "- '", "- 0.0.0.0"),
        patterns=(_K8S_OR_COMPOSE,),
        negatives=(r"^\s*#", r"\$\{|\{\{|secretKeyRef|valueFrom|_FILE\s*[:=]|/run/secrets", r"runAsUser\s*:\s*[1-9]"),
        checker=_compose_k8s,
        recommendation="Run containers unprivileged as non-root with dropped capabilities, pin images to digests, use secrets objects and bind published ports to localhost.",
        remediation="securityContext: { runAsNonRoot: true, runAsUser: 10001, allowPrivilegeEscalation: false, capabilities: { drop: [ALL] } }; image: repo/app@sha256:...; ports: - \"127.0.0.1:5432:5432\"",
    ),
)
