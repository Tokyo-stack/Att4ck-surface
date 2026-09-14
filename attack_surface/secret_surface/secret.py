"""Secret surface: hardcoded keys in config files, env templates, CI/CD
tokens, credentials in VCS metadata and non-PCI card handling
(surfaces 15, 21, 22, 33, 39).
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from attack_surface.analysis import (
    PLACEHOLDER,
    SECRET_KEY_NAMES,
    lookahead,
    lookbehind,
    looks_like_secret,
    make_hit,
    shannon_entropy,
)
from attack_surface.models import FileContext, Hit, Rule, Severity

CONFIG_EXTS = (".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".config", ".properties", ".xml", ".plist",
               ".env", ".envrc", ".tfvars", ".tf", ".hcl", ".txt", ".cnf", ".rc", ".secrets", ".settings")
CODE_EXTS = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".rb", ".java", ".go", ".cs", ".kt",
             ".scala", ".swift", ".m", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".pl", ".lua", ".dart", ".sql",
             ".md", ".rst", ".ipynb", ".gradle", ".groovy", ".vue", ".svelte", ".html", ".tpl", ".dockerfile", ".make")
ALL_TEXT = CONFIG_EXTS + CODE_EXTS

# --------------------------------------------------------------------------- #
# 21. secrets-config
# --------------------------------------------------------------------------- #

#: (name, regex, severity, confidence) — well-known credential formats.
TOKEN_SIGNATURES: tuple[tuple[str, str, Severity, int], ...] = (
    ("AWS access key id", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b", Severity.CRITICAL, 95),
    ("AWS secret access key", r"(?i)aws[\w\-]*(?:secret|sk)[\w\-]*\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])", Severity.CRITICAL, 90),
    ("GitHub token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b", Severity.CRITICAL, 97),
    ("GitHub fine-grained PAT", r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b", Severity.CRITICAL, 97),
    ("GitLab token", r"\bglpat-[A-Za-z0-9_\-]{20,}\b", Severity.CRITICAL, 95),
    ("Slack token", r"\bxox[baprs]-[0-9]{8,}-[0-9A-Za-z\-]{8,}\b", Severity.CRITICAL, 95),
    ("Slack webhook URL", r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}", Severity.HIGH, 95),
    ("Stripe live secret key", r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b", Severity.CRITICAL, 97),
    ("Stripe test secret key", r"\b(?:sk|rk)_test_[0-9a-zA-Z]{20,}\b", Severity.MEDIUM, 90),
    ("OpenAI API key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b|\bsk-proj-[A-Za-z0-9_\-]{48,}\b", Severity.CRITICAL, 95),
    ("Anthropic API key", r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{40,}\b", Severity.CRITICAL, 97),
    ("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b", Severity.HIGH, 92),
    ("Google OAuth client secret", r"\bGOCSPX-[A-Za-z0-9_\-]{28}\b", Severity.CRITICAL, 95),
    ("SendGrid API key", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", Severity.CRITICAL, 97),
    ("Twilio API key", r"\bSK[0-9a-fA-F]{32}\b", Severity.HIGH, 80),
    ("Mailgun API key", r"\bkey-[0-9a-zA-Z]{32}\b", Severity.HIGH, 85),
    ("Mailchimp API key", r"\b[0-9a-f]{32}-us[0-9]{1,2}\b", Severity.HIGH, 90),
    ("npm access token", r"\bnpm_[A-Za-z0-9]{36}\b", Severity.CRITICAL, 95),
    ("PyPI API token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b", Severity.CRITICAL, 97),
    ("Hugging Face token", r"\bhf_[A-Za-z0-9]{34}\b", Severity.HIGH, 92),
    ("Discord bot token", r"\b[MN][A-Za-z0-9_\-]{23,}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}\b", Severity.HIGH, 80),
    ("Discord webhook URL", r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_\-]{60,}", Severity.HIGH, 95),
    ("Telegram bot token", r"\b\d{8,10}:AA[0-9A-Za-z_\-]{33}\b", Severity.HIGH, 92),
    ("Shopify access token", r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b", Severity.CRITICAL, 95),
    ("Square access token", r"\bsq0atp-[0-9A-Za-z_\-]{22}\b|\bsq0csp-[0-9A-Za-z_\-]{43}\b", Severity.CRITICAL, 95),
    ("Heroku API key", r"(?i)heroku[\w\-]*\s*[:=]\s*['\"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", Severity.HIGH, 85),
    ("Azure storage account key", r"AccountKey=[A-Za-z0-9+/=]{86,88}", Severity.CRITICAL, 95),
    ("Azure AD client secret", r"(?i)(?:client|app)[_\-]?secret\s*[:=]\s*['\"]?[A-Za-z0-9~._\-]{34,40}['\"]?", Severity.HIGH, 70),
    ("DigitalOcean token", r"\bdop_v1_[a-f0-9]{64}\b|\bdoo_v1_[a-f0-9]{64}\b", Severity.CRITICAL, 97),
    ("Vault token", r"\b(?:hvs|hvb)\.[A-Za-z0-9_\-]{24,}\b|\bs\.[A-Za-z0-9]{24}\b(?=.*vault)", Severity.CRITICAL, 90),
    ("Doppler token", r"\bdp\.(?:pt|st|ct|sa)\.[A-Za-z0-9]{40,}\b", Severity.CRITICAL, 95),
    ("Cloudflare API token", r"(?i)cloudflare[\w\-]*(?:token|key)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{40}\b", Severity.HIGH, 85),
    ("Linear / Notion / Airtable key", r"\blin_api_[A-Za-z0-9]{40}\b|\bsecret_[A-Za-z0-9]{43}\b|\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b", Severity.HIGH, 85),
    ("Private key block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----", Severity.CRITICAL, 97),
    ("JSON Web Token", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", Severity.MEDIUM, 75),
    ("Basic auth header", r"(?i)authorization['\"]?\s*[:=]\s*['\"]?basic\s+[A-Za-z0-9+/=]{16,}", Severity.HIGH, 85),
    ("Bearer token literal", r"(?i)authorization['\"]?\s*[:=]\s*['\"]?bearer\s+[A-Za-z0-9._~+/\-]{20,}=*['\"]?", Severity.HIGH, 80),
    ("Facebook/Meta access token", r"\bEAACEdEose0cBA[0-9A-Za-z]+\b|\bEAA[A-Za-z0-9]{100,}\b", Severity.HIGH, 85),
    ("Twitter/X bearer token", r"\bAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{60,}\b", Severity.HIGH, 85),
    ("Age / SSH secret key", r"\bAGE-SECRET-KEY-1[A-Z0-9]{58}\b", Severity.CRITICAL, 97),
    ("Generic hex API key assignment", r"(?i)(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token)\s*[:=]\s*['\"]([a-f0-9]{32,64})['\"]", Severity.HIGH, 80),
)
_TOKEN_PATTERNS = tuple((name, re.compile(rx), sev, conf) for name, rx, sev, conf in TOKEN_SIGNATURES)
_TOKEN_NEGATIVE = re.compile(r"EXAMPLE|example|sample|dummy|placeholder|AKIAIOSFODNN7EXAMPLE|wJalrXUtnFEMI|xxxxxxxx|\.\.\.|<[A-Za-z_]+>|\$\{|\{\{|your[_\-]|redacted|fake|mock|test_token|00000000|11111111|deadbeef|ABCDEFGHIJKLMNOP|1234567890abcdef|snapshot", re.I)


def _token_signatures(rule: Rule, ctx: FileContext) -> Iterator[Hit]:
    if ctx.rel_path.lower().endswith((".lock", ".sum", ".min.js", ".map")):
        return
    text = ctx.text
    quick = ("AKIA", "ASIA", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "xox", "hooks.slack", "sk_live", "rk_live", "sk_test", "rk_test", "sk-", "AIza", "GOCSPX", "SG.", "key-", "npm_", "pypi-", "hf_", "discord", "shp", "sq0", "AccountKey", "dop_v1", "doo_v1", "hvs.", "hvb.", "dp.", "lin_api", "PRIVATE KEY", "eyJ", "asic ", "ASIC ", "earer ", "EARER ", "EAA", "AAAAAAAAAAAAAAAAAAAAA", "AGE-SECRET", "secret", "SECRET", "token", "TOKEN", "api", "API", "heroku", "HEROKU", "cloudflare", "CLOUDFLARE", "aws", "AWS", "pat", "-us")
    if not any(q in text for q in quick):
        return
    seen: set[int] = set()
    for name, pattern, severity, confidence in _TOKEN_PATTERNS:
        for match in pattern.finditer(text):
            line_no = ctx.line_at_offset(match.start())
            if line_no in seen:
                continue
            line = ctx.line(line_no)
            if _TOKEN_NEGATIVE.search(line) or (name == "JSON Web Token" and re.search(r"test|spec|fixture|example|jwt\.io|docs", ctx.rel_path, re.I)):
                continue
            if name in {"Twilio API key", "Mailgun API key", "Discord bot token"} and shannon_entropy(match.group(0)) < 3.2:
                continue
            seen.add(line_no)
            yield Hit(line=line_no, snippet=line, column=match.start() - text.rfind("\n", 0, match.start()),
                      name=f"{name} exposed", severity=severity, confidence=confidence, skip_sanitizer_check=True,
                      description=f"A value matching the {name} format is committed to the repository.")


_CONFIG_ASSIGN = re.compile(
    rf"(?i)(?:^|[\s,{{\[\"'])(?P<key>[\w.\-]*{SECRET_KEY_NAMES}[\w.\-]*)\s*[\"']?\s*(?:[:=]|=>)\s*[\"']?(?P<value>[^\"'\s,;}}\]#]{{8,}})",
)


def _config_secret(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    key = match.group("key")
    value = match.group("value").strip()
    if re.search(r"_(?:file|path|url|name|id|env|var|ref|arn|key_id|field|header|param|prefix|suffix|length|ttl|expiry|expires|expiration|rotation|version|algorithm|alg|type|kind|source|from|ref|store|provider|manager|backend|class|required|enabled|policy|secret_name|secretName|secretKeyRef|valueFrom)$", key, re.I):
        return None
    if re.search(r"(?:file|path|url|name|id|env|ref|arn|key_id|header|length|ttl|expiry|expires|expiration|rotation|version|algorithm|type|kind|source|store|provider|manager|backend|class|required|enabled|policy|secretName|secretKeyRef|valueFrom|Placeholder|placeholder|label|title|description|hint|help|prompt|message|error|regex|pattern|validator|validation|min|max)$", key):
        return None
    if PLACEHOLDER.search(value) or _TOKEN_NEGATIVE.search(value):
        return None
    if re.match(r"^(?:\$|%|@|\{|\(|<|\[|/|~|\.\/|\\|true|false|null|none|nil|yes|no|on|off|\d+(?:\.\d+)?|0x[0-9a-f]+|https?://|file:|s3://|gs://|arn:|vault:|ssm:|secretsmanager:|projects/|/run/secrets|op://|akv:|kms:)", value, re.I):
        return None
    if re.search(r"^[A-Z][A-Z0-9_]{3,}$", value) and "=" not in value:
        return None  # references like SECRET_KEY = DJANGO_SECRET (constant name)
    if re.search(r"^\w+\(|\w+\.\w+\(|\bconfig\b|\bsettings\b|\benv\b|\bENV\b|getenv|environ|process\.|require\(|import|readFile|open\(|\bref\b|\bfrom\b", value):
        return None
    if ctx.ext in {".md", ".rst", ".txt"} and re.search(r"^\s*(?:\$|>|#|-)|\bexample\b|\bsample\b", ctx.line(line_no), re.I):
        return None
    entropy = shannon_entropy(value)
    if len(value) < 12 and entropy < 3.0:
        return None
    if not looks_like_secret(value, min_length=8, min_entropy=2.8):
        return None
    severity = Severity.CRITICAL if re.search(r"private|secret|password|passwd|master|encryption|signing", key, re.I) else Severity.HIGH
    confidence = 90 if entropy >= 4.0 else (80 if entropy >= 3.3 else 65)
    if re.search(r"test|spec|fixture|example|sample|mock|docs?/", ctx.rel_path, re.I):
        confidence -= 25
        severity = severity.downgrade()
    return make_hit(ctx, line_no, column=match.start("value") + 1, severity=severity, confidence=confidence,
                    skip_sanitizer_check=True,
                    description=f"'{key}' is assigned a literal high-entropy value in a configuration file.")


# --------------------------------------------------------------------------- #
# 22. environment-files
# --------------------------------------------------------------------------- #

_ENV_TEMPLATE_NAME = re.compile(
    r"(?:^|/)(?:\.env(?:\.[\w-]+)*\.(?:example|sample|template|tpl|dist|default|defaults|skel|stub)|"
    r"(?:example|sample|template|default)\.env|env\.(?:example|sample|template|dist)|\.env\.(?:example|sample)\.[\w-]+|"
    r"\.envrc\.(?:example|sample|template)|env\.example\.\w+)$",
    re.I,
)
_ENV_REAL_NAME = re.compile(
    r"(?:^|/)(?:\.env|\.env\.(?!example|sample|template|tpl|dist|default|defaults|skel|stub)[\w.-]+|\.envrc|\.flaskenv|env\.local|secrets\.env|[\w.-]+\.env)$",
    re.I,
)
_ENV_LINE = re.compile(r"^\s*(?:export\s+)?(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>.*?)\s*$")
_ENV_SECRET_KEY = re.compile(
    r"(?:PASS(?:WORD|WD)?|PWD|SECRET|TOKEN|API_?KEY|APIKEY|ACCESS_?KEY|PRIVATE_?KEY|CLIENT_?SECRET|AUTH|CREDENTIAL|"
    r"DSN|DATABASE_URL|DB_URL|REDIS_URL|MONGO(?:DB)?_URI|AMQP_URL|BROKER_URL|CONNECTION_?STRING|SIGNING|ENCRYPTION|"
    r"MASTER_?KEY|SALT|WEBHOOK|LICENSE|CERT|KEY)",
    re.I,
)


def _env_value_is_real(value: str) -> tuple[bool, int]:
    value = value.strip()
    if (value.startswith(("'", '"')) and value.endswith(("'", '"')) and len(value) >= 2):
        value = value[1:-1]
    value = value.split(" #")[0].strip()
    if not value or PLACEHOLDER.search(value) or _TOKEN_NEGATIVE.search(value):
        return False, 0
    if re.match(r"^(?:\$|%|\{|<|\[|true|false|null|none|yes|no|on|off|\d{1,5}|localhost|127\.0\.0\.1|0\.0\.0\.0|https?://(?:localhost|127\.0\.0\.1|example)|[A-Za-z_]+$|/[\w/.-]*$|\*+$|x+$|\.+$|-+$|_+$)", value, re.I):
        return False, 0
    if re.match(r"^[a-z]+[-_ ][a-z]+(?:[-_ ][a-z]+)*$", value, re.I) and len(value) < 24:
        return False, 0  # "change-me-please" style words
    if re.search(r"://[^:]+:[^@]{4,}@", value):
        return True, 95
    for _name, pattern, _sev, conf in _TOKEN_PATTERNS:
        if pattern.search(value):
            return True, max(conf, 90)
    entropy = shannon_entropy(value)
    if len(value) >= 16 and entropy >= 3.5:
        return True, 88
    if len(value) >= 10 and entropy >= 3.0 and re.search(r"\d", value) and re.search(r"[A-Za-z]", value):
        return True, 75
    if len(value) >= 8 and re.search(r"[A-Z]", value) and re.search(r"[a-z]", value) and re.search(r"\d", value) and re.search(r"[^A-Za-z0-9]", value):
        return True, 70
    return False, 0


def _env_files(rule: Rule, ctx: FileContext) -> Iterator[Hit]:
    rel = ctx.rel_path
    is_template = bool(_ENV_TEMPLATE_NAME.search(rel))
    is_real = not is_template and bool(_ENV_REAL_NAME.search(rel))
    if not (is_template or is_real):
        return
    for idx, line in enumerate(ctx.lines, start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = _ENV_LINE.match(line)
        if not match:
            continue
        key, value = match.group("key"), match.group("value")
        if not _ENV_SECRET_KEY.search(key):
            continue
        real, confidence = _env_value_is_real(value)
        if not real:
            continue
        if is_template:
            yield Hit(line=idx, snippet=line, confidence=confidence, severity=Severity.HIGH, skip_sanitizer_check=True,
                      name="Real secret in environment template file",
                      description=f"{ctx.name} is a template shared with every developer, yet '{key}' holds a real-looking secret.")
        else:
            yield Hit(line=idx, snippet=line, confidence=max(50, confidence - 10), severity=Severity.HIGH, skip_sanitizer_check=True,
                      name="Secret in environment file committed to the repository",
                      description=f"'{key}' in {ctx.name} contains a real-looking secret; env files must stay out of version control.")


# --------------------------------------------------------------------------- #
# 33. ci-cd
# --------------------------------------------------------------------------- #

_CI_FILE = (
    r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$", r"(?:^|/)\.gitlab-ci\.ya?ml$", r"(?:^|/)\.gitlab/ci/[^/]+\.ya?ml$",
    r"(?:^|/)\.circleci/config\.ya?ml$", r"(?:^|/)Jenkinsfile[^/]*$", r"(?:^|/)azure-pipelines[^/]*\.ya?ml$",
    r"(?:^|/)bitbucket-pipelines\.ya?ml$", r"(?:^|/)\.travis\.ya?ml$", r"(?:^|/)\.drone\.ya?ml$",
    r"(?:^|/)buildspec[^/]*\.ya?ml$", r"(?:^|/)cloudbuild[^/]*\.ya?ml$", r"(?:^|/)\.buildkite/[^/]+\.ya?ml$",
    r"(?:^|/)appveyor\.yml$", r"(?:^|/)\.woodpecker\.ya?ml$", r"(?:^|/)codemagic\.yaml$", r"(?:^|/)\.tekton/[^/]+\.ya?ml$",
    r"(?:^|/)\.github/actions/[^/]+/action\.ya?ml$", r"(?:^|/)action\.ya?ml$", r"(?:^|/)\.gitea/workflows/[^/]+\.ya?ml$",
    r"(?:^|/)wercker\.yml$", r"(?:^|/)\.semaphore/[^/]+\.ya?ml$", r"(?:^|/)skaffold\.ya?ml$", r"(?:^|/)Makefile$",
)
_CI_SECRET_LINE = re.compile(
    rf"(?i)(?:^\s*-?\s*(?:env\.|)(?P<key>[\w.\-]*{SECRET_KEY_NAMES}[\w.\-]*)\s*[:=]\s*[\"']?(?P<value>[^\"'\s#]{{8,}})[\"']?\s*(?:#.*)?$"
    rf"|(?:--?(?:password|token|api-?key|secret|access-?key|auth)|-p|-u\s+\w+:)\s*[= ]\s*[\"']?(?P<value2>(?!\$)[^\"'\s]{{6,}})[\"']?"
    rf"|(?:docker\s+login|npm\s+login|helm\s+registry\s+login|gh\s+auth\s+login|az\s+login|aws\s+configure\s+set)\s+[^\n]*?(?:-p|--password|--password-stdin|--token|-t|--secret)\s+[\"']?(?P<value3>(?!\$)[^\"'\s]{{6,}})"
    rf"|_authToken\s*=\s*(?P<value4>(?!\$)[^\s]{{8,}})"
    rf"|(?:echo|printf)\s+[\"']?(?P<value5>(?!\$)[^\"'\s|>]{{20,}})[\"']?\s*\|\s*(?:docker\s+login|gh\s+auth|npm\s+login|base64))",
)


def _ci_secret(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    value = next((match.group(g) for g in ("value", "value2", "value3", "value4", "value5") if match.groupdict().get(g)), "")
    key = (match.groupdict().get("key") or "").strip()
    line = ctx.line(line_no)
    if re.search(r"\$\{\{|\$\{|\$\w+|\$\(|<<|\{\{|%\(|\bsecrets\.|vault|masked|\bvars\.|\benv\.|\$env:|\bENV\[|from_secret|secretKeyRef|--password-stdin\s*$|\bwith:\s*$", line):
        return None
    if key and re.search(r"(?:_FILE|_PATH|_NAME|_ID|_REF|_ARN|_URL|_LENGTH|_TTL|_HEADER|_TYPE|_KIND|_KEY_ID|Required|Enabled)$", key, re.I):
        return None
    if not value or PLACEHOLDER.search(value) or _TOKEN_NEGATIVE.search(value):
        return None
    if re.match(r"^(?:true|false|null|none|\d+|[a-z]+|https?://|/|\./|~|\*|-+)$", value, re.I):
        return None
    if not looks_like_secret(value, min_length=6, min_entropy=2.6) and not any(p.search(value) for _n, p, _s, _c in _TOKEN_PATTERNS):
        return None
    return make_hit(ctx, line_no, column=match.start() + 1, skip_sanitizer_check=True,
                    description=f"A literal credential{f' for {key}' if key else ''} is embedded in the pipeline definition instead of a secret reference.")


def _ci_injection(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    block = lookbehind(ctx, line_no, 15)
    if re.search(r"env:\s*$", block) and re.search(r"\b\w+:\s*\$\{\{\s*github\.event\.[\w.]+\s*\}\}", block):
        return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by="env: indirection", skip_sanitizer_check=True, confidence=30)
    return make_hit(ctx, line_no, column=match.start() + 1, skip_sanitizer_check=True)


# --------------------------------------------------------------------------- #
# 39. source-control
# --------------------------------------------------------------------------- #

_VCS_CRED_URL = re.compile(
    r"(?:https?|ssh|git|svn(?:\+ssh)?|ftp)://(?P<user>[A-Za-z0-9._%+\-]+):(?P<pass>[^@/\s'\"`<>]{4,})@(?P<host>[A-Za-z0-9.\-]+)",
)
_VCS_FILES = (
    r"(?:^|/)\.git-credentials$", r"(?:^|/)\.netrc$", r"(?:^|/)_netrc$", r"(?:^|/)\.npmrc$", r"(?:^|/)\.yarnrc(?:\.yml)?$",
    r"(?:^|/)\.pypirc$", r"(?:^|/)\.gitconfig$", r"(?:^|/)\.gitmodules$", r"(?:^|/)\.hgrc$", r"(?:^|/)\.subversion/auth/",
    r"(?:^|/)\.gem/credentials$", r"(?:^|/)\.composer/auth\.json$", r"(?:^|/)auth\.json$", r"(?:^|/)\.docker/config\.json$",
    r"(?:^|/)\.dockercfg$", r"(?:^|/)\.m2/settings\.xml$", r"(?:^|/)settings\.xml$", r"(?:^|/)\.bundle/config$",
    r"(?:^|/)\.cargo/credentials(?:\.toml)?$", r"(?:^|/)\.terraformrc$", r"(?:^|/)terraform\.rc$", r"(?:^|/)\.s3cfg$",
    r"(?:^|/)\.boto$", r"(?:^|/)\.aws/credentials$", r"(?:^|/)credentials$", r"(?:^|/)\.azure/",
    r"(?:^|/)\.config/gcloud/", r"(?:^|/)\.kube/config$", r"(?:^|/)kubeconfig$", r"(?:^|/)\.ssh/", r"(?:^|/)id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$",
    r"(?:^|/)\.git/config$", r"(?:^|/)\.git/", r"(?:^|/)\.gitlab-ci\.ya?ml$", r"(?:^|/)\.github/",
)


def _vcs_cred_url(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    user, password, host = match.group("user"), match.group("pass"), match.group("host")
    if PLACEHOLDER.search(password) or _TOKEN_NEGATIVE.search(password) or re.match(r"^(?:pass(?:word)?|pwd|token|secret|xxx+|\*+|\.+|\$|%|\{|<|your)", password, re.I):
        return None
    if re.match(r"^(?:user(?:name)?|foo|bar|me|admin|root|git|oauth2|x-token-auth|x-access-token|token|USER|\$|\{|<)$", user, re.I) and not looks_like_secret(password, 8, 3.0):
        return None
    if host in {"localhost", "127.0.0.1", "example.com", "host", "hostname", "server", "db", "database"}:
        return None
    if not (looks_like_secret(password, min_length=6, min_entropy=2.5) or any(p.search(password) for _n, p, _s, _c in _TOKEN_PATTERNS)):
        return None
    return make_hit(ctx, line_no, column=match.start() + 1, skip_sanitizer_check=True,
                    description=f"URL for {host} embeds credentials for user '{user}'.")


_VCS_FILE_SECRET = re.compile(
    r"(?i)^\s*(?:(?:password|passwd|_auth|_authToken|//[^:]+/:_authToken|token|api_key|apikey|npmAuthToken|aws_secret_access_key|"
    r"secret_key|access_key|client-secret|<password>|\"auth\"|auth)\s*[:=]?\s*[\"']?(?P<value>[^\"'\s<]{8,})|machine\s+\S+\s+login\s+\S+\s+password\s+(?P<value2>\S{4,}))",
)


def _vcs_file(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    value = match.groupdict().get("value") or match.groupdict().get("value2") or ""
    if not value or PLACEHOLDER.search(value) or re.match(r"^(?:\$|%|\{|<|true|false|null)", value):
        return None
    if not (looks_like_secret(value, 8, 2.8) or any(p.search(value) for _n, p, _s, _c in _TOKEN_PATTERNS)):
        return None
    return make_hit(ctx, line_no, column=match.start() + 1, skip_sanitizer_check=True,
                    description=f"{ctx.name} stores a plaintext credential that will be cloned with the repository.")


_KEY_MATERIAL_NAME = re.compile(
    r"(?:^|/)(?:id_(?:rsa|dsa|ecdsa|ed25519)|[\w.-]*\.(?:pem|key|p12|pfx|jks|keystore|ppk|asc|gpg|kdbx|ovpn|pkcs12|crt\.key|priv))$",
    re.I,
)


def _key_material(rule: Rule, ctx: FileContext) -> Iterator[Hit]:
    name = ctx.name
    rel = ctx.rel_path.lower()
    if not _KEY_MATERIAL_NAME.search(name):
        return
    if name.endswith(".pub") or re.search(r"(?:^|/)(?:public|pub|certs?|ca-certificates|trust)/", rel) or re.search(r"public|cacert|ca-bundle|chain|fullchain|root", name, re.I):
        return
    if re.search(r"test|spec|fixture|example|sample|mock|dummy|snapshot", rel):
        yield Hit(line=1, snippet=name, severity=Severity.LOW, confidence=45, skip_sanitizer_check=True,
                  description=f"Private key material '{name}' sits in a test/example path; confirm it is a throwaway key.")
        return
    yield Hit(line=1, snippet=name, severity=Severity.HIGH, confidence=80, skip_sanitizer_check=True,
              description=f"Private key material '{name}' is committed to version control.")


# --------------------------------------------------------------------------- #
# 15. payment-systems
# --------------------------------------------------------------------------- #

_CARD_FIELD = re.compile(
    r"(?P<field>\b(?:cvv2?|cvc2?|cvn|cid|csc|security[_\-]?code|card[_\-]?(?:security|verification)[_\-]?(?:code|value)|"
    r"card[_\-]?number|cardnumber|cardnum|credit[_\-]?card[_\-]?(?:number|num|no|nbr)?|creditcard|cc[_\-]?(?:number|num|no)|"
    r"\bpan\b|primary[_\-]?account[_\-]?number|card[_\-]?data|full[_\-]?card|track[_\-]?(?:1|2|data)|magstripe|"
    r"exp(?:iry|iration)?[_\-]?(?:date|month|year)|card[_\-]?exp\w*|exp_month|exp_year|expiry|expMonth|expYear)\b)",
    re.I,
)
_STORE_SINK = re.compile(
    r"\.save\(|\.create\(|\.insert\w*\(|INSERT\s+INTO|UPDATE\s+\w+\s+SET|\.update\w*\(|execute\(|\.commit\(|Column\(|"
    r"models\.\w*Field\(|db\.\w*\(|@Column|@Field|@Prop|Schema\(|new\s+Schema|mongoose|sequelize|\.persist\(|\.merge\(|"
    r"localStorage|sessionStorage|document\.cookie|set_cookie|res\.cookie|session\[|session\.|redis|cache\.set|\.set\(|"
    r"logger?\.|logging\.|console\.|print\(|\.log\(|\.info\(|\.debug\(|\.warn\(|\.error\(|System\.out|Log\.|NSLog|"
    r"writeFile|open\(|\.write\(|json\.dump|csv\.writer|to_csv|to_json|pickle|send_mail|sendMail|smtp|\.publish\(|"
    r"\bstore\b|\bpersist\b|localStorage|IndexedDB|AsyncStorage|SharedPreferences|UserDefaults|CoreData|Realm|"
    r"requests\.post\(\s*(?!https://api\.stripe|https://api\.braintree|https://\w+\.adyen)|axios\.post\(\s*(?!['\"]https://api\.stripe)|fetch\(\s*['\"]/",
    re.I,
)
_PCI_SAFE = re.compile(
    r"\bstripe\b|Stripe\(|braintree|\btokeni[sz]|payment_method(?:_id)?|paymentMethod|paymentIntent|setup_intent|SetupIntent|"
    r"\badyen\b|\bsquare\b|paypal|checkout\.com|mollie|klarna|razorpay|paystack|flutterwave|authorize\.net|worldpay|"
    r"last4|last_four|lastFour|\bmasked|\*{4}|x{4}|bin\b|first6|iin\b|\bencrypt|\bvault|token\b|nonce|"
    r"card_token|cardToken|payment_token|paymentToken|hosted[_\-]?fields|elements\.create|CardElement|PaymentElement|"
    r"\bp2pe\b|hsm|kms|redact|pci",
    re.I,
)


def _card_handling(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    line = ctx.line(line_no)
    field = match.group("field")
    if re.search(r"^\s*(?:import|from|require|#|//|\*)|\.d\.ts|test_|spec\.|describe\(|fixture|placeholder=|label|<label|aria-|i18n|translations?|locale|\.po\b|msgid|className|class=|\bcss\b|style", line, re.I):
        return None
    if re.search(r"last4|last_four|lastFour|masked|\*{4}|x{4}|_token|Token\b|token\b|nonce|encrypted|_hash|hashed|\bbin\b|first6|length|isValid|validate|luhn|regex|pattern|format|mask\(|placeholder|input\b|<input|type=|autocomplete|v-model|onChange|setState|useState|ref\b|\bel\b|querySelector|getElementById|value\s*$", line, re.I):
        return None
    if not _STORE_SINK.search(line):
        return None
    if re.search(r"exp(?:iry|iration)?[_\-]?(?:date|month|year)|card[_\-]?exp|exp_month|exp_year|expiry|expMonth|expYear", field, re.I) and not re.search(r"cvv|cvc|card[_\-]?number|pan\b", ctx.window(line_no, 3, 3), re.I):
        return None
    block = lookbehind(ctx, line_no, 12) + "\n" + line + "\n" + lookahead(ctx, line_no, 6)
    safe = _PCI_SAFE.search(block)
    if safe and re.search(r"stripe|braintree|adyen|square|paypal|checkout\.com|mollie|klarna|razorpay|paystack|flutterwave|authorize\.net|worldpay|tokeni[sz]|payment_method|paymentMethod|paymentIntent|hosted|elements\.create|CardElement|PaymentElement", safe.group(0), re.I) and re.search(r"stripe|braintree|adyen|square|paypal|tokeni[sz]|payment_method|paymentMethod|paymentIntent|elements|CardElement|PaymentElement", line, re.I):
        return None
    is_cvv = bool(re.search(r"cvv|cvc|cvn|\bcid\b|\bcsc\b|security[_\-]?code|verification", field, re.I))
    severity = Severity.CRITICAL if is_cvv else Severity.HIGH
    return make_hit(ctx, line_no, column=match.start() + 1, severity=severity, confidence=90 if not safe else 45,
                    mitigated_by=safe.group(0) if safe else None, skip_sanitizer_check=True,
                    description=("Card verification value (CVV) is stored/logged — forbidden under PCI DSS 3.2." if is_cvv
                                 else f"Primary account number field '{field}' is persisted/logged/transmitted by custom code instead of a PCI-compliant tokenizer."))


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

RULES: tuple[Rule, ...] = (
    # ---- 21. secrets-config ---------------------------------------------- #
    Rule(
        id="SEC-001",
        surface="secrets-config",
        name="Well-known credential format detected",
        description="A token matching a vendor-specific credential format (AWS, GitHub, Stripe, Slack, private key, ...) is present in the tree.",
        severity=Severity.CRITICAL,
        cwe="CWE-798",
        confidence=95,
        file_checker=_token_signatures,
        scan_comments=True,
        recommendation="Revoke and rotate the credential immediately, remove it from history and load it from a secret store.",
        remediation="Rotate at the provider, run git filter-repo to purge history, inject via environment/secrets manager.",
    ),
    Rule(
        id="SEC-002",
        surface="secrets-config",
        name="Hardcoded secret in configuration file",
        description="A configuration key with a credential-like name holds a literal high-entropy value.",
        severity=Severity.CRITICAL,
        cwe="CWE-798",
        confidence=80,
        extensions=CONFIG_EXTS + (".js", ".ts", ".rb", ".php", ".gradle", ".groovy", ".kt", ".swift", ".dart"),
        filename_patterns=(r"(?:^|/)(?:config|settings|application|appsettings|secrets?|credentials?|database|db|local|production|prod|staging|development|dev)[\w.-]*\.(?:json|ya?ml|toml|ini|cfg|conf|properties|xml|plist|py|js|ts|rb|php|env)$",
                           r"(?:^|/)(?:config|settings|conf|etc)/[^/]+$", r"(?:^|/)(?:settings|config|local_settings|secrets)\.py$", r"(?:^|/)wp-config\.php$",
                           r"(?:^|/)docker-compose[\w.-]*\.ya?ml$", r"(?:^|/)compose[\w.-]*\.ya?ml$", r"(?:^|/)values[\w.-]*\.ya?ml$", r"(?:^|/)\.s3cfg$", r"(?:^|/)\.boto$",
                           r"(?:^|/)terraform\.tfvars$", r"(?:^|/)[\w.-]+\.tfvars$", r"(?:^|/)[\w.-]+\.tf$", r"(?:^|/)ansible[\w.-]*/[\w.-]+\.ya?ml$", r"(?:^|/)group_vars/", r"(?:^|/)host_vars/"),
        keywords=("key", "secret", "token", "pass", "pwd", "credential", "auth", "connection", "dsn"),
        patterns=(_CONFIG_ASSIGN,),
        negatives=(r"\$\{|\{\{|%\(|<\w+>|process\.env|os\.environ|getenv|ENV\[|env\(|secretsmanager|vault|ssm:|keyring|valueFrom|secretKeyRef|!secret|!vault|!ENV|\bref\b|@Value|\{\{|"
                   r"required|help|description|placeholder|label|title|example|sample|schema|type\s*[:=]|format|pattern|regex|min|max|length|ttl|expir|rotation|\.example|\.sample|\.dist$"),
        checker=_config_secret,
        scan_comments=False,
        use_surface_indicators=False,
        recommendation="Reference secrets by name (${VAR}, vault paths, secret manager ARNs) and keep values out of committed config.",
        remediation="database: { password: ${DB_PASSWORD} } with the real value supplied by the deployment environment.",
    ),
    Rule(
        id="SEC-003",
        surface="secrets-config",
        name="Cloud credential file or secret bundle committed",
        description="A file that by design contains credentials (service-account JSON, kubeconfig, AWS credentials, keystore) is in the tree.",
        severity=Severity.CRITICAL,
        cwe="CWE-538",
        confidence=85,
        extensions=(".json", ".yaml", ".yml", ".ini", ".toml", ".xml"),
        filename_patterns=(r"(?:^|/)(?:service[_-]?account[\w-]*|[\w-]*-sa|gcp[\w-]*|firebase[\w-]*-adminsdk[\w-]*|google[\w-]*credentials?)\.json$",
                           r"(?:^|/)\.aws/credentials$", r"(?:^|/)kubeconfig$", r"(?:^|/)\.kube/config$", r"(?:^|/)credentials\.(?:json|ya?ml|ini|toml|xml)$",
                           r"(?:^|/)secrets?\.(?:json|ya?ml|toml)$", r"(?:^|/)\.terraformrc$"),
        keywords=("private_key", "client-key-data", "aws_secret_access_key", "\"type\": \"service_account\"", "password", "secret", "token"),
        patterns=(
            r"\"type\"\s*:\s*\"service_account\"",
            r"\"private_key\"\s*:\s*\"-----BEGIN",
            r"client-key-data\s*:\s*[A-Za-z0-9+/=]{40,}",
            r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}",
            r"\"private_key_id\"\s*:\s*\"[a-f0-9]{40}\"",
            r"(?i)(?:password|secret|token)\s*[:=]\s*[\"']?[A-Za-z0-9+/=_\-]{16,}",
        ),
        negatives=(r"\$\{|\{\{|<\w+>|example|sample|placeholder|REDACTED|xxxx"),
        scan_comments=True,
        use_surface_indicators=False,
        recommendation="Remove credential bundles from the repository, rotate them and mount them at deploy time.",
        remediation="Add the file to .gitignore, purge from history and provision it through your secret manager / CI secret files.",
    ),
    # ---- 22. environment-files ------------------------------------------- #
    Rule(
        id="ENV-001",
        surface="environment-files",
        name="Secret value in environment (template) file",
        description="A .env / .env.example style file holds real-looking secrets rather than placeholders.",
        severity=Severity.HIGH,
        cwe="CWE-540",
        confidence=85,
        filename_patterns=(r"(?:^|/)\.env(?:\.[\w-]+)*$", r"(?:^|/)(?:example|sample|template|default)\.env$", r"(?:^|/)env\.(?:example|sample|template|dist)$",
                           r"(?:^|/)\.envrc(?:\.[\w-]+)?$", r"(?:^|/)\.flaskenv$", r"(?:^|/)[\w.-]+\.env$", r"(?:^|/)env\.example\.\w+$"),
        file_checker=_env_files,
        scan_comments=False,
        recommendation="Keep only empty or clearly fake placeholder values in templates; keep real .env files untracked (.gitignore).",
        remediation="DB_PASSWORD=<change-me> in .env.example; rotate any real value that was committed.",
    ),
    Rule(
        id="ENV-002",
        surface="environment-files",
        name="Environment file loaded from an untrusted or public location",
        description="dotenv is configured to load from a web-served directory or to override variables from a committed file.",
        severity=Severity.MEDIUM,
        cwe="CWE-15",
        confidence=75,
        extensions=(".py", ".js", ".ts", ".mjs", ".cjs", ".php", ".rb", ".go"),
        keywords=("dotenv", "load_dotenv", "env", ".env"),
        patterns=(
            r"load_dotenv\s*\(\s*['\"][^'\"]*(?:public|static|www|htdocs|wwwroot|uploads?|tmp)/[^'\"]*['\"]",
            r"dotenv\.config\s*\(\s*\{[^}]*path\s*:\s*['\"`][^'\"`]*(?:public|static|www|htdocs|wwwroot|uploads?|tmp)/",
            r"load_dotenv\s*\([^)]*override\s*=\s*True[^)]*\)\s*(?:#.*)?$",
            r"dotenv\.config\s*\(\s*\{[^}]*override\s*:\s*true",
            r"Dotenv\\Dotenv::create\w*\(\s*(?:\$_SERVER\[['\"]DOCUMENT_ROOT['\"]\]|['\"][^'\"]*(?:public|www|htdocs))",
            r"\.env['\"]\s*\)\s*\.\s*(?:copy|move|upload)|copy\s*\(\s*['\"]\.env['\"]\s*,\s*['\"][^'\"]*(?:public|static|www)",
            r"COPY\s+\.env\s+|ADD\s+\.env\s+",
        ),
        use_surface_indicators=False,
        recommendation="Load .env only from the application root outside the document root and never bake it into images.",
        remediation="Keep .env beside the application entry point, exclude it from Docker context (.dockerignore) and public folders.",
    ),
    # ---- 33. ci-cd -------------------------------------------------------- #
    Rule(
        id="CI-001",
        surface="ci-cd",
        name="Hardcoded credential in CI/CD pipeline definition",
        description="A pipeline file embeds a literal token/password instead of referencing a masked secret.",
        severity=Severity.CRITICAL,
        cwe="CWE-798",
        confidence=90,
        filename_patterns=_CI_FILE,
        keywords=("token", "secret", "password", "passwd", "pwd", "key", "credential", "auth", "login", "-p ", "-u ", "echo", "printf"),
        patterns=(_CI_SECRET_LINE,),
        checker=_ci_secret,
        scan_comments=False,
        use_surface_indicators=False,
        recommendation="Store credentials as encrypted CI secrets and reference them (${{ secrets.NAME }}, $CI_VAR, credentials()).",
        remediation="env: NPM_TOKEN: ${{ secrets.NPM_TOKEN }} — remove the literal and rotate it.",
    ),
    Rule(
        id="CI-002",
        surface="ci-cd",
        name="CI script injection from untrusted event data",
        description="Untrusted GitHub event fields (PR title/body, branch name, comments) are interpolated directly into a run: script.",
        severity=Severity.HIGH,
        cwe="CWE-78",
        confidence=90,
        filename_patterns=(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$", r"(?:^|/)\.gitea/workflows/[^/]+\.ya?ml$", r"(?:^|/)action\.ya?ml$"),
        keywords=("github.event", "github.head_ref", "inputs."),
        patterns=(
            r"^\s*(?:-\s*)?run\s*:[^\n]*\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|workflow_run|inputs)\.[\w.\[\]]*(?:title|body|message|ref|label|name|email|login|html_url|default_branch|value)",
            r"^\s*(?:-\s*)?run\s*:[^\n]*\$\{\{\s*github\.(?:head_ref|event\.workflow_run\.head_branch|event\.pull_request\.head\.(?:ref|label|repo\.\w+))",
            r"^\s*(?:-\s*)?run\s*:[^\n]*\$\{\{\s*(?:github\.event\.)?inputs\.\w+",
            r"^\s*(?:-\s*)?(?:run|script)\s*:\s*\|\s*$",
        ),
        negatives=(r"^\s*#",),
        checker=_ci_injection,
        multiline=False,
        use_surface_indicators=False,
        recommendation="Pass untrusted values through environment variables (env:) and quote them in the shell instead of inline ${{ }} expressions.",
        remediation="env:\n  TITLE: ${{ github.event.pull_request.title }}\nrun: echo \"$TITLE\"",
    ),
    Rule(
        id="CI-003",
        surface="ci-cd",
        name="Insecure CI/CD workflow configuration",
        description="Pipeline settings widen the blast radius: write-all permissions, pull_request_target with PR checkout, unpinned third-party actions, disabled TLS verification, curl|sh installs.",
        severity=Severity.MEDIUM,
        cwe="CWE-1104",
        confidence=85,
        filename_patterns=_CI_FILE,
        keywords=("permissions", "pull_request_target", "uses:", "curl", "wget", "insecure", "no-check-certificate", "gitlab-ci", "privileged", "allow_failure", "image:", "sudo"),
        patterns=(
            r"^\s*permissions\s*:\s*write-all\s*$",
            r"^\s*(?:contents|id-token|packages|actions|deployments|pull-requests|issues|statuses|checks|security-events|pages)\s*:\s*write\s*$(?!.*\n\s*permissions)",
            r"^\s*(?:on\s*:\s*)?(?:-\s*)?pull_request_target\s*:?\s*$",
            r"^\s*ref\s*:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}",
            r"^\s*(?:-\s*)?uses\s*:\s*(?!actions/|github/|docker/|\./|\.\./)[\w.-]+/[\w.\-/]+@(?:main|master|latest|develop|dev|v?\d+)\s*$",
            r"(?:curl|wget)\s+[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b",
            r"(?:--insecure|-k\s|--no-check-certificate|GIT_SSL_NO_VERIFY\s*[:=]\s*(?:1|true)|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['\"]?0|PIP_TRUSTED_HOST|--trusted-host|strict-ssl\s*[=:]\s*false|sslVerify\s*(?:=|:)\s*false)",
            r"^\s*privileged\s*:\s*true\s*$",
            r"^\s*(?:-\s*)?image\s*:\s*['\"]?[\w./-]+(?::latest)?['\"]?\s*$",
            r"^\s*ACTIONS_ALLOW_UNSECURE_COMMANDS\s*:\s*['\"]?true",
            r"^\s*ACTIONS_RUNNER_DEBUG\s*:\s*['\"]?true|^\s*ACTIONS_STEP_DEBUG\s*:\s*['\"]?true",
            r"set-env\s+name=|::set-env::|::add-path::",
            r"^\s*(?:-\s*)?run\s*:[^\n]*(?:echo|printf|cat)\s+[^\n]*\$(?:\{\{\s*secrets\.\w+\s*\}\}|\w*(?:TOKEN|SECRET|PASSWORD|KEY)\w*)",
        ),
        negatives=(r"^\s*#", r"@[a-f0-9]{40}", r"uses\s*:\s*actions/"),
        use_surface_indicators=False,
        recommendation="Grant least-privilege permissions per job, pin actions/images to digests, never check out untrusted PR code with secrets.",
        remediation="permissions: { contents: read }; uses: owner/action@<40-char-sha>; avoid pull_request_target or split untrusted build from privileged deploy.",
    ),
    # ---- 39. source-control ---------------------------------------------- #
    Rule(
        id="VCS-001",
        surface="source-control",
        name="Credentials embedded in repository/remote URL",
        description="A clone/remote/submodule/package URL embeds a username and password or token.",
        severity=Severity.CRITICAL,
        cwe="CWE-522",
        confidence=90,
        extensions=ALL_TEXT + (".gitmodules", ".gitconfig", ".git-credentials", ".npmrc", ".yarnrc", ".pypirc", ".netrc", ".lock", ".sum", ".mod", ".gradle", ".pom", ".csproj", ".sln", ".cabal", ".nix"),
        filename_patterns=_VCS_FILES,
        keywords=("://",),
        patterns=(_VCS_CRED_URL,),
        checker=_vcs_cred_url,
        scan_comments=True,
        use_surface_indicators=False,
        recommendation="Use SSH keys, credential helpers or short-lived tokens injected at runtime; rotate the embedded credential.",
        remediation="git remote set-url origin git@github.com:org/repo.git; rotate the token; purge history with git filter-repo.",
    ),
    Rule(
        id="VCS-002",
        surface="source-control",
        name="Plaintext credential in VCS/package-manager metadata file",
        description="A tooling config file (.git-credentials, .netrc, .npmrc, .pypirc, settings.xml, docker config...) contains a stored credential.",
        severity=Severity.CRITICAL,
        cwe="CWE-522",
        confidence=90,
        filename_patterns=_VCS_FILES,
        keywords=("password", "token", "auth", "secret", "machine", "_auth", "key"),
        patterns=(_VCS_FILE_SECRET,),
        checker=_vcs_file,
        scan_comments=True,
        use_surface_indicators=False,
        recommendation="Never commit tooling credential files; use environment-based tokens and add the files to .gitignore.",
        remediation="Remove the file from the repository, rotate the credential and configure git credential.helper = manager/osxkeychain/libsecret.",
    ),
    Rule(
        id="VCS-003",
        surface="source-control",
        name="Private key material committed to version control",
        description="A private key / keystore file is part of the repository and is cloned by everyone with read access.",
        severity=Severity.HIGH,
        cwe="CWE-321",
        confidence=80,
        path_only=True,
        filename_patterns=(_KEY_MATERIAL_NAME,),
        file_checker=_key_material,
        recommendation="Remove key material from the repository, rotate the keys and distribute them through a secret manager.",
        remediation="git rm --cached <key>; add *.pem / *.key / id_* to .gitignore; regenerate the key pair.",
    ),
    Rule(
        id="VCS-004",
        surface="source-control",
        name="Insecure git credential storage configured",
        description="credential.helper=store keeps plaintext passwords on disk; insecure transport/verification settings weaken clones.",
        severity=Severity.MEDIUM,
        cwe="CWE-256",
        confidence=85,
        extensions=(".gitconfig", ".sh", ".bash", ".zsh", ".yml", ".yaml", ".ps1", ".py", ".dockerfile", ".txt", ".md"),
        filename_patterns=(r"(?:^|/)\.gitconfig$", r"(?:^|/)\.git/config$", r"(?:^|/)gitconfig$", r"(?:^|/)Dockerfile[^/]*$", r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$"),
        keywords=("credential", "sslverify", "git_ssl_no_verify", "http.sslverify", "insteadof", "askpass"),
        patterns=(
            r"credential\.helper\s*[=:]?\s*['\"]?store\b|helper\s*=\s*store\b",
            r"git\s+config\s+(?:--global\s+|--system\s+)?credential\.helper\s+['\"]?store",
            r"http\.sslVerify\s*[=:]?\s*['\"]?false|sslVerify\s*=\s*false",
            r"GIT_SSL_NO_VERIFY\s*[=:]\s*['\"]?(?:1|true)",
            r"url\s*\.\s*['\"]?https?://[^@'\"\s]+:[^@'\"\s]+@",
            r"insteadOf\s*=\s*https?://\S*@",
            r"GIT_ASKPASS\s*=\s*['\"]?echo\b|core\.askPass\s*=\s*echo",
            r"git\s+clone\s+http://",
        ),
        negatives=(r"^\s*#",),
        use_surface_indicators=False,
        recommendation="Use a keychain-backed credential helper and keep TLS verification enabled.",
        remediation="git config --global credential.helper libsecret (or osxkeychain/manager); unset http.sslVerify.",
    ),
    # ---- 15. payment-systems --------------------------------------------- #
    Rule(
        id="PAY-001",
        surface="payment-systems",
        name="Card data handled/stored by custom code (non-PCI)",
        description="Primary account numbers, CVV or expiry fields are persisted, logged, cached or transmitted by application code instead of a PCI-compliant tokenizer.",
        severity=Severity.CRITICAL,
        cwe="CWE-311",
        confidence=90,
        extensions=CODE_EXTS + (".sql", ".prisma", ".graphql", ".proto", ".json", ".yaml", ".yml"),
        keywords=("cvv", "cvc", "cvn", "cid", "csc", "security_code", "securitycode", "card_number", "cardnumber", "cardnum", "credit_card", "creditcard", "cc_num", "ccnum", "pan", "track", "magstripe", "exp_month", "exp_year", "expiry", "expmonth", "expyear", "expiration"),
        patterns=(_CARD_FIELD,),
        negatives=(r"^\s*(?:import|from|require|#|//|\*)", r"\.d\.ts", r"test_|spec\.|describe\(|fixture|mock", r"pan(?:el|ic|da|el|try|e|els|ther|tone|orama|ama|ache|sy|ic|el|t|ts)\b", r"expand|expect|experience|experiment|expert|expensive|explain|export|expose|expression|exponent|expedite"),
        checker=_card_handling,
        recommendation="Never touch raw card data: use hosted fields / client-side tokenization (Stripe Elements, Braintree Hosted Fields) and store only tokens and last4.",
        remediation="Replace card_number/cvv columns with payment_method_id + last4 + brand; delete CVV everywhere (PCI DSS 3.2 forbids storing it).",
    ),
    Rule(
        id="PAY-002",
        surface="payment-systems",
        name="Card number literal or card-number validation implemented by hand",
        description="A full card number literal or custom Luhn/regex validation indicates raw PAN handling outside a PCI-scoped provider.",
        severity=Severity.HIGH,
        cwe="CWE-312",
        confidence=80,
        extensions=CODE_EXTS + (".sql", ".json", ".yaml", ".yml", ".csv", ".txt"),
        patterns=(
            r"(?<![\d.])(?:4\d{3}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}|5[1-5]\d{2}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}|3[47]\d{2}[ -]?\d{6}[ -]?\d{5}|6(?:011|5\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{4})(?![\d.])",
            r"\bluhn\w*\s*\(|def\s+\w*luhn\w*|function\s+\w*luhn\w*|mod\s*10\s*check|checkLuhn|luhnCheck|validateCardNumber|isValidCardNumber|validate_card_number|is_valid_card",
        ),
        negatives=(r"4111[ -]?1111[ -]?1111[ -]?1111|4242[ -]?4242[ -]?4242[ -]?4242|4000[ -]?0000[ -]?0000[ -]?\d{4}|5555[ -]?5555[ -]?5555[ -]?4444|5105[ -]?1051[ -]?0510[ -]?5100|3782[ -]?822463[ -]?10005|3714[ -]?496353[ -]?98431|6011[ -]?1111[ -]?1111[ -]?1117|6011[ -]?0009[ -]?9013[ -]?9424|test|sandbox|example|fixture|mock|dummy|sample|placeholder|phone|tel:|\+\d|order|invoice|tracking|sku|isbn|ean|upc|serial|imei|id\b|uuid|hash|sha|md5|timestamp|epoch|\d{4}-\d{2}-\d{2}|version|port|pid|iban"),
        sanitizers=(r"stripe", r"braintree", r"adyen", r"tokeni[sz]", r"payment_method", r"last4", r"masked", r"\bbin\b", r"\*{4}", r"paymentIntent", r"elements", r"hosted"),
        context_before=6,
        context_after=6,
        recommendation="Delegate card validation and collection to the payment provider's SDK / hosted fields; never handle full PANs.",
        remediation="Use Stripe Elements / Braintree Hosted Fields; remove hand-written card validation and any literal card numbers.",
    ),
    Rule(
        id="PAY-003",
        surface="payment-systems",
        name="Payment provider misconfiguration",
        description="Payment integration settings weaken security: live keys in client code, webhook signature checks disabled, test mode toggles, insecure endpoints.",
        severity=Severity.HIGH,
        cwe="CWE-16",
        confidence=85,
        extensions=CODE_EXTS + CONFIG_EXTS,
        keywords=("stripe", "paypal", "braintree", "adyen", "square", "razorpay", "payment", "checkout", "3ds", "three_d_secure", "webhook", "capture"),
        patterns=(
            r"(?:Stripe|stripe)\s*\(\s*['\"]sk_live_[0-9a-zA-Z]{20,}['\"]",
            r"(?:publishableKey|publishable_key|STRIPE_PUBLISHABLE_KEY)\s*[:=]\s*['\"]sk_(?:live|test)_",
            r"(?:verify_signature|verifySignature|signature_verification|check_signature|validate_webhook)\s*[:=]\s*(?:False|false)",
            r"(?:three_d_secure|threeDSecure|3ds|request_three_d_secure)\s*[:=]\s*['\"]?(?:false|off|never|disabled)",
            r"(?:PAYPAL_MODE|paypal\.mode|mode)\s*[:=]\s*['\"]sandbox['\"](?=.*(?:prod|live))",
            r"api_base\s*=\s*['\"]http://|(?:stripe|paypal|braintree)\.api_base\s*=\s*['\"]http://",
            r"(?:skip|disable|bypass)_(?:payment|fraud|avs|cvv|cvc)_?(?:check|verification|validation)\s*[:=]\s*(?:True|true|1)",
            r"(?:capture|auto_capture|capture_method)\s*[:=]\s*['\"]?(?:false|manual)['\"]?\s*(?:#|//)?.*(?:prod|live)",
            r"amount\s*[:=]\s*(?:request\.(?:json|form|args|POST)|req\.body|params\[|\$_(?:POST|GET))",
            r"(?:price|total|amount)\s*=\s*(?:float|int|Decimal)?\(?\s*(?:request\.(?:json|form|args|POST)|req\.body|params\[|\$_(?:POST|GET))",
        ),
        negatives=(r"^\s*(?:import|from|require|#|//|\*)", r"test|spec|fixture|example"),
        use_surface_indicators=False,
        recommendation="Keep secret keys server-side only, verify webhook signatures, enforce 3DS/AVS/CVC checks and compute amounts server-side.",
        remediation="Load sk_live_* from the environment on the server; compute the charge amount from the cart, never from the request body.",
    ),
)
