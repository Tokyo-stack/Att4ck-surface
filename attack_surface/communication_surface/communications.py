"""Communication surface: SMTP/email flows and notification services
(surfaces 17, 18).
"""

from __future__ import annotations

import re

from attack_surface.analysis import arg_tainted, has_input, lookahead, lookbehind, make_hit
from attack_surface.models import FileContext, Hit, Rule, Severity

CODE_EXTS = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".rb", ".java", ".go", ".cs", ".kt", ".scala", ".swift", ".dart")
CONFIG_EXTS = (".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".xml", ".env", ".txt")

# --------------------------------------------------------------------------- #
# 17. email-flows
# --------------------------------------------------------------------------- #

_HEADER_ASSIGN = re.compile(
    r"(?:(?:msg|message|mail|email|mime|m|headers?|mailer|em)\s*\[\s*['\"](?P<h1>Subject|To|From|Cc|Bcc|Reply-To|Sender|Return-Path|X-[\w-]+)['\"]\s*\]\s*=\s*(?P<v1>.+)$"
    r"|(?:msg|message|mail|email|mime|m)\s*\.\s*(?:add_header|__setitem__|replace_header|setHeader|addHeader|set_header|header)\s*\(\s*['\"](?P<h2>Subject|To|From|Cc|Bcc|Reply-To|Sender|Return-Path|X-[\w-]+)['\"]\s*,\s*(?P<v2>[^)]+)\)"
    r"|\b(?P<h3>subject|to|from_?|cc|bcc|reply_to|replyTo|sender|from_email|to_email|recipient|recipients|to_addrs?)\s*[:=]\s*(?P<v3>(?:f['\"]|['\"][^'\"]*['\"]\s*(?:%|\+|\.format)|request\.|req\.|\$_(?:GET|POST|REQUEST)|params\[|params\.|`[^`]*\$\{)[^,;]*)"
    r"|(?:send_mail|send_mass_mail|mail_admins|mail_managers|EmailMessage|EmailMultiAlternatives|MIMEText|MIMEMultipart|Message|Mail|sendmail|sendMail|send_email|sendEmail|mail|wp_mail|Mail::send|Mail::to|Notification::route|deliver_now|deliver_later|deliver)\s*\(\s*(?P<v4>(?:[^()]*\b(?:request\.(?:form|args|POST|GET|json|values)|req\.(?:body|query|params)|\$_(?:GET|POST|REQUEST)|params\[)[^()]*))"
    r"|\bmail\s*\(\s*(?P<v5>[^,]*\$_(?:GET|POST|REQUEST)[^,]*),"
    r"|\bmail\s*\(\s*[^,]+,\s*(?P<v6>[^,]*\$_(?:GET|POST|REQUEST)[^,]*),"
    r"|\bmail\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*(?P<v7>[^)]*\$(?:_(?:GET|POST|REQUEST)|headers?)[^)]*)\)"
    r"|(?:\$headers?\s*\.?=\s*(?P<v8>.*\$_(?:GET|POST|REQUEST).*)$))",
    re.I,
)
_HEADER_SAFE = re.compile(
    r"\\r|\\n|replace\(\s*['\"]\\[rn]|\.strip\(\)|\.strip\(|\bsanitize|validate_email|email_validator|EmailValidator|BadHeaderError|"
    r"re\.sub\(|\.split\(\s*['\"]\\n|\bHeader\(|filter_var\(|FILTER_VALIDATE_EMAIL|\bpreg_replace\(|\bstr_replace\(|\bescape|"
    r"newline|line_break|crlf|CRLF|header_injection|is_valid_email|validate_address|parseaddr|formataddr|"
    r"email\.utils|address\.parse|EmailAddress|MailAddress\(|InternetAddress\(|mail\.parseAddress|"
    r"validator\.isEmail|isEmail\(|\bz\.string\(\)\.email|Joi\.string\(\)\.email|@validates|schema|"
    r"\.match\(\s*/\^\[|re\.(?:match|fullmatch)\(|EMAIL_REGEX|email_regex|\bindexOf\(\s*['\"]\\n|includes\(\s*['\"]\\n|"
    r"\bencode\(|encodeURIComponent|quopri|base64|\bsubject\s*=\s*_\(|gettext|Encode\.forJava|Encoders",
    re.I,
)


def _header_injection(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    line = ctx.line(line_no)
    if re.search(r"^\s*(?:import|from|require|#|//|\*)|test_|spec\.|describe\(|\.d\.ts|logger|print\(", line, re.I):
        return None
    value = next((match.group(g) for g in ("v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8") if match.groupdict().get(g)), "") or ""
    header = next((match.group(g) for g in ("h1", "h2", "h3") if match.groupdict().get(g)), "header")
    value = value.strip().rstrip(";,")
    if not value:
        return None
    if re.fullmatch(r"(?:'[^']*'|\"[^\"]*\")\s*(?:,.*)?", value) and not re.search(r"\+|%|\.format", value):
        return None
    if re.search(r"settings\.|config\.|os\.environ|getenv|process\.env|DEFAULT_FROM|EMAIL_HOST_USER|SERVER_EMAIL|ADMINS|MANAGERS|_\(|gettext|\bconst\b|\$\{\s*(?:process|config)", value):
        return None
    tainted = has_input(value) or arg_tainted(ctx, line_no, value, lookback=25)
    if not tainted and not re.search(r"\b(?:name|email|subject|message|body|title|user|username|address|to|from|recipient|comment|text|input|data|form|payload)\w*\b", value, re.I):
        return None
    if not tainted and not re.search(r"def\s+\w+\s*\([^)]*\b(?:request|req|params|form|data|payload)\b|\(\s*(?:req|request)\b|params\[|request\.|req\.", lookbehind(ctx, line_no, 25), re.I):
        return None
    block = lookbehind(ctx, line_no, 20) + "\n" + ctx.statement(line_no, 6) + "\n" + lookahead(ctx, line_no, 6)
    safe = _HEADER_SAFE.search(block)
    if safe and re.search(r"BadHeaderError|validate_email|email_validator|EmailValidator|FILTER_VALIDATE_EMAIL|isEmail|parseaddr|formataddr|MailAddress|InternetAddress|EmailAddress|\.email\(\)", safe.group(0), re.I) and re.search(r"subject|to|from|cc|bcc|reply", header, re.I):
        # Address validation covers address headers fully; subject still needs newline stripping.
        if not re.search(r"subject", header, re.I) or re.search(r"\\r|\\n|newline|CRLF|strip|replace", block, re.I):
            return None
    return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by=safe.group(0) if safe else None, skip_sanitizer_check=True,
                    confidence=88 if tainted and not safe else (70 if not safe else 40),
                    severity=Severity.HIGH if tainted and not safe else Severity.MEDIUM,
                    description=f"Email header '{header}' is built from request data; CR/LF sequences let an attacker inject extra headers/recipients (email header injection).")


def _smtp_plaintext(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    block = lookbehind(ctx, line_no, 6) + "\n" + ctx.statement(line_no, 6) + "\n" + lookahead(ctx, line_no, 20)
    if re.search(r"starttls\(|SMTP_SSL|smtps://|secure\s*:\s*true|requireTLS\s*:\s*true|ssl\s*[:=]\s*True|tls\s*[:=]\s*True|use_tls\s*[:=]\s*True|EMAIL_USE_TLS\s*=\s*True|EMAIL_USE_SSL\s*=\s*True|MAIL_USE_TLS\s*=\s*True|MAIL_USE_SSL\s*=\s*True|enable_starttls_auto|:465\b|port\s*[:=]\s*465|port\s*[:=]\s*587|ssl:\s*true|tls:\s*\{|smtp\.SendMail\(|STARTTLS|StartTLS|EnableSsl\s*=\s*true|mail\.smtp\.starttls\.enable|localhost|127\.0\.0\.1|mailhog|mailpit|maildev|mailcatcher|sendmail_path|@sendgrid|@mailgun|@postmark|@ses", block, re.I):
        return None
    return make_hit(ctx, line_no, column=match.start() + 1, skip_sanitizer_check=True)


# --------------------------------------------------------------------------- #
# 18. notification-services
# --------------------------------------------------------------------------- #

_NOTIFY_CALL = re.compile(
    r"\b(?P<api>messages\.create|client\.messages\.create|twilio\.messages\.create|sns\.publish|snsClient\.publish|PublishCommand|"
    r"send_sms|sendSms|sendSMS|sms\.send|sms_send|send_text|sendText|text_message|Nexmo|Vonage|vonage\.sms\.send|"
    r"plivo|\.send_message\(|sendMessage\(|bot\.send_message|bot\.sendMessage|chat_postMessage|chat\.postMessage|"
    r"postMessage\(|slack_sdk|WebClient\(|webhook\.send|IncomingWebhook|discord\.send|channel\.send|"
    r"push\.send|pushNotification|send_push|sendPush|fcm\.send|messaging\(\)\.send|messaging\.send|admin\.messaging|"
    r"apns|APNs|OneSignal|onesignal|pusher\.trigger|Pusher\.trigger|notify\(|notification\.send|Notification::send|"
    r"notifications\.send|send_notification|sendNotification|telegram\.send|telegram_send|"
    r"WhatsApp|whatsapp|messagebird|clicksend|sinch\.|textmagic|smsapi|termii|africastalking|"
    r"pushbullet|pushover|ntfy|gotify|expo\.sendPushNotifications|Expo\.|notifee|Notifier|"
    r"mail\.send\(|sendgrid|SendGridAPIClient|sg\.send|ses\.send_email|sesClient\.sendEmail|mailgun|postmark|resend\.emails\.send|"
    r"transporter\.sendMail|smtp\.sendmail|server\.sendmail|send_mail\(|send_email\(|sendEmail\(|deliver_now|deliver_later|Mail::send|wp_mail\()\s*\(?",
    re.I,
)
_NOTIFY_SENSITIVE = re.compile(
    r"\b(?P<kind>(?:password|passwd|pwd|temp(?:orary)?_?pass\w*|new_?password|initial_?password|secret|api[_-]?key|apikey|private[_-]?key|"
    r"access[_-]?token|refresh[_-]?token|auth[_-]?token|bearer|jwt|session[_-]?id|session[_-]?token|"
    r"card[_-]?number|cardnumber|cvv|cvc|\bpan\b|account[_-]?number|iban|routing[_-]?number|ssn|social[_-]?security|"
    r"otp|one[_-]?time[_-]?(?:code|password|pin)|verification[_-]?code|verify[_-]?code|auth[_-]?code|login[_-]?code|"
    r"2fa|mfa|two[_-]?factor|totp|\bpin\b|pin[_-]?code|passcode|security[_-]?code|reset[_-]?(?:token|code|link)|"
    r"activation[_-]?(?:code|link|token)|magic[_-]?link|invite[_-]?token|recovery[_-]?(?:code|key)|backup[_-]?code|"
    r"balance|salary|diagnosis|medical|prescription|credit[_-]?score|tax[_-]?id|passport|licen[cs]e[_-]?number))\b",
    re.I,
)
_NOTIFY_SAFE = re.compile(
    r"\bencrypt|\bmasked|\*{3,}|last4|last_four|\bredact|\bhash|\bexpires?_?(?:in|at)|\bttl\b|one_time|single_use|"
    r"\bwarning|do not share|never share|will expire|\bexpir|template_id|templateId|dynamic_template|"
    r"\.format\(\s*\)|i18n|gettext|_\(|\{\{\s*\w+\s*\}\}",
    re.I,
)
_HIGH_RISK = re.compile(r"password|passwd|pwd|secret|api[_-]?key|apikey|private[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|bearer|jwt|session|card|cvv|cvc|\bpan\b|account[_-]?number|iban|routing|ssn|social|balance|salary|diagnosis|medical|prescription|credit[_-]?score|tax[_-]?id|passport|licen[cs]e", re.I)


def _notification(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    line = ctx.line(line_no)
    if re.search(r"^\s*(?:import|from|require|#|//|\*)|test_|spec\.|describe\(|\.d\.ts|mock|stub|fixture", line, re.I):
        return None
    statement = ctx.statement(line_no, 10)
    before = lookbehind(ctx, line_no, 12)
    scope = before + "\n" + statement
    # Where does the message text come from?
    body_vars = re.findall(r"(?:body|message|text|msg|content|Message|Body|Text|notification|payload|data|title|subject|html|template)\s*[:=]\s*([^,\n]+)", statement)
    sensitive = _NOTIFY_SENSITIVE.search(statement)
    if not sensitive:
        # Check message variables built just above the call.
        for candidate in re.findall(r"\b(\w+)\b", " ".join(body_vars)):
            assign = re.search(rf"\b{re.escape(candidate)}\s*=\s*(.+)", before)
            if assign:
                sensitive = _NOTIFY_SENSITIVE.search(assign.group(1))
                if sensitive:
                    break
    if not sensitive:
        sensitive = _NOTIFY_SENSITIVE.search("\n".join(ln for ln in before.split("\n")[-6:] if re.search(r"(?:body|message|text|msg|content)\s*=|f['\"]|`|\+", ln)))
    if not sensitive:
        return None
    kind = sensitive.group(0)
    # The message body must be dynamic (interpolation/concatenation/template), not a static string.
    if not re.search(r"\+|\$\{|`|\.format|%s|%\(|f['\"]|\{[^}]*\}|:\s*\w+[.\[]|=\s*\w+\.", scope):
        return None
    if re.search(r"\b(?:password|passwd|pwd)_?(?:reset|changed|updated|expired|policy|hint|rules|strength)\b|(?:reset|forgot)_?password_?(?:url|link)|has been (?:changed|reset|updated)", statement, re.I) and not re.search(r"\{[^}]*(?:password|pwd)\b[^}]*\}|\+\s*(?:password|new_password|temp_password)", statement, re.I):
        return None
    safe = _NOTIFY_SAFE.search(scope)
    high = bool(_HIGH_RISK.search(kind))
    if high:
        severity, confidence = Severity.HIGH, 88
        desc = f"Sensitive value '{kind}' is sent in plaintext through a notification channel (SMS/push/chat/email are unencrypted and logged by providers)."
    else:
        severity, confidence = Severity.MEDIUM, 75
        desc = f"One-time code '{kind}' is delivered over an unencrypted notification channel; ensure it is short-lived, single-use and rate-limited."
    if safe and not high:
        return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by=safe.group(0), confidence=35, severity=Severity.LOW, skip_sanitizer_check=True, description=desc)
    return make_hit(ctx, line_no, column=match.start() + 1, severity=severity, confidence=confidence if not safe else 55,
                    mitigated_by=safe.group(0) if safe and re.search(r"encrypt|masked|\*{3,}|last4|redact|hash", safe.group(0), re.I) else None,
                    skip_sanitizer_check=True, description=desc)


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

RULES: tuple[Rule, ...] = (
    # ---- 17. email-flows -------------------------------------------------- #
    Rule(
        id="EMAIL-001",
        surface="email-flows",
        name="Email header injection from request data",
        description="Subject/To/From/Cc headers or raw sendmail/mail() arguments are built from user input without stripping CR/LF, enabling header injection and spam relaying.",
        severity=Severity.HIGH,
        cwe="CWE-93",
        confidence=85,
        extensions=CODE_EXTS,
        keywords=("subject", "to", "from", "cc", "bcc", "reply", "sender", "recipient", "mail", "sendmail", "mime", "header", "email", "deliver"),
        patterns=(_HEADER_ASSIGN,),
        checker=_header_injection,
        recommendation="Validate addresses (email-validator), strip CR/LF from every header value and use the framework mailer (which raises on newlines) instead of raw SMTP strings.",
        remediation="subject = request.form['subject'].replace('\\r', '').replace('\\n', ' ')[:200]; validate_email(to_addr); send_mail(subject, body, from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=[to_addr])",
    ),
    Rule(
        id="EMAIL-002",
        surface="email-flows",
        name="SMTP connection without TLS",
        description="Mail is submitted over plaintext SMTP (no STARTTLS/SMTPS), exposing credentials and message content on the wire.",
        severity=Severity.MEDIUM,
        cwe="CWE-319",
        confidence=80,
        extensions=CODE_EXTS + CONFIG_EXTS,
        keywords=("smtp", "mail_use_tls", "email_use_tls", "mail_use_ssl", "secure", "starttls", "smtp.host", "smtp_host", "mail_port", "email_port", "nodemailer", "phpmailer", "smtpclient", "enablessl"),
        patterns=(
            r"\bsmtplib\.SMTP\s*\(",
            r"\bsmtp\.NewClient\s*\(|\bsmtp\.Dial\s*\(",
            r"new\s+SmtpClient\s*\([^)]*\)\s*(?:\{[^}]*EnableSsl\s*=\s*false|;\s*$)",
            r"(?:EMAIL|MAIL)_USE_(?:TLS|SSL)\s*[:=]\s*(?:False|false|0)\b",
            r"(?:SMTP|smtp|mail|MAIL)_?(?:TLS|SSL|SECURE|tls|ssl|secure)\s*[:=]\s*(?:False|false|0|off|none)\b",
            r"secure\s*:\s*false\s*,?\s*(?://.*)?$(?=[\s\S]{0,300}(?:host|port|smtp))",
            r"(?:ignoreTLS|ignore_tls)\s*[:=]\s*(?:true|True)|(?:requireTLS|require_tls)\s*[:=]\s*(?:false|False)",
            r"\$mail->SMTPSecure\s*=\s*(?:false|''|\"\")|SMTPSecure\s*=>\s*(?:false|''|\"\")|\$mail->SMTPAutoTLS\s*=\s*false",
            r"mail\.smtp\.starttls\.enable\s*[:=]\s*false|mail\.smtp\.ssl\.enable\s*[:=]\s*false",
            r"(?:tls|ssl)\s*:\s*\{\s*rejectUnauthorized\s*:\s*false",
            r"openssl_verify_mode\s*:\s*['\"]?none|OpenSSL::SSL::VERIFY_NONE|enable_starttls_auto\s*:\s*false",
            r"(?:EMAIL|MAIL|SMTP)_PORT\s*[:=]\s*['\"]?25\b",
            r"port\s*[:=]\s*25\s*,?\s*(?:#|//|$)(?=[\s\S]{0,300}(?:smtp|mail))",
        ),
        negatives=(r"^\s*(?:import|from|require|#|//|\*)", r"SMTP_SSL|smtps://|localhost|127\.0\.0\.1|mailhog|mailpit|maildev|mailcatcher|test_|spec\.|\.example|\.sample|:465|:587"),
        checker=_smtp_plaintext,
        use_surface_indicators=False,
        recommendation="Use SMTPS (465) or STARTTLS (587) with certificate verification; never disable TLS for production mail relays.",
        remediation="with smtplib.SMTP(host, 587) as s: s.starttls(context=ssl.create_default_context()); s.login(user, password)",
    ),
    Rule(
        id="EMAIL-003",
        surface="email-flows",
        name="Insecure email flow configuration",
        description="Mail settings that enable abuse: open relays, credentials in URLs, unrestricted recipients, HTML from user input, unsubscribe/verification tokens predictable, SPF/DKIM disabled.",
        severity=Severity.MEDIUM,
        cwe="CWE-20",
        confidence=80,
        extensions=CODE_EXTS + CONFIG_EXTS,
        keywords=("smtp", "mail", "relay", "html_message", "html", "recipient", "dkim", "spf", "unsubscribe", "verification", "mynetworks", "smtpd_recipient_restrictions", "sendmail", "mail_from", "from_email", "allow_relay"),
        patterns=(
            r"\bsmtps?://[^:/\s'\"]+:[^@/\s'\"]{3,}@",
            r"(?:mynetworks|smtpd_relay_restrictions|relay_domains)\s*=\s*[^\n]*(?:0\.0\.0\.0/0|permit\b(?!_)|\ball\b)",
            r"smtpd_recipient_restrictions\s*=\s*(?:permit\b|$)",
            r"(?:allow_relay|open_relay|relay_all|ALLOW_RELAY)\s*[:=]\s*(?:true|True|1|yes)",
            r"(?:html_message|html_body|html|HtmlBody|body_html|isHtml|IsBodyHtml)\s*[:=(]\s*(?:request\.(?:form|POST|json|args)|req\.body|\$_(?:POST|GET)|params\[)",
            r"send_mail\([^)]*recipient_list\s*=\s*(?:request\.(?:form|POST|json)|req\.body|params\[)",
            r"(?:to|recipients?|to_email|to_addrs?)\s*[:=]\s*(?:request\.(?:form|POST|json|args|values)(?:\.get(?:list)?\()?\s*\[?\s*['\"](?:to|email|recipient|recipients)['\"]|req\.body\.(?:to|email|recipients?)|\$_(?:POST|GET)\[['\"](?:to|email)['\"]\]|params\[:(?:to|email)\])",
            r"(?:from_email|from_addr|sender|From|mail_from|MAIL_FROM|setFrom|from)\s*[:=(]\s*(?:request\.(?:form|POST|json|args)|req\.body|\$_(?:POST|GET)|params\[)",
            r"(?:verification|confirm|confirmation|unsubscribe|activation|reset)_?(?:token|code|key)\s*=\s*(?:str\(\s*)?(?:random\.(?:randint|choice|random)|Math\.random|uuid\.uuid1|md5\(|hashlib\.md5|time\.time\(\)|Date\.now\(\)|user\.id|user_id|\w+\.id\b|base64\.b64encode\(\s*(?:email|user))",
            r"(?:dkim|DKIM|spf|SPF)_?(?:enabled|ENABLED|sign|SIGN|check|CHECK|verify|VERIFY)\s*[:=]\s*(?:false|False|0|no|off)\b",
            r"(?:EMAIL|MAIL)_BACKEND\s*=\s*['\"]django\.core\.mail\.backends\.(?:console|filebased|dummy)\.EmailBackend['\"]",
            r"(?:MAIL|EMAIL|SMTP)_(?:PASSWORD|PASS|PWD)\s*[:=]\s*['\"][^'\"$%{<]{6,}['\"]",
            r"(?:smtp|mail)\.(?:login|auth)\s*\(\s*['\"][^'\"]+['\"]\s*,\s*['\"][^'\"$%{<]{4,}['\"]\s*\)",
            r"auth\s*:\s*\{\s*user\s*:\s*['\"][^'\"]+['\"]\s*,\s*pass\s*:\s*['\"][^'\"$%{<]{4,}['\"]",
            r"\$mail->Password\s*=\s*['\"][^'\"$%{<]{4,}['\"]",
        ),
        negatives=(r"^\s*(?:import|from|require|#|//|\*)", r"test_|spec\.|\.example|\.sample|example\.com|localhost|127\.0\.0\.1|os\.environ|getenv|process\.env|\$\{|\{\{|<\w+>|xxx|changeme|placeholder"),
        sanitizers=(r"validate_email", r"email_validator", r"EmailValidator", r"BadHeaderError", r"bleach", r"sanitize", r"escape", r"secrets\.", r"token_urlsafe", r"SystemRandom", r"hmac", r"itsdangerous", r"signing\.", r"allowlist", r"ALLOWED_RECIPIENTS", r"if\s+.*endswith\(\s*['\"]@", r"rate_?limit", r"throttle"),
        context_before=6,
        context_after=8,
        recommendation="Restrict relays, keep mail credentials in secrets, never take sender/recipient/HTML directly from requests, generate tokens with a CSPRNG and sign outgoing mail (SPF/DKIM/DMARC).",
        remediation="token = secrets.token_urlsafe(32); recipients validated against the account owner; from_email = settings.DEFAULT_FROM_EMAIL; enable DKIM signing in the MTA.",
    ),
    # ---- 18. notification-services --------------------------------------- #
    Rule(
        id="NOTIF-001",
        surface="notification-services",
        name="Sensitive data sent in plaintext notification (SMS/push/chat/email)",
        description="Passwords, tokens, card/account data, medical or financial details, or one-time codes are placed in the body of an SMS, push, chat or email notification.",
        severity=Severity.HIGH,
        cwe="CWE-319",
        confidence=85,
        extensions=CODE_EXTS,
        keywords=("messages.create", "publish", "sms", "send_text", "sendtext", "nexmo", "vonage", "plivo", "send_message", "sendmessage", "postmessage", "slack", "webhook", "discord", "channel.send", "push", "fcm", "messaging", "apns", "onesignal", "pusher", "notify", "notification", "telegram", "whatsapp", "messagebird", "clicksend", "sinch", "textmagic", "smsapi", "termii", "africastalking", "pushbullet", "pushover", "ntfy", "gotify", "expo", "notifee", "notifier", "mail.send", "sendgrid", "ses.", "mailgun", "postmark", "resend", "sendmail", "send_mail", "send_email", "sendemail", "deliver", "wp_mail"),
        patterns=(_NOTIFY_CALL,),
        negatives=(r"^\s*(?:import|from|require|#|//|\*)", r"\.d\.ts"),
        checker=_notification,
        recommendation="Send only references (links to authenticated pages) or short-lived, single-use codes; never transmit passwords, tokens, card or health/financial data via SMS/push/chat.",
        remediation="Replace the credential in the message with a time-limited magic link, generate OTPs with secrets.choice and expire them within minutes; enforce rate limits.",
    ),
    Rule(
        id="NOTIF-002",
        surface="notification-services",
        name="Notification provider credential or webhook URL hardcoded",
        description="Twilio/Slack/Discord/Teams/Firebase/Pusher credentials or incoming webhook URLs are embedded in source, letting anyone send notifications as the application.",
        severity=Severity.HIGH,
        cwe="CWE-798",
        confidence=90,
        extensions=CODE_EXTS + CONFIG_EXTS + (".md", ".html", ".sh"),
        keywords=("hooks.slack.com", "discord.com/api/webhooks", "discordapp.com/api/webhooks", "webhook.office.com", "twilio", "auth_token", "account_sid", "onesignal", "pusher", "server_key", "aaaa", "fcm", "pushover", "telegram", "bot", "chat.googleapis.com", "hooks.zapier.com", "api.telegram.org/bot"),
        patterns=(
            r"https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{16,}",
            r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{15,}/[A-Za-z0-9_\-]{40,}",
            r"https://[\w.-]+\.webhook\.office\.com/webhookb2/[A-Za-z0-9@\-]{20,}",
            r"https://chat\.googleapis\.com/v1/spaces/[\w\-]+/messages\?key=[A-Za-z0-9_\-]{20,}",
            r"https://hooks\.zapier\.com/hooks/catch/\d+/[A-Za-z0-9]{5,}",
            r"https://api\.telegram\.org/bot\d{8,10}:AA[0-9A-Za-z_\-]{33}",
            r"\bAC[0-9a-f]{32}\b(?=[\s\S]{0,200}(?:auth_token|authToken|TWILIO_AUTH_TOKEN)\s*[:=]\s*['\"][0-9a-f]{32}['\"])",
            r"(?:TWILIO_AUTH_TOKEN|twilio_auth_token|auth_token|authToken)\s*[:=]\s*['\"][0-9a-f]{32}['\"]",
            r"(?:PUSHER_SECRET|pusher_secret|app_secret)\s*[:=]\s*['\"][0-9a-f]{20,}['\"]",
            r"(?:ONESIGNAL_REST_API_KEY|onesignal_api_key|rest_api_key)\s*[:=]\s*['\"][A-Za-z0-9_\-]{40,}['\"]",
            r"(?:FCM_SERVER_KEY|fcm_server_key|server_key|SERVER_KEY)\s*[:=]\s*['\"]AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}['\"]",
            r"key\s*=\s*AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}",
            r"(?:PUSHOVER|pushover)_?(?:TOKEN|token|USER|user|api_token|user_key)\s*[:=]\s*['\"][A-Za-z0-9]{30}['\"]",
            r"(?:VONAGE|NEXMO)_API_SECRET\s*[:=]\s*['\"][A-Za-z0-9]{16}['\"]",
            r"(?:MESSAGEBIRD|messagebird)_?(?:ACCESS_KEY|access_key|api_key)\s*[:=]\s*['\"][A-Za-z0-9]{25}['\"]",
        ),
        negatives=(r"^\s*(?:#|//|\*)", r"XXXX|xxxx|example|placeholder|\$\{|\{\{|<\w+>|your[_-]|REDACTED|00000000|T00000000|B00000000|test_|spec\.|fixture"),
        scan_comments=True,
        use_surface_indicators=False,
        recommendation="Treat webhook URLs and provider tokens as secrets: inject them from the environment/secret manager and rotate the exposed ones.",
        remediation="SLACK_WEBHOOK_URL = os.environ['SLACK_WEBHOOK_URL']; regenerate the webhook in Slack/Discord/Teams after removal from history.",
    ),
    Rule(
        id="NOTIF-003",
        surface="notification-services",
        name="Notification endpoint without verification or rate limiting",
        description="Handlers that trigger SMS/push/email take the destination or content from the request without ownership checks or throttling (SMS pumping, spam relay, notification bombing).",
        severity=Severity.MEDIUM,
        cwe="CWE-799",
        confidence=75,
        extensions=CODE_EXTS,
        keywords=("messages.create", "send_sms", "sendsms", "sms.send", "publish", "send_push", "sendpush", "notify", "send_notification", "sendnotification", "send_mail", "send_email", "sendemail", "sendmail", "deliver", "postmessage", "chat_postmessage"),
        patterns=(
            r"(?:messages\.create|send_sms|sendSms|sendSMS|sms\.send|sns\.publish|send_push|sendPush|send_notification|sendNotification|notify|send_mail|send_email|sendEmail|sendMail|transporter\.sendMail|deliver_now|deliver_later)\s*\(\s*[^)]*\b(?:to|phone|phone_number|phoneNumber|number|recipient|email|to_email|to_number|PhoneNumber|TargetArn|Endpoint)\s*[:=]\s*(?:request\.(?:form|args|POST|GET|json|data|values)|req\.(?:body|query|params)|\$_(?:GET|POST|REQUEST)|params\[|params\.|body\.|data\[|data\.|payload\.|json\[|json\.|args\.|form\.)",
            r"(?:messages\.create|send_sms|sendSms|sms\.send|sns\.publish|send_push|send_notification|notify|send_mail|send_email|sendEmail|sendMail|transporter\.sendMail)\s*\(\s*(?:request\.(?:form|args|POST|GET|json|data)|req\.(?:body|query|params)|\$_(?:GET|POST|REQUEST)|params\[)",
        ),
        negatives=(r"^\s*(?:import|from|require|#|//|\*)", r"test_|spec\.|describe\(|mock"),
        sanitizers=(r"rate_?limit", r"ratelimit", r"throttle", r"Throttle", r"limiter", r"Limiter", r"@limiter", r"slowapi", r"express-rate-limit", r"rack-attack", r"Rack::Attack", r"captcha", r"recaptcha", r"hcaptcha", r"turnstile", r"current_user", r"request\.user", r"req\.user", r"g\.user", r"get_jwt_identity", r"session\[", r"\.owner\b", r"user\.phone", r"user\.email", r"user\.phone_number", r"verified", r"is_verified", r"phone_verified", r"email_verified", r"allowlist", r"whitelist", r"cooldown", r"backoff", r"max_attempts", r"attempts", r"lookup\(\s*phone", r"phonenumbers\.", r"E164", r"validate_phone", r"is_valid_number"),
        context_before=25,
        context_after=15,
        use_surface_indicators=False,
        recommendation="Send only to destinations owned by the authenticated user (stored + verified), validate numbers/addresses, add per-user and per-IP rate limits plus CAPTCHA on unauthenticated flows.",
        remediation="to = current_user.verified_phone (never request data); @limiter.limit('3/hour') on the endpoint; verify country allow-list for SMS.",
    ),
)
