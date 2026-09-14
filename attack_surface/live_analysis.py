"""Live HTTP security-posture analysis for the ``crawl`` command.

The static engine reviews *source code*; this module reviews the *running
site*. Given the :class:`~attack_surface.web_crawler.PageRecord` snapshots the
crawler collects (status, response headers, ``Set-Cookie`` headers and HTML),
it produces standard :class:`~attack_surface.models.Finding` objects mapped
onto the existing 40 attack surfaces, so live findings flow through the same
risk engine and exporters as static findings.

Checks are non-intrusive (they only read what the crawler already fetched) and
sanitization-aware: a hardened response simply yields no finding for that
control. Every finding is de-duplicated so a repeated header issue across many
pages is reported once, against a representative URL.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from attack_surface.models import Finding, Severity, Status, finding_id
from attack_surface.risk_engine import calculate_risk_score
from attack_surface.rules import SURFACE_BY_KEY


@dataclass(slots=True)
class LiveCheck:
    """A single HTTP-posture check result before it becomes a Finding."""

    rule_id: str
    surface: str
    name: str
    description: str
    severity: Severity
    confidence: int
    location: str
    evidence: str
    recommendation: str
    remediation: str
    mitigated_by: str | None = None
    cwe: str | None = None


def _finding_from_check(check: LiveCheck) -> Finding:
    surface = SURFACE_BY_KEY[check.surface]
    base_severity = check.severity
    status = Status.VULNERABLE
    severity = base_severity
    confidence = check.confidence
    mitigation = None
    if check.mitigated_by:
        status = Status.POTENTIALLY_MITIGATED
        severity = base_severity.downgrade()
        confidence = max(10, confidence - 25)
        mitigation = check.mitigated_by
    evidence = check.evidence.strip()[:300]
    return Finding(
        id=finding_id(check.rule_id, check.location, 0, evidence),
        rule_id=check.rule_id,
        surface=surface.key,
        surface_number=surface.number,
        surface_name=surface.name,
        package=surface.package,
        name=check.name,
        description=check.description,
        severity=severity,
        base_severity=base_severity,
        confidence=int(confidence),
        status=status,
        cwe=check.cwe or surface.cwe,
        file=check.location,
        line=0,
        column=0,
        snippet=evidence,
        recommendation=check.recommendation,
        remediation=check.remediation,
        mitigation=mitigation,
        risk_score=calculate_risk_score(severity, int(confidence), status is Status.POTENTIALLY_MITIGATED),
        tags=("live", "http"),
    )


# --------------------------------------------------------------------------- #
# Header-based checks (evaluated against the seed / representative page)
# --------------------------------------------------------------------------- #

# Security response headers: (header, surface, severity, cwe, name, remediation).
_SECURITY_HEADERS: tuple[tuple[str, str, Severity, str, str, str], ...] = (
    (
        "strict-transport-security", "server-config", Severity.MEDIUM, "CWE-319",
        "HTTP Strict Transport Security (HSTS) not set",
        "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' on HTTPS responses.",
    ),
    (
        "content-security-policy", "frontend-assets", Severity.MEDIUM, "CWE-693",
        "Content-Security-Policy header missing",
        "Define a restrictive CSP (default-src 'self'; object-src 'none'; frame-ancestors 'none') to contain XSS/injection.",
    ),
    (
        "x-content-type-options", "server-config", Severity.LOW, "CWE-693",
        "X-Content-Type-Options: nosniff not set",
        "Send 'X-Content-Type-Options: nosniff' to stop MIME sniffing.",
    ),
    (
        "x-frame-options", "server-config", Severity.LOW, "CWE-1021",
        "Clickjacking protection missing (no X-Frame-Options / frame-ancestors)",
        "Set 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
    ),
    (
        "referrer-policy", "server-config", Severity.INFO, "CWE-200",
        "Referrer-Policy header not set",
        "Send 'Referrer-Policy: strict-origin-when-cross-origin' (or stricter) to limit referrer leakage.",
    ),
)

# Headers that disclose implementation/version detail.
_DISCLOSURE_HEADERS: tuple[str, ...] = ("server", "x-powered-by", "x-aspnet-version", "x-generator")

_VERSION_RE = re.compile(r"\d+\.\d+")


def _ci(headers: dict[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def _check_security_headers(record, is_https: bool) -> list[LiveCheck]:  # noqa: ANN001
    headers = _ci(record.headers)
    checks: list[LiveCheck] = []
    csp = headers.get("content-security-policy", "")
    for header, surface, severity, cwe, name, remediation in _SECURITY_HEADERS:
        if header == "strict-transport-security" and not is_https:
            continue  # HSTS only meaningful over HTTPS
        present = header in headers
        # X-Frame-Options is satisfied by a CSP frame-ancestors directive.
        if header == "x-frame-options" and "frame-ancestors" in csp.lower():
            present = True
        if present:
            continue
        checks.append(LiveCheck(
            rule_id=f"LIVE-HDR-{header.upper()}",
            surface=surface,
            name=name,
            description=f"The response for {record.final_url} does not set the '{header}' security header.",
            severity=severity,
            confidence=85,
            location=record.final_url,
            evidence=f"missing response header: {header}",
            recommendation="Add the missing security header at the web server / framework / CDN edge.",
            remediation=remediation,
            cwe=cwe,
        ))
    return checks


def _check_disclosure(record) -> list[LiveCheck]:  # noqa: ANN001
    headers = _ci(record.headers)
    checks: list[LiveCheck] = []
    for header in _DISCLOSURE_HEADERS:
        value = headers.get(header)
        if not value:
            continue
        discloses_version = bool(_VERSION_RE.search(value))
        checks.append(LiveCheck(
            rule_id=f"LIVE-DISCLOSE-{header.upper()}",
            surface="server-config",
            name=f"Technology/version disclosure via '{header}'",
            description=f"The '{header}' response header reveals implementation detail: {value!r}.",
            severity=Severity.INFO,
            confidence=70 if discloses_version else 40,
            location=record.final_url,
            evidence=f"{header}: {value}",
            recommendation="Strip or genericise banner/version headers at the edge.",
            remediation=f"Remove or mask the '{header}' header; do not expose exact software versions.",
            mitigated_by=None if discloses_version else "no version string",
            cwe="CWE-200",
        ))
    return checks


def _check_cors(record) -> list[LiveCheck]:  # noqa: ANN001
    headers = _ci(record.headers)
    acao = headers.get("access-control-allow-origin")
    if acao is None:
        return []
    acac = headers.get("access-control-allow-credentials", "").strip().lower() == "true"
    if acao.strip() == "*":
        if acac:
            # ACAO:* with credentials is rejected by browsers, but signals misconfig intent.
            severity, conf, mit = Severity.HIGH, 80, None
            detail = "wildcard origin combined with Allow-Credentials: true"
        else:
            severity, conf, mit = Severity.MEDIUM, 75, None
            detail = "wildcard origin allows any site to read responses"
        return [LiveCheck(
            rule_id="LIVE-CORS-WILDCARD",
            surface="server-config",
            name="Permissive CORS (Access-Control-Allow-Origin: *)",
            description=f"{record.final_url} returns a wildcard CORS policy: {detail}.",
            severity=severity,
            confidence=conf,
            location=record.final_url,
            evidence=f"access-control-allow-origin: {acao}"
                     + ("; access-control-allow-credentials: true" if acac else ""),
            recommendation="Reflect only an explicit allowlist of trusted origins; never pair '*' with credentials.",
            remediation="Replace the wildcard with a validated origin allowlist and set Vary: Origin.",
            mitigated_by=mit,
            cwe="CWE-942",
        )]
    return []


_SENSITIVE_COOKIE_RE = re.compile(r"sess|auth|token|jwt|sid|login|csrf|xsrf", re.IGNORECASE)


def _check_cookies(record) -> list[LiveCheck]:  # noqa: ANN001
    checks: list[LiveCheck] = []
    for raw in record.set_cookie:
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        missing = []
        if "secure" not in low:
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        if not missing:
            continue
        sensitive = bool(_SENSITIVE_COOKIE_RE.search(name))
        severity = Severity.MEDIUM if sensitive else Severity.LOW
        checks.append(LiveCheck(
            rule_id="LIVE-COOKIE-FLAGS",
            surface="session-management",
            name=f"Cookie '{name}' missing {', '.join(missing)} flag(s)",
            description=f"A Set-Cookie for '{name}' at {record.final_url} omits: {', '.join(missing)}.",
            severity=severity,
            confidence=80 if sensitive else 60,
            location=record.final_url,
            evidence=raw[:200],
            recommendation="Set Secure, HttpOnly and SameSite on session/auth cookies.",
            remediation="Add the Secure, HttpOnly and SameSite=Lax|Strict attributes to the cookie.",
            cwe="CWE-1004" if "HttpOnly" in missing else "CWE-614",
        ))
    return checks


_SCRIPT_SRC_RE = re.compile(r"<script\b[^>]*\bsrc\s*=\s*['\"]([^'\"]+)['\"][^>]*>", re.IGNORECASE)
_INTEGRITY_RE = re.compile(r"\bintegrity\s*=", re.IGNORECASE)


def _check_sri(record, base_host: str) -> list[LiveCheck]:  # noqa: ANN001
    checks: list[LiveCheck] = []
    seen: set[str] = set()
    for match in _SCRIPT_SRC_RE.finditer(record.html):
        tag = match.group(0)
        src = match.group(1)
        # Only external (absolute or protocol-relative) scripts are in scope for SRI.
        if not src.startswith(("http://", "https://", "//")):
            continue
        host = re.sub(r"^(https?:)?//", "", src).split("/")[0].split(":")[0].lower()
        if base_host and (host == base_host or host.endswith("." + base_host)):
            continue  # same-origin scripts don't need SRI
        if src in seen:
            continue
        seen.add(src)
        if _INTEGRITY_RE.search(tag):
            continue
        mixed = src.startswith(("http://", "//")) and record.final_url.startswith("https://") and src.startswith("http://")
        checks.append(LiveCheck(
            rule_id="LIVE-SRI-MISSING",
            surface="frontend-assets",
            name="Third-party script loaded without Subresource Integrity",
            description=f"{record.final_url} loads external script {src} without an 'integrity' attribute.",
            severity=Severity.MEDIUM if mixed else Severity.LOW,
            confidence=70,
            location=record.final_url,
            evidence=tag[:200],
            recommendation="Add integrity + crossorigin attributes (SRI) to third-party <script>/<link> tags.",
            remediation="Pin the resource with a Subresource Integrity hash and 'crossorigin=anonymous'.",
            cwe="CWE-353",
        ))
    return checks


def analyze_records(records: Sequence, base_domain: str = "") -> list[Finding]:  # noqa: ANN001
    """Run every live check over the crawled page records and return findings.

    Header-level checks (security headers, disclosure, CORS) are evaluated once
    against the first successful HTML page (representative of the edge config);
    cookie and SRI checks run per page. Findings are de-duplicated by rule id +
    a stable key so a site-wide issue is reported once.
    """
    records = [r for r in records if 200 <= getattr(r, "status", 0) < 400]
    findings: list[Finding] = []
    if not records:
        return findings

    html_records = [r for r in records if getattr(r, "html", "")]
    representative = html_records[0] if html_records else records[0]
    is_https = representative.final_url.startswith("https://")
    base_host = base_domain.split(":")[0].lower().removeprefix("www.")

    checks: list[LiveCheck] = []
    checks += _check_security_headers(representative, is_https)
    checks += _check_disclosure(representative)
    checks += _check_cors(representative)
    for record in records:
        checks += _check_cookies(record)
    for record in html_records:
        checks += _check_sri(record, base_host)

    seen: set[str] = set()
    for check in checks:
        key = f"{check.rule_id}|{check.name}|{check.evidence}"
        if key in seen:
            continue
        seen.add(key)
        findings.append(_finding_from_check(check))
    return findings


def dedupe_and_sort(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.risk_score, -f.severity.rank, f.rule_id))


__all__ = ["analyze_records", "LiveCheck"]
