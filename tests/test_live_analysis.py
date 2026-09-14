"""Offline tests for the live HTTP-posture analyzer (no network I/O)."""

from __future__ import annotations

from attack_surface.live_analysis import analyze_records
from attack_surface.models import Status
from attack_surface.web_crawler import PageRecord


def _rec(headers=None, set_cookie=None, html="", url="https://ex.com", status=200):
    return PageRecord(
        url=url, final_url=url, status=status,
        headers=headers or {}, set_cookie=set_cookie or [], html=html,
    )


def test_hardened_page_yields_no_findings() -> None:
    rec = _rec(
        headers={
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
        },
        set_cookie=["sid=x; Secure; HttpOnly; SameSite=Lax"],
        html="<script src='https://cdn.ex.net/a.js' integrity='sha384-y'></script>",
    )
    assert analyze_records([rec], base_domain="ex.com") == []


def test_missing_headers_are_flagged() -> None:
    findings = analyze_records([_rec(headers={})], base_domain="ex.com")
    rule_ids = {f.rule_id for f in findings}
    assert "LIVE-HDR-STRICT-TRANSPORT-SECURITY" in rule_ids
    assert "LIVE-HDR-CONTENT-SECURITY-POLICY" in rule_ids
    assert "LIVE-HDR-X-CONTENT-TYPE-OPTIONS" in rule_ids
    assert "LIVE-HDR-X-FRAME-OPTIONS" in rule_ids


def test_frame_ancestors_satisfies_clickjacking() -> None:
    rec = _rec(headers={"Content-Security-Policy": "frame-ancestors 'none'"})
    ids = {f.rule_id for f in analyze_records([rec], base_domain="ex.com")}
    assert "LIVE-HDR-X-FRAME-OPTIONS" not in ids


def test_cors_wildcard_with_credentials_is_high() -> None:
    rec = _rec(headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    })
    cors = [f for f in analyze_records([rec], base_domain="ex.com") if f.rule_id == "LIVE-CORS-WILDCARD"]
    assert cors and cors[0].severity.value == "HIGH"


def test_sensitive_cookie_missing_flags() -> None:
    rec = _rec(set_cookie=["sessionid=abc"])
    cookie = [f for f in analyze_records([rec], base_domain="ex.com") if f.rule_id == "LIVE-COOKIE-FLAGS"]
    assert cookie
    assert cookie[0].surface == "session-management"
    assert cookie[0].severity.value == "MEDIUM"


def test_same_origin_script_needs_no_sri() -> None:
    rec = _rec(html="<script src='https://www.ex.com/app.js'></script>")
    ids = {f.rule_id for f in analyze_records([rec], base_domain="ex.com")}
    assert "LIVE-SRI-MISSING" not in ids


def test_external_script_without_integrity_flagged() -> None:
    rec = _rec(html="<script src='https://cdn.jsdelivr.net/x.js'></script>")
    sri = [f for f in analyze_records([rec], base_domain="ex.com") if f.rule_id == "LIVE-SRI-MISSING"]
    assert sri and sri[0].surface == "frontend-assets"


def test_server_banner_without_version_is_mitigated() -> None:
    rec = _rec(headers={"Server": "cloudflare"})
    disc = [f for f in analyze_records([rec], base_domain="ex.com") if f.rule_id == "LIVE-DISCLOSE-SERVER"]
    assert disc and disc[0].status is Status.POTENTIALLY_MITIGATED


def test_non_2xx_records_ignored() -> None:
    assert analyze_records([_rec(headers={}, status=500)], base_domain="ex.com") == []
