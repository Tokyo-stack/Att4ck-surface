"""Unit tests for the live-target crawler's origin handling (no network I/O)."""

from __future__ import annotations

import pytest

wc = pytest.importorskip("attack_surface.web_crawler")


def _crawler(url: str):
    if not getattr(wc, "_LIVE_AVAILABLE", False):
        pytest.skip("live extra (requests/bs4) not installed")
    return wc.WebCrawler(url)


def test_registrable_strips_www_and_port() -> None:
    assert wc.WebCrawler._registrable("www.example.com") == "example.com"
    assert wc.WebCrawler._registrable("example.com:8443") == "example.com"
    assert wc.WebCrawler._registrable("user@www.example.com:443") == "example.com"


def test_apex_and_www_are_same_origin() -> None:
    c = _crawler("https://example.com")
    assert c._same_origin("https://www.example.com/path")
    assert c._same_origin("/relative/path")
    assert c._same_origin("https://example.com/x")


def test_external_host_is_cross_origin() -> None:
    c = _crawler("https://example.com")
    assert not c._same_origin("https://evil.example.org/x")
