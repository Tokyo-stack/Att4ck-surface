"""Optional reflected-XSS prober for the ``crawl --xss`` mode.

Sends a benign, uniquely-marked payload to each query parameter of a URL and
reports parameters whose value is reflected unencoded. Purely for authorised
testing of live targets; static DOM/reflected-XSS detection lives in the
frontend/input surfaces.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

try:
    import requests

    _LIVE_AVAILABLE = True
except ImportError:  # pragma: no cover - optional
    _LIVE_AVAILABLE = False

_MARKER = "att4ckXSS"
#: Non-destructive probes; the marker makes reflections easy to locate.
XSS_PAYLOADS: tuple[str, ...] = (
    f"<{_MARKER}>",
    f"\"{_MARKER}\"",
    f"'{_MARKER}'",
    f"<img src=x onerror={_MARKER}>",
    f"javascript:{_MARKER}",
)


@dataclass(slots=True)
class XSSFinding:
    url: str
    parameter: str
    payload: str
    reflected_raw: bool
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "reflected_raw": self.reflected_raw,
            "evidence": self.evidence,
        }


class XSSScanner:
    def __init__(self, timeout: float = 10.0) -> None:
        if not _LIVE_AVAILABLE:  # pragma: no cover - optional
            raise ImportError("xss_scanner needs 'requests' (pip install att4ck-surface[live])")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "ATT4ck-Surface-XSS/1.0"})

    def scan_url(self, url: str) -> list[XSSFinding]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        findings: list[XSSFinding] = []
        for param in params or {}:
            for payload in XSS_PAYLOADS:
                probe = {k: v[0] for k, v in params.items()}
                probe[param] = payload
                target = urlunparse(parsed._replace(query=urlencode(probe)))
                try:
                    resp = self.session.get(target, timeout=self.timeout)
                except requests.RequestException:
                    continue
                if payload in resp.text and html.escape(payload) not in resp.text.replace(payload, "", 1):
                    idx = resp.text.find(payload)
                    findings.append(XSSFinding(
                        url=url, parameter=param, payload=payload, reflected_raw=True,
                        evidence=resp.text[max(0, idx - 40): idx + len(payload) + 40],
                    ))
                    break
        return findings

    def scan_urls(self, urls: list[str]) -> list[XSSFinding]:
        findings: list[XSSFinding] = []
        for url in urls:
            if "?" in url:
                findings.extend(self.scan_url(url))
        return findings


__all__ = ["XSSScanner", "XSSFinding", "XSS_PAYLOADS"]
