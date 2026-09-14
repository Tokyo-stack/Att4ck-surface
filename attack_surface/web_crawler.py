"""Optional live-target crawler used by the ``crawl`` command.

Requires the optional 'live' extra (requests + beautifulsoup4). Kept minimal:
its job is endpoint discovery, not vulnerability detection (that is the static
engine's role). Imported lazily so the core tool has zero runtime dependencies
beyond the standard analysis stack.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

try:
    import requests
    from bs4 import BeautifulSoup

    _LIVE_AVAILABLE = True
except ImportError:  # pragma: no cover - optional
    _LIVE_AVAILABLE = False


@dataclass(slots=True)
class PageRecord:
    """HTTP-level snapshot of one fetched page, consumed by the live analyzer."""

    url: str
    final_url: str
    status: int
    headers: dict[str, str]
    set_cookie: list[str] = field(default_factory=list)
    html: str = ""

_USER_AGENT = "ATT4ck-Surface/1.0 (+https://github.com/Tokyo-stack/Att4ck-surface)"


class WebCrawler:
    """Breadth-first, same-origin crawler that collects pages, JS files and endpoints."""

    def __init__(self, target_url: str, max_pages: int = 50, timeout: float = 10.0) -> None:
        if not _LIVE_AVAILABLE:  # pragma: no cover - optional
            raise ImportError("web_crawler needs 'requests' and 'beautifulsoup4' (pip install att4ck-surface[live])")
        self.target_url = target_url.rstrip("/")
        self.base_domain = urlparse(self.target_url).netloc
        self.max_pages = max_pages
        self.timeout = timeout
        self.visited: set[str] = set()
        self.endpoints: set[str] = set()
        self.js_files: set[str] = set()
        self.records: list[PageRecord] = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": _USER_AGENT})

    @staticmethod
    def _registrable(netloc: str) -> str:
        """Normalise a netloc for comparison: drop a leading ``www.`` and any port."""
        host = netloc.split("@")[-1].split(":")[0].lower()
        return host[4:] if host.startswith("www.") else host

    def _same_origin(self, url: str) -> bool:
        netloc = urlparse(url).netloc
        return netloc == "" or self._registrable(netloc) == self._registrable(self.base_domain)

    @staticmethod
    def _raw_set_cookies(resp) -> list[str]:  # noqa: ANN001
        """Return each individual ``Set-Cookie`` header (requests collapses them)."""
        try:
            raw = getattr(resp, "raw", None)
            headers = getattr(raw, "headers", None)
            if headers is not None and hasattr(headers, "getlist"):
                values = headers.getlist("Set-Cookie")
                if values:
                    return list(values)
        except Exception:  # pragma: no cover - defensive
            pass
        value = resp.headers.get("Set-Cookie")
        return [value] if value else []

    def crawl(self) -> dict[str, list[str]]:
        queue: deque[str] = deque([self.target_url])
        while queue and len(self.visited) < self.max_pages:
            url = queue.popleft()
            if url in self.visited:
                continue
            self.visited.add(url)
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            except requests.RequestException:
                continue
            # If the seed URL redirected (e.g. apex -> www), adopt the final host
            # so discovered links are not wrongly treated as cross-origin.
            if url == self.target_url and resp.url:
                self.base_domain = urlparse(str(resp.url)).netloc or self.base_domain
            content_type = resp.headers.get("Content-Type", "")
            is_html = "html" in content_type
            self.records.append(
                PageRecord(
                    url=url,
                    final_url=str(resp.url),
                    status=resp.status_code,
                    headers=dict(resp.headers.items()),
                    set_cookie=self._raw_set_cookies(resp),
                    html=resp.text if is_html else "",
                )
            )
            if not is_html:
                continue
            self.endpoints.add(url)
            soup = BeautifulSoup(resp.text, "html.parser")
            for tag, attr in (("a", "href"), ("script", "src"), ("link", "href"), ("form", "action"), ("img", "src")):
                for el in soup.find_all(tag):
                    ref = el.get(attr)
                    if isinstance(ref, (list, tuple)):
                        ref = ref[0] if ref else None
                    if not ref or not isinstance(ref, str):
                        continue
                    absolute = urljoin(url, ref)
                    if absolute.endswith(".js"):
                        self.js_files.add(absolute)
                    if self._same_origin(absolute) and absolute not in self.visited:
                        if "?" in absolute or tag == "form":
                            self.endpoints.add(absolute)
                        if tag == "a":
                            queue.append(absolute.split("#")[0])
        return {
            "pages": sorted(self.visited),
            "endpoints": sorted(self.endpoints),
            "js_files": sorted(self.js_files),
        }


__all__ = ["WebCrawler"]
