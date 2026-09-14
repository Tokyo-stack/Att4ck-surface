"""ATT4ck Surface - Attack Surface Mapping & Security Review Framework.

Public API::

    from attack_surface import scan_path, SurfaceScanner, ScanConfig, export_results

The live-target helpers (:mod:`attack_surface.web_crawler`,
:mod:`attack_surface.xss_scanner`) are imported lazily because they are only
needed for the optional ``crawl`` command.
"""

from __future__ import annotations

from attack_surface.models import Finding, Rule, ScanConfig, ScanResult, Severity, Status
from attack_surface.rules import SURFACE_KEYS, SURFACES, load_rules, rules_for_surfaces
from attack_surface.scanner import SurfaceScanner, scan_path
from attack_surface.version import __version__

__author__ = "Tokyo"

__all__ = [
    "Finding",
    "Rule",
    "SURFACES",
    "SURFACE_KEYS",
    "ScanConfig",
    "ScanResult",
    "Severity",
    "Status",
    "SurfaceScanner",
    "__author__",
    "__version__",
    "export_results",
    "load_rules",
    "rules_for_surfaces",
    "scan_path",
]


def export_results(*args, **kwargs):  # type: ignore[no-untyped-def]
    """Proxy to :func:`attack_surface.exporter.export_results` (lazy import)."""
    from attack_surface.exporter import export_results as _export

    return _export(*args, **kwargs)
