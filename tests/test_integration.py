"""End-to-end integration: scan the sandbox and assert detection + sanitization.

* Every one of the 40 surfaces MUST produce a finding in ``vulnerable/``.
* The ``sanitized/`` counterparts MUST NOT produce a VULNERABLE finding
  (POTENTIALLY_MITIGATED is acceptable — that is sanitization awareness).
* All four export formats are produced and are valid.
"""

from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path

import pytest

from attack_surface.exporter import export_results, render_html
from attack_surface.models import Status
from attack_surface.rules import SURFACE_KEYS
from attack_surface.scanner import scan_path

SANDBOX = Path(__file__).resolve().parent.parent / "test_sandbox"
pytestmark = pytest.mark.skipif(not SANDBOX.exists(), reason="test_sandbox not present")


@pytest.fixture(scope="module")
def vuln_result():
    return scan_path(SANDBOX / "vulnerable", include_hidden=True)


@pytest.fixture(scope="module")
def safe_result():
    return scan_path(SANDBOX / "sanitized", include_hidden=True)


def test_every_surface_detected(vuln_result):
    found = {f.surface for f in vuln_result.findings}
    missing = [s for s in SURFACE_KEYS if s not in found]
    assert not missing, f"surfaces not detected in vulnerable sandbox: {missing}"


@pytest.mark.parametrize("surface", SURFACE_KEYS)
def test_surface_fires_in_its_own_directory(surface):
    target = SANDBOX / "vulnerable" / surface
    if not target.exists():
        pytest.skip(f"no sandbox for {surface}")
    result = scan_path(target, include_hidden=True)
    surfaces_hit = {f.surface for f in result.findings}
    assert surface in surfaces_hit, (
        f"{surface}: expected a finding, got {surfaces_hit or 'none'}"
    )


def test_sanitized_has_no_vulnerable_findings(safe_result):
    vulnerable = [
        f for f in safe_result.findings if f.status is Status.VULNERABLE
    ]
    detail = "\n".join(f"  {f.surface} {f.rule_id} {f.file}:{f.line}" for f in vulnerable)
    assert not vulnerable, f"sanitized samples produced VULNERABLE findings:\n{detail}"


def test_sandbox_coverage_is_complete(vuln_result):
    assert vuln_result.summary["coverage"]["surfaces_scanned"] == 40


def test_all_exports_written(vuln_result, tmp_path):
    written = export_results(vuln_result, tmp_path)
    assert set(written) == {"json", "csv", "sqlite", "html"}
    for path in written.values():
        assert path.exists() and path.stat().st_size > 0


def test_json_export_valid(vuln_result, tmp_path):
    written = export_results(vuln_result, tmp_path, formats=["json"])
    data = json.loads(written["json"].read_text())
    assert data["meta"]["tool"] == "ATT4ck Surface"
    assert len(data["findings"]) == len(vuln_result.findings)
    assert "summary" in data and "coverage" in data["summary"]


def test_csv_export_valid(vuln_result, tmp_path):
    written = export_results(vuln_result, tmp_path, formats=["csv"])
    rows = list(csv.DictReader(written["csv"].open()))
    assert len(rows) == len(vuln_result.findings)
    assert "severity" in rows[0]


def test_sqlite_schema_and_data(vuln_result, tmp_path):
    written = export_results(vuln_result, tmp_path, formats=["sqlite"])
    conn = sqlite3.connect(written["sqlite"])
    try:
        (n_findings,) = conn.execute("SELECT COUNT(*) FROM findings").fetchone()
        (n_surfaces,) = conn.execute("SELECT COUNT(*) FROM surfaces").fetchone()
        (tool,) = conn.execute("SELECT tool FROM scan_meta").fetchone()
    finally:
        conn.close()
    assert n_findings == len(vuln_result.findings)
    assert n_surfaces == 40
    assert tool == "ATT4ck Surface"


def test_html_export_self_contained(vuln_result):
    html = render_html(vuln_result)
    assert "<!DOCTYPE html>" in html
    assert "ATT4CK SURFACE" in html
    assert "http://" not in html.split("</head>")[0].replace("http://www.w3.org", "")
    assert "const FINDINGS" in html
