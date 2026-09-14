"""Exporters: JSON, CSV, SQLite and a self-contained interactive HTML report.

Every exporter accepts a :class:`~attack_surface.models.ScanResult` (or a raw
list of :class:`~attack_surface.models.Finding`) and writes to ``output_dir``.
The HTML report is fully self-contained (inline CSS + JS, no network calls) so
it can be opened straight from disk or emailed.
"""

from __future__ import annotations

import csv
import html
import json
import sqlite3
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from attack_surface.models import Finding, ScanResult
from attack_surface.rules import SURFACES
from attack_surface.version import __version__

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "#e5484d",
    "HIGH": "#f76808",
    "MEDIUM": "#ffb224",
    "LOW": "#46a758",
    "INFO": "#8b8d98",
}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _as_result(data: ScanResult | Iterable[Finding]) -> ScanResult:
    if isinstance(data, ScanResult):
        return data
    from attack_surface.risk_engine import summarize

    findings = list(data)
    now = datetime.now(UTC).isoformat(timespec="seconds")
    from attack_surface.models import ScanStats

    surfaces = tuple(sorted({f.surface for f in findings}))
    summary = summarize(findings, surfaces, [], 0)
    return ScanResult(target="", started_at=now, finished_at=now, findings=findings,
                      stats=ScanStats(), surfaces_run=surfaces, summary=summary)


def _ensure_dir(output_dir: str | Path) -> Path:
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #


def export_json(result: ScanResult, output_dir: str | Path = "output", filename: str = "findings.json") -> Path:
    path = _ensure_dir(output_dir) / filename
    payload = result.to_dict()
    payload["meta"]["tool"] = "ATT4ck Surface"
    payload["meta"]["version"] = __version__
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    return path


# --------------------------------------------------------------------------- #
# CSV
# --------------------------------------------------------------------------- #

_CSV_FIELDS = (
    "id", "priority", "surface_number", "surface", "surface_name", "rule_id", "name",
    "severity", "base_severity", "confidence", "status", "risk_score", "cwe",
    "file", "line", "column", "mitigation", "description", "recommendation", "snippet",
)


def export_csv(result: ScanResult, output_dir: str | Path = "output", filename: str = "findings.csv") -> Path:
    path = _ensure_dir(output_dir) / filename
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for finding in result.findings:
            row = finding.to_dict()
            row["snippet"] = (row.get("snippet") or "").replace("\n", " ")[:500]
            row["description"] = (row.get("description") or "").replace("\n", " ")
            writer.writerow(row)
    return path


# --------------------------------------------------------------------------- #
# SQLite
# --------------------------------------------------------------------------- #

_SCHEMA = """
CREATE TABLE scan_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    tool TEXT NOT NULL,
    version TEXT NOT NULL,
    target TEXT,
    started_at TEXT,
    finished_at TEXT,
    total_findings INTEGER,
    overall_risk TEXT,
    coverage_percent REAL,
    files_scanned INTEGER,
    rules_executed INTEGER
);
CREATE TABLE surfaces (
    number INTEGER PRIMARY KEY,
    key TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    package TEXT NOT NULL,
    description TEXT,
    scanned INTEGER NOT NULL DEFAULT 0,
    rules INTEGER NOT NULL DEFAULT 0,
    findings INTEGER NOT NULL DEFAULT 0,
    risk REAL NOT NULL DEFAULT 0,
    max_severity TEXT
);
CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    priority INTEGER,
    rule_id TEXT NOT NULL,
    surface TEXT NOT NULL,
    surface_number INTEGER NOT NULL,
    surface_name TEXT NOT NULL,
    package TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    base_severity TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    status TEXT NOT NULL,
    cwe TEXT,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    column INTEGER,
    snippet TEXT,
    mitigation TEXT,
    recommendation TEXT,
    remediation TEXT,
    risk_score REAL,
    FOREIGN KEY (surface) REFERENCES surfaces (key)
);
CREATE INDEX idx_findings_severity ON findings (severity);
CREATE INDEX idx_findings_surface ON findings (surface);
CREATE INDEX idx_findings_status ON findings (status);
CREATE INDEX idx_findings_file ON findings (file);
"""


def export_sqlite(result: ScanResult, output_dir: str | Path = "output", filename: str = "findings.db") -> Path:
    path = _ensure_dir(output_dir) / filename
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(path)
    try:
        conn.executescript(_SCHEMA)
        summary = result.summary
        coverage = summary.get("coverage", {})
        conn.execute(
            "INSERT INTO scan_meta VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "ATT4ck Surface", __version__, result.target, result.started_at, result.finished_at,
                summary.get("total_findings", len(result.findings)), summary.get("overall_risk"),
                coverage.get("coverage_percent"), coverage.get("files_scanned"), coverage.get("rules_executed"),
            ),
        )
        surface_rows = {row["key"]: row for row in summary.get("surfaces", [])}
        for surface in SURFACES:
            row = surface_rows.get(surface.key, {})
            conn.execute(
                "INSERT INTO surfaces (number, key, name, package, description, scanned, rules, findings, risk, max_severity)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    surface.number, surface.key, surface.name, surface.package, surface.description,
                    int(row.get("scanned", False)), row.get("rules", 0), row.get("findings", 0),
                    row.get("risk", 0.0), row.get("max_severity"),
                ),
            )
        conn.executemany(
            "INSERT OR REPLACE INTO findings (id, priority, rule_id, surface, surface_number, surface_name, package,"
            " name, description, severity, base_severity, confidence, status, cwe, file, line, column, snippet,"
            " mitigation, recommendation, remediation, risk_score)"
            " VALUES (:id, :priority, :rule_id, :surface, :surface_number, :surface_name, :package, :name,"
            " :description, :severity, :base_severity, :confidence, :status, :cwe, :file, :line, :column, :snippet,"
            " :mitigation, :recommendation, :remediation, :risk_score)",
            [f.to_dict() for f in result.findings],
        )
        conn.commit()
    finally:
        conn.close()
    return path


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #


def export_html(result: ScanResult, output_dir: str | Path = "output", filename: str = "report.html") -> Path:
    path = _ensure_dir(output_dir) / filename
    path.write_text(render_html(result), encoding="utf-8")
    return path


def render_html(result: ScanResult) -> str:
    summary = result.summary
    findings = result.findings
    sev_counts = summary.get("by_severity", {})
    coverage = summary.get("coverage", {})
    stats = result.stats.to_dict()

    findings_json = json.dumps([f.to_dict() for f in findings], ensure_ascii=False)
    surfaces_json = json.dumps(summary.get("surfaces", []), ensure_ascii=False)
    meta_json = json.dumps(
        {
            "target": result.target,
            "started_at": result.started_at,
            "finished_at": result.finished_at,
            "version": __version__,
            "duration": stats.get("duration_seconds"),
        },
        ensure_ascii=False,
    )

    def stat_card(label: str, value: Any, color: str = "#e6e6e9") -> str:
        return (
            f'<div class="stat"><div class="stat-value" style="color:{color}">{value}</div>'
            f'<div class="stat-label">{html.escape(label)}</div></div>'
        )

    sev_cards = "".join(
        stat_card(sev, sev_counts.get(sev, 0), SEVERITY_COLORS[sev])
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )

    top_surface_rows = "".join(
        f'<tr><td>{html.escape(row["name"])}</td><td>{row["findings"]}</td>'
        f'<td><span class="sev-badge" style="background:{SEVERITY_COLORS.get(row["max_severity"] or "INFO", "#8b8d98")}">'
        f'{html.escape(row["max_severity"] or "-")}</span></td>'
        f'<td>{row["risk"]:.1f}</td></tr>'
        for row in summary.get("top_surfaces", [])
    ) or '<tr><td colspan="4" class="empty">No findings</td></tr>'

    coverage_pct = coverage.get("coverage_percent", 0)
    overall = summary.get("overall_risk", "CLEAN")
    overall_color = SEVERITY_COLORS.get(overall, "#46a758")

    return _HTML_TEMPLATE.format(
        version=html.escape(__version__),
        generated=html.escape(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        target=html.escape(result.target or "(unknown)"),
        total=summary.get("total_findings", len(findings)),
        overall=html.escape(overall),
        overall_color=overall_color,
        sev_cards=sev_cards,
        files_scanned=coverage.get("files_scanned", stats.get("files_scanned", 0)),
        rules_executed=coverage.get("rules_executed", 0),
        surfaces_scanned=coverage.get("surfaces_scanned", 0),
        coverage_pct=coverage_pct,
        duration=stats.get("duration_seconds", 0),
        vulnerable=summary.get("by_status", {}).get("VULNERABLE", 0),
        mitigated=summary.get("by_status", {}).get("POTENTIALLY_MITIGATED", 0),
        top_surface_rows=top_surface_rows,
        normalized_risk=summary.get("normalized_risk", 0),
        findings_json=findings_json,
        surfaces_json=surfaces_json,
        meta_json=meta_json,
        severity_colors_json=json.dumps(SEVERITY_COLORS),
    )


_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ATT4ck Surface Report</title>
<style>
  :root {{
    --bg: #0b0c0f; --panel: #15171c; --panel2: #1c1f26; --border: #2a2d36;
    --text: #e6e6e9; --muted: #9497a3; --accent: #e5484d; --accent2: #f76808;
    --shadow: 0 4px 24px rgba(0,0,0,.4);
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    font-size: 14px; line-height: 1.5; }}
  a {{ color: var(--accent2); }}
  .wrap {{ max-width: 1400px; margin: 0 auto; padding: 24px 20px 80px; }}
  header {{ display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px;
    padding-bottom: 20px; border-bottom: 1px solid var(--border); margin-bottom: 24px; }}
  .brand {{ display: flex; align-items: center; gap: 14px; }}
  .logo {{ font-size: 28px; font-weight: 800; letter-spacing: -.5px;
    background: linear-gradient(135deg, var(--accent), var(--accent2)); -webkit-background-clip: text;
    background-clip: text; color: transparent; }}
  .sub {{ color: var(--muted); font-size: 13px; }}
  .meta {{ text-align: right; color: var(--muted); font-size: 12px; }}
  .meta code {{ color: var(--text); }}
  .grid {{ display: grid; gap: 16px; }}
  .cards {{ grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); margin-bottom: 16px; }}
  .stat {{ background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 16px;
    text-align: center; box-shadow: var(--shadow); }}
  .stat-value {{ font-size: 30px; font-weight: 800; }}
  .stat-label {{ color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .8px; margin-top: 4px; }}
  .panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 20px;
    box-shadow: var(--shadow); }}
  .two-col {{ grid-template-columns: 2fr 1fr; align-items: start; margin-bottom: 24px; }}
  @media (max-width: 900px) {{ .two-col {{ grid-template-columns: 1fr; }} .meta {{ text-align: left; }} }}
  h2 {{ font-size: 15px; margin: 0 0 14px; text-transform: uppercase; letter-spacing: .6px; color: var(--muted); }}
  .risk-hero {{ display: flex; align-items: center; gap: 24px; }}
  .risk-dial {{ width: 120px; height: 120px; border-radius: 50%; display: grid; place-items: center;
    font-size: 26px; font-weight: 800; flex-shrink: 0; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ text-align: left; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .6px;
    padding: 8px 10px; border-bottom: 1px solid var(--border); position: sticky; top: 0; background: var(--panel); }}
  td {{ padding: 9px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tr:hover td {{ background: var(--panel2); }}
  .empty {{ color: var(--muted); text-align: center; padding: 24px; }}
  .sev-badge {{ display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 700;
    color: #0b0c0f; }}
  .status-badge {{ display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 11px; font-weight: 600;
    border: 1px solid var(--border); }}
  .status-VULNERABLE {{ color: var(--accent); border-color: var(--accent); }}
  .status-POTENTIALLY_MITIGATED {{ color: #46a758; border-color: #46a758; }}
  .controls {{ display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 16px; }}
  .controls input, .controls select {{ background: var(--panel2); border: 1px solid var(--border); color: var(--text);
    padding: 8px 12px; border-radius: 8px; font-size: 13px; }}
  .controls input[type=search] {{ flex: 1; min-width: 200px; }}
  .chip {{ cursor: pointer; padding: 6px 12px; border-radius: 999px; border: 1px solid var(--border);
    background: var(--panel2); font-size: 12px; font-weight: 600; user-select: none; }}
  .chip.active {{ background: var(--accent); color: #0b0c0f; border-color: var(--accent); }}
  .finding {{ border: 1px solid var(--border); border-radius: 10px; margin-bottom: 10px; overflow: hidden;
    background: var(--panel); }}
  .finding-head {{ display: flex; align-items: center; gap: 12px; padding: 12px 16px; cursor: pointer; }}
  .finding-head:hover {{ background: var(--panel2); }}
  .finding-title {{ flex: 1; font-weight: 600; }}
  .finding-loc {{ color: var(--muted); font-size: 12px; font-family: ui-monospace, "SF Mono", Menlo, monospace; }}
  .finding-body {{ padding: 0 16px 16px; display: none; border-top: 1px solid var(--border); }}
  .finding.open .finding-body {{ display: block; }}
  .kv {{ display: grid; grid-template-columns: 140px 1fr; gap: 6px 16px; margin: 14px 0; font-size: 13px; }}
  .kv dt {{ color: var(--muted); }}
  .kv dd {{ margin: 0; }}
  pre.snippet {{ background: #0b0c0f; border: 1px solid var(--border); border-radius: 8px; padding: 12px;
    overflow-x: auto; font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 12.5px; color: #d9dbe0;
    white-space: pre-wrap; word-break: break-word; }}
  .rec {{ background: rgba(70,167,88,.08); border-left: 3px solid #46a758; padding: 10px 14px; border-radius: 6px;
    margin-top: 10px; font-size: 13px; }}
  .rem {{ background: rgba(247,104,8,.08); border-left: 3px solid var(--accent2); padding: 10px 14px;
    border-radius: 6px; margin-top: 8px; font-size: 13px; font-family: ui-monospace, Menlo, monospace; }}
  .cov-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 8px; }}
  .cov-item {{ display: flex; align-items: center; gap: 8px; padding: 8px 10px; border: 1px solid var(--border);
    border-radius: 8px; font-size: 12.5px; background: var(--panel2); }}
  .cov-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
  .cov-num {{ margin-left: auto; font-weight: 700; }}
  .muted {{ color: var(--muted); }}
  .footer {{ text-align: center; color: var(--muted); font-size: 12px; margin-top: 40px; }}
  .count-tag {{ background: var(--panel2); border: 1px solid var(--border); border-radius: 999px;
    padding: 1px 8px; font-size: 11px; color: var(--muted); }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">
      <div class="logo">ATT4CK SURFACE</div>
      <div>
        <div>Attack Surface Mapping &amp; Security Review</div>
        <div class="sub">v{version} &middot; Report generated {generated}</div>
      </div>
    </div>
    <div class="meta">
      Target: <code>{target}</code><br>
      Scan duration: <code>{duration}s</code> &middot; {files_scanned} files &middot; {rules_executed} rules
    </div>
  </header>

  <div class="grid cards">
    {sev_cards}
  </div>

  <div class="grid two-col">
    <div class="panel">
      <h2>Risk Overview</h2>
      <div class="risk-hero">
        <div class="risk-dial" style="background: conic-gradient({overall_color} {coverage_pct}%, var(--panel2) 0); color: {overall_color};">
          <div style="width:96px;height:96px;border-radius:50%;background:var(--panel);display:grid;place-items:center;">
            <div style="text-align:center"><div style="font-size:26px">{total}</div><div style="font-size:10px;color:var(--muted)">FINDINGS</div></div>
          </div>
        </div>
        <div>
          <div style="font-size:13px;color:var(--muted)">Overall risk level</div>
          <div style="font-size:28px;font-weight:800;color:{overall_color}">{overall}</div>
          <div style="margin-top:8px;font-size:13px">
            <span class="status-badge status-VULNERABLE">{vulnerable} vulnerable</span>
            <span class="status-badge status-POTENTIALLY_MITIGATED">{mitigated} potentially mitigated</span>
          </div>
          <div style="margin-top:8px;font-size:12px;color:var(--muted)">
            Normalised risk score: <b style="color:var(--text)">{normalized_risk}</b> / 10 &middot;
            Surface coverage: <b style="color:var(--text)">{surfaces_scanned}/40</b> ({coverage_pct}%)
          </div>
        </div>
      </div>
    </div>
    <div class="panel">
      <h2>Top Risk Surfaces</h2>
      <table>
        <thead><tr><th>Surface</th><th>#</th><th>Max</th><th>Risk</th></tr></thead>
        <tbody>{top_surface_rows}</tbody>
      </table>
    </div>
  </div>

  <div class="panel" style="margin-bottom:24px">
    <h2>Attack Surface Coverage</h2>
    <div class="cov-grid" id="coverage"></div>
  </div>

  <div class="panel">
    <h2>Findings <span class="count-tag" id="finding-count"></span></h2>
    <div class="controls">
      <input type="search" id="search" placeholder="Search name, file, CWE, rule id, description...">
      <select id="surface-filter"><option value="">All surfaces</option></select>
      <select id="status-filter">
        <option value="">All statuses</option>
        <option value="VULNERABLE">Vulnerable only</option>
        <option value="POTENTIALLY_MITIGATED">Potentially mitigated</option>
      </select>
      <select id="sort">
        <option value="priority">Sort: priority</option>
        <option value="severity">Sort: severity</option>
        <option value="surface">Sort: surface</option>
        <option value="file">Sort: file</option>
      </select>
    </div>
    <div id="sev-chips" class="controls"></div>
    <div id="findings"></div>
  </div>

  <div class="footer">
    Generated by ATT4ck Surface v{version} &middot; Made with &#10084; by Tokyo &middot; Stay Secure, Stay Vigilant!
  </div>
</div>

<script>
const FINDINGS = {findings_json};
const SURFACES = {surfaces_json};
const META = {meta_json};
const COLORS = {severity_colors_json};
const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const active = {{ severities: new Set(SEV_ORDER), search: "", surface: "", status: "", sort: "priority" }};

function esc(s) {{ return String(s == null ? "" : s).replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c])); }}

function renderCoverage() {{
  const el = document.getElementById("coverage");
  el.innerHTML = SURFACES.map(s => {{
    const color = s.max_severity ? COLORS[s.max_severity] : (s.scanned ? "#46a758" : "#3a3d46");
    const label = s.findings ? s.findings + " finding" + (s.findings === 1 ? "" : "s") : (s.scanned ? "clean" : "not scanned");
    return `<div class="cov-item" title="${{esc(s.description)}}">
      <span class="cov-dot" style="background:${{color}}"></span>
      <span>${{s.number}}. ${{esc(s.name)}}</span>
      <span class="cov-num" style="color:${{color}}">${{esc(label)}}</span></div>`;
  }}).join("");
}}

function populateSurfaceFilter() {{
  const sel = document.getElementById("surface-filter");
  SURFACES.filter(s => s.findings > 0).forEach(s => {{
    const o = document.createElement("option");
    o.value = s.key; o.textContent = `${{s.number}}. ${{s.name}} (${{s.findings}})`;
    sel.appendChild(o);
  }});
}}

function renderChips() {{
  const el = document.getElementById("sev-chips");
  const counts = {{}};
  FINDINGS.forEach(f => counts[f.severity] = (counts[f.severity] || 0) + 1);
  el.innerHTML = SEV_ORDER.map(s =>
    `<span class="chip ${{active.severities.has(s) ? "active" : ""}}" data-sev="${{s}}"
      style="${{active.severities.has(s) ? `background:${{COLORS[s]}};border-color:${{COLORS[s]}}` : ""}}">
      ${{s}} <b>${{counts[s] || 0}}</b></span>`).join("");
  el.querySelectorAll(".chip").forEach(c => c.onclick = () => {{
    const s = c.dataset.sev;
    active.severities.has(s) ? active.severities.delete(s) : active.severities.add(s);
    renderChips(); renderFindings();
  }});
}}

function filtered() {{
  let list = FINDINGS.filter(f => active.severities.has(f.severity));
  if (active.surface) list = list.filter(f => f.surface === active.surface);
  if (active.status) list = list.filter(f => f.status === active.status);
  if (active.search) {{
    const q = active.search.toLowerCase();
    list = list.filter(f => (f.name + " " + f.file + " " + f.cwe + " " + f.rule_id + " " +
      f.description + " " + f.surface_name + " " + f.snippet).toLowerCase().includes(q));
  }}
  const cmp = {{
    priority: (a, b) => a.priority - b.priority,
    severity: (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) || b.risk_score - a.risk_score,
    surface: (a, b) => a.surface_number - b.surface_number || a.priority - b.priority,
    file: (a, b) => (a.file || "").localeCompare(b.file || "") || a.line - b.line,
  }}[active.sort];
  return list.sort(cmp);
}}

function renderFindings() {{
  const list = filtered();
  document.getElementById("finding-count").textContent = list.length + " / " + FINDINGS.length;
  const el = document.getElementById("findings");
  if (!list.length) {{ el.innerHTML = '<div class="empty">No findings match the current filters.</div>'; return; }}
  el.innerHTML = list.map((f, i) => `
    <div class="finding" data-i="${{i}}">
      <div class="finding-head">
        <span class="sev-badge" style="background:${{COLORS[f.severity]}}">${{f.severity}}</span>
        <span class="finding-title">${{esc(f.name)}}</span>
        <span class="status-badge status-${{f.status}}">${{f.status === "VULNERABLE" ? "vuln" : "mitigated"}}</span>
        <span class="finding-loc">${{esc(f.file)}}:${{f.line}}</span>
      </div>
      <div class="finding-body">
        <dl class="kv">
          <dt>Surface</dt><dd>${{f.surface_number}}. ${{esc(f.surface_name)}} <span class="muted">(${{esc(f.surface)}})</span></dd>
          <dt>Rule / CWE</dt><dd><code>${{esc(f.rule_id)}}</code> &middot; ${{esc(f.cwe)}}</dd>
          <dt>Severity</dt><dd>${{f.severity}} <span class="muted">(base ${{f.base_severity}}, confidence ${{f.confidence}}%, risk ${{f.risk_score}})</span></dd>
          <dt>Status</dt><dd>${{f.status}}${{f.mitigation ? ` &mdash; mitigation seen: <code>${{esc(f.mitigation)}}</code>` : ""}}</dd>
          <dt>Description</dt><dd>${{esc(f.description)}}</dd>
        </dl>
        <pre class="snippet">${{esc(f.snippet)}}</pre>
        ${{f.recommendation ? `<div class="rec"><b>Recommendation:</b> ${{esc(f.recommendation)}}</div>` : ""}}
        ${{f.remediation ? `<div class="rem">${{esc(f.remediation)}}</div>` : ""}}
      </div>
    </div>`).join("");
  el.querySelectorAll(".finding-head").forEach(h => h.onclick = () => h.parentElement.classList.toggle("open"));
}}

document.getElementById("search").oninput = e => {{ active.search = e.target.value; renderFindings(); }};
document.getElementById("surface-filter").onchange = e => {{ active.surface = e.target.value; renderFindings(); }};
document.getElementById("status-filter").onchange = e => {{ active.status = e.target.value; renderFindings(); }};
document.getElementById("sort").onchange = e => {{ active.sort = e.target.value; renderFindings(); }};

renderCoverage(); populateSurfaceFilter(); renderChips(); renderFindings();
</script>
</body>
</html>"""


# --------------------------------------------------------------------------- #
# orchestration
# --------------------------------------------------------------------------- #

_EXPORTERS = {
    "json": export_json,
    "csv": export_csv,
    "sqlite": export_sqlite,
    "db": export_sqlite,
    "html": export_html,
}


def export_results(
    data: ScanResult | Iterable[Finding],
    output_dir: str | Path = "output",
    formats: Iterable[str] = ("json", "csv", "sqlite", "html"),
) -> dict[str, Path]:
    """Export ``data`` to each requested format, returning ``{format: path}``."""
    result = _as_result(data)
    written: dict[str, Path] = {}
    for fmt in formats:
        key = fmt.lower()
        exporter = _EXPORTERS.get(key)
        if exporter is None:
            raise ValueError(f"Unknown export format: {fmt!r}")
        canonical = "sqlite" if key in {"sqlite", "db"} else key
        written[canonical] = exporter(result, output_dir)
    return written


__all__ = [
    "export_csv",
    "export_html",
    "export_json",
    "export_results",
    "export_sqlite",
    "render_html",
]
