"""Risk engine: scoring, classification, prioritisation and summary statistics.

Scores are on a 0-10 scale::

    risk = severity_weight * (confidence / 100) * mitigation_factor

A finding that appears to be mitigated nearby has its severity downgraded one
level and its confidence reduced, so it still surfaces in reports but ranks
below un-mitigated findings of the same rule.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from typing import Any

from attack_surface.models import Finding, Hit, Rule, Severity, Status, finding_id
from attack_surface.rules import SURFACE_BY_KEY, SURFACE_COUNT, SURFACES, Surface

MITIGATION_FACTOR = 0.5
MITIGATED_CONFIDENCE_PENALTY = 30
MIN_CONFIDENCE = 10

SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


def calculate_risk_score(severity: Severity, confidence: int, mitigated: bool = False) -> float:
    """Return the 0-10 risk score for a severity / confidence pair."""
    score = severity.weight * (max(MIN_CONFIDENCE, min(100, confidence)) / 100.0)
    if mitigated:
        score *= MITIGATION_FACTOR
    return round(score, 2)


def build_finding(rule: Rule, hit: Hit, rel_path: str) -> Finding:
    """Turn a raw :class:`Hit` into a classified :class:`Finding`."""
    surface: Surface = SURFACE_BY_KEY[rule.surface]
    base_severity = hit.severity or rule.severity
    confidence = hit.confidence if hit.confidence is not None else rule.confidence
    status = Status.VULNERABLE
    severity = base_severity
    mitigation = None
    if hit.mitigated_by:
        status = Status.POTENTIALLY_MITIGATED
        severity = base_severity.downgrade()
        confidence = max(MIN_CONFIDENCE, confidence - MITIGATED_CONFIDENCE_PENALTY)
        mitigation = hit.mitigated_by.strip()
    snippet = hit.snippet.strip()[:300]
    return Finding(
        id=finding_id(rule.id, rel_path, hit.line, snippet),
        rule_id=rule.id,
        surface=surface.key,
        surface_number=surface.number,
        surface_name=surface.name,
        package=surface.package,
        name=hit.name or rule.name,
        description=hit.description or rule.description,
        severity=severity,
        base_severity=base_severity,
        confidence=int(confidence),
        status=status,
        cwe=hit.cwe or rule.cwe or surface.cwe,
        file=rel_path,
        line=hit.line,
        column=hit.column,
        snippet=snippet,
        recommendation=rule.recommendation,
        remediation=rule.remediation,
        mitigation=mitigation,
        risk_score=calculate_risk_score(severity, int(confidence), status is Status.POTENTIALLY_MITIGATED),
        tags=tuple(rule.tags),
    )


def prioritize(findings: Iterable[Finding]) -> list[Finding]:
    """Sort by risk score, severity, confidence then location and assign ranks."""
    ordered = sorted(
        findings,
        key=lambda f: (-f.risk_score, -f.severity.rank, -f.confidence, f.file, f.line, f.rule_id),
    )
    for rank, finding in enumerate(ordered, start=1):
        finding.priority = rank
    return ordered


def filter_by_threshold(findings: Iterable[Finding], threshold: Severity, hide_mitigated: bool = False) -> list[Finding]:
    """Keep findings at or above ``threshold`` (optionally dropping mitigated ones)."""
    kept: list[Finding] = []
    for finding in findings:
        if finding.severity.rank < threshold.rank:
            continue
        if hide_mitigated and finding.status is Status.POTENTIALLY_MITIGATED:
            continue
        kept.append(finding)
    return kept


def dedupe(findings: Iterable[Finding]) -> list[Finding]:
    """Drop exact duplicates (same rule, file and line)."""
    seen: set[tuple[str, str, int]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.file, finding.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def summarize(
    findings: Sequence[Finding],
    surfaces_run: Iterable[str],
    rules: Sequence[Rule],
    files_scanned: int,
) -> dict[str, Any]:
    """Compute the aggregate statistics used by the CLI and every report."""
    surfaces_run = tuple(surfaces_run)
    by_severity = Counter(f.severity.value for f in findings)
    by_status = Counter(f.status.value for f in findings)
    by_surface_count: Counter[str] = Counter(f.surface for f in findings)
    by_surface_risk: dict[str, float] = defaultdict(float)
    by_surface_max: dict[str, Severity] = {}
    by_package: Counter[str] = Counter(f.package for f in findings)
    by_file: Counter[str] = Counter(f.file for f in findings)
    by_cwe: Counter[str] = Counter(f.cwe for f in findings)

    for finding in findings:
        by_surface_risk[finding.surface] += finding.risk_score
        current = by_surface_max.get(finding.surface)
        if current is None or finding.severity.rank > current.rank:
            by_surface_max[finding.surface] = finding.severity

    rules_per_surface = Counter(rule.surface for rule in rules)
    surface_rows: list[dict[str, Any]] = []
    for surface in SURFACES:
        scanned = surface.key in surfaces_run
        count = by_surface_count.get(surface.key, 0)
        surface_rows.append(
            {
                "number": surface.number,
                "key": surface.key,
                "name": surface.name,
                "package": surface.package,
                "description": surface.description,
                "scanned": scanned,
                "rules": rules_per_surface.get(surface.key, 0),
                "findings": count,
                "vulnerable": sum(
                    1 for f in findings if f.surface == surface.key and f.status is Status.VULNERABLE
                ),
                "mitigated": sum(
                    1 for f in findings if f.surface == surface.key and f.status is Status.POTENTIALLY_MITIGATED
                ),
                "risk": round(by_surface_risk.get(surface.key, 0.0), 2),
                "max_severity": by_surface_max[surface.key].value if surface.key in by_surface_max else None,
            }
        )

    top_surfaces = sorted(
        (row for row in surface_rows if row["findings"]),
        key=lambda row: (-row["risk"], -row["findings"], row["number"]),
    )[:10]

    total_risk = round(sum(f.risk_score for f in findings), 2)
    max_possible = max(1.0, len(findings) * Severity.CRITICAL.weight)
    overall = "CLEAN"
    for severity in SEVERITY_ORDER:
        if by_severity.get(severity.value):
            overall = severity.value
            break

    return {
        "total_findings": len(findings),
        "overall_risk": overall,
        "total_risk_score": total_risk,
        "normalized_risk": round(total_risk / max_possible * 10, 2) if findings else 0.0,
        "by_severity": {s.value: by_severity.get(s.value, 0) for s in SEVERITY_ORDER},
        "by_status": {s.value: by_status.get(s.value, 0) for s in Status},
        "by_package": dict(sorted(by_package.items())),
        "by_cwe": dict(by_cwe.most_common(15)),
        "top_files": [{"file": path, "findings": count} for path, count in by_file.most_common(10)],
        "top_surfaces": top_surfaces,
        "surfaces": surface_rows,
        "coverage": {
            "surfaces_total": SURFACE_COUNT,
            "surfaces_scanned": len(surfaces_run),
            "surfaces_with_findings": len(by_surface_count),
            "coverage_percent": round(len(surfaces_run) / SURFACE_COUNT * 100, 1),
            "rules_executed": len(rules),
            "files_scanned": files_scanned,
        },
    }


def severity_at_or_above(findings: Iterable[Finding], threshold: Severity, include_mitigated: bool = False) -> int:
    """Count findings that meet the threshold (used by ``--fail-on``)."""
    return sum(
        1
        for f in findings
        if f.severity.rank >= threshold.rank and (include_mitigated or f.status is Status.VULNERABLE)
    )


__all__ = [
    "MITIGATION_FACTOR",
    "SEVERITY_ORDER",
    "build_finding",
    "calculate_risk_score",
    "dedupe",
    "filter_by_threshold",
    "prioritize",
    "severity_at_or_above",
    "summarize",
]
