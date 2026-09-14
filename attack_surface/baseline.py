"""Baseline support: accept the current set of findings and fail only on new ones.

A baseline is a small JSON file listing the stable ids (and metadata) of
findings that were present when it was written. On a later scan, findings whose
id appears in the baseline are marked and can be filtered out, so CI gates only
react to *newly introduced* issues instead of the whole backlog.

Finding ids are the stable ``AS-<hash>`` values produced by
:func:`attack_surface.models.finding_id` (rule + path + line + snippet), so they
survive re-scans as long as the code around them does not move.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from attack_surface.models import Finding
from attack_surface.version import __version__

BASELINE_VERSION = 1


def build_baseline(findings: Iterable[Finding], target: str = "") -> dict[str, Any]:
    """Serialise ``findings`` into a baseline document."""
    findings = list(findings)
    return {
        "baseline_version": BASELINE_VERSION,
        "tool_version": __version__,
        "target": target,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "count": len(findings),
        "findings": sorted(
            {
                f.id: {
                    "id": f.id,
                    "rule_id": f.rule_id,
                    "surface": f.surface,
                    "file": f.file,
                    "line": f.line,
                    "severity": f.severity.value,
                }
                for f in findings
            }.values(),
            key=lambda d: (d["file"], d["line"], d["rule_id"]),
        ),
    }


def write_baseline(findings: Iterable[Finding], path: str | Path, target: str = "") -> Path:
    """Write a baseline file and return its path."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_baseline(findings, target), indent=2), encoding="utf-8")
    return path


def load_baseline(path: str | Path) -> set[str]:
    """Load a baseline file and return the set of known finding ids.

    Raises ``ValueError`` if the file is malformed or is not an ATT4ck baseline.
    """
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read baseline {path}: {exc}") from exc
    if not isinstance(data, dict) or "findings" not in data:
        raise ValueError(f"{path} is not a valid ATT4ck baseline file")
    ids = {entry.get("id") for entry in data.get("findings", []) if isinstance(entry, dict)}
    return {i for i in ids if isinstance(i, str)}


def apply_baseline(findings: Iterable[Finding], known: set[str]) -> tuple[list[Finding], int]:
    """Split findings into ``(new, suppressed_count)`` against a baseline id set."""
    new: list[Finding] = []
    suppressed = 0
    for finding in findings:
        if finding.id in known:
            suppressed += 1
        else:
            new.append(finding)
    return new, suppressed


__all__ = ["build_baseline", "write_baseline", "load_baseline", "apply_baseline", "BASELINE_VERSION"]
