"""Tests for inline att4ck:ignore suppression, code_only and baseline."""

from __future__ import annotations

import json
from pathlib import Path

from attack_surface.baseline import apply_baseline, load_baseline, write_baseline
from attack_surface.models import FileContext, FileEntry
from attack_surface.scanner import _cached_index, analyze_file


def _ctx(text: str, name: str = "m.py") -> FileContext:
    entry = FileEntry(path=Path(name), rel_path=name, size=len(text))
    return FileContext(entry, text)


def _scan(tmp_path, text: str, name: str = "m.py"):
    path = tmp_path / name
    path.write_text(text)
    entry = FileEntry(path=path, rel_path=name, size=len(text))
    index = _cached_index(())
    findings, reason = analyze_file(entry, index.candidates(entry), 1 << 20, 1 << 20)
    assert reason is None, f"unexpected skip: {reason}"
    return findings


# -- FileContext-level suppression logic ------------------------------------ #

def test_trailing_marker_suppresses_only_its_line() -> None:
    ctx = _ctx("a\nb  # att4ck:ignore\nc\n")
    assert not ctx.is_suppressed(1, "X")
    assert ctx.is_suppressed(2, "X")
    assert not ctx.is_suppressed(3, "X")  # trailing marker must not leak downward


def test_standalone_marker_covers_next_line() -> None:
    ctx = _ctx("# att4ck:ignore\ncode_here\n")
    assert ctx.is_suppressed(2, "ANY-RULE")


def test_per_rule_id_targeting() -> None:
    ctx = _ctx("x  # att4ck:ignore[AUTH-001]\n")
    assert ctx.is_suppressed(1, "AUTH-001")
    assert not ctx.is_suppressed(1, "OTHER-001")


# -- End-to-end through analyze_file ---------------------------------------- #

def test_inline_ignore_removes_finding(tmp_path) -> None:
    flagged = _scan(tmp_path, "import hashlib\nh = hashlib.md5(x).hexdigest()\n")
    assert any(f.rule_id == "AUTH-001" for f in flagged)
    suppressed = _scan(tmp_path, "import hashlib\nh = hashlib.md5(x).hexdigest()  # att4ck:ignore\n", "n.py")
    assert not any(f.rule_id == "AUTH-001" for f in suppressed)


def test_code_only_ignores_match_inside_string(tmp_path) -> None:
    in_string = _scan(tmp_path, 'PATTERN = "app.debug = True"\n', "pat.py")
    assert not any(f.rule_id == "DBG-001" for f in in_string)
    real_code = _scan(tmp_path, "app.debug = True\n", "settings.py")
    assert any(f.rule_id == "DBG-001" for f in real_code)


def test_baseline_round_trip(tmp_path) -> None:
    findings = _scan(tmp_path, "import hashlib\nh = hashlib.md5(x).hexdigest()\n")
    assert findings
    path = write_baseline(findings, tmp_path / "base.json", target="x")
    doc = json.loads(path.read_text())
    assert doc["count"] == len(findings)
    known = load_baseline(path)
    new, suppressed = apply_baseline(findings, known)
    assert new == []
    assert suppressed == len(findings)


def test_baseline_reports_new_finding(tmp_path) -> None:
    # Same file path so ids are comparable: the pre-existing line-2 finding is
    # suppressed by the baseline, the newly added line-3 one is reported.
    old = _scan(tmp_path, "import hashlib\nh = hashlib.md5(x).hexdigest()\n", "app.py")
    known = load_baseline(write_baseline(old, tmp_path / "b.json"))
    more = _scan(tmp_path, "import hashlib\nh = hashlib.md5(x).hexdigest()\ng = hashlib.sha1(y).hexdigest()\n", "app.py")
    new, suppressed = apply_baseline(more, known)
    assert suppressed >= 1
    assert any(f.line == 3 for f in new)
    assert not any(f.line == 2 for f in new)
