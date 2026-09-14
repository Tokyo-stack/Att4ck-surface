"""Scanner engine unit tests: discovery, binary handling, robustness."""

from __future__ import annotations

from pathlib import Path

from attack_surface.models import ScanConfig, Severity
from attack_surface.scanner import FileWalker, decode_bytes, is_binary_sample, scan_path


def test_binary_detection():
    assert is_binary_sample(b"\x00\x01\x02\x03")
    assert is_binary_sample(bytes(range(256)) * 4)
    assert not is_binary_sample(b"def foo():\n    return 1\n")
    assert not is_binary_sample(b"")


def test_decode_never_raises():
    assert decode_bytes(b"\xff\xfe\x00hello") is not None
    assert decode_bytes("héllo".encode()) == "héllo"
    assert decode_bytes(b"\x80\x81\x82") is not None


def test_walker_prunes_noise(tmp_path: Path):
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "lib.js").write_text("var x = 1;\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n")
    (tmp_path / "bundle.min.js").write_text("var a=1;\n")
    found = {e.rel_path for e in FileWalker(tmp_path).walk()}
    assert "app.py" in found
    assert not any("node_modules" in f for f in found)
    assert not any(".git" in f for f in found)
    assert "bundle.min.js" not in found


def test_scan_single_file(tmp_path: Path):
    f = tmp_path / "v.py"
    f.write_text("import hashlib\nx = hashlib.md5(password).hexdigest()\n")
    result = scan_path(f)
    assert any(finding.surface == "authentication" for finding in result.findings)


def test_scan_empty_dir(tmp_path: Path):
    result = scan_path(tmp_path)
    assert result.findings == []
    assert result.summary["total_findings"] == 0
    assert result.summary["coverage"]["surfaces_scanned"] == 40


def test_scan_survives_bad_files(tmp_path: Path):
    (tmp_path / "broken.py").write_text("def (:\n  this is not valid python !!!\n")
    (tmp_path / "binary.py").write_bytes(b"\x00\x01\x02\x03\xff\xfe")
    (tmp_path / "empty.py").write_text("")
    result = scan_path(tmp_path)  # must not raise
    assert result is not None


def test_surface_selection(tmp_path: Path):
    f = tmp_path / "v.py"
    f.write_text("import hashlib\nx = hashlib.md5(pw).hexdigest()\neval(user_input)\n")
    only_auth = scan_path(f, surfaces=["authentication"])
    assert {finding.surface for finding in only_auth.findings} <= {"authentication"}


def test_risk_threshold(tmp_path: Path):
    f = tmp_path / "cfg.py"
    f.write_text("import os\nAPI_BASE = 'https://api-staging.internal.acme.io'\n")
    low = scan_path(f, risk_threshold=Severity.INFO)
    high = scan_path(f, risk_threshold=Severity.CRITICAL)
    assert len(high.findings) <= len(low.findings)


def test_findings_are_prioritized(tmp_path: Path):
    (tmp_path / "a.py").write_text(
        "import hashlib\n"
        "pw = hashlib.md5(x).hexdigest()\n"
        "cur.execute('SELECT * FROM t WHERE id = ' + request.args['id'])\n"
    )
    result = scan_path(tmp_path)
    priorities = [f.priority for f in result.findings]
    assert priorities == sorted(priorities)
    scores = [f.risk_score for f in result.findings]
    assert scores == sorted(scores, reverse=True)


def test_process_pool_matches_threads(tmp_path: Path):
    for i in range(12):
        (tmp_path / f"f{i}.py").write_text("import hashlib\nhashlib.md5(pw)\n")
    threaded = scan_path(tmp_path, process_pool=False)
    pooled = scan_path(tmp_path, process_pool=True)
    assert len(threaded.findings) == len(pooled.findings)


def test_large_uniform_file_is_cheap(tmp_path: Path):
    """A big file with no rule keywords must be gated out of the per-line loop.

    Guards against the O(lines x rules) pathology: 200k trivial lines should
    scan in well under a couple of seconds even single-threaded.
    """
    import time

    big = tmp_path / "generated.py"
    big.write_text("x = 1\n" * 200_000)
    t0 = time.perf_counter()
    result = scan_path(big, workers=1)
    elapsed = time.perf_counter() - t0
    assert result.findings == []
    assert elapsed < 3.0, f"large uniform file took {elapsed:.1f}s (keyword gate regressed)"


def test_use_processes_decision(tmp_path: Path):
    from attack_surface.scanner import SurfaceScanner

    (tmp_path / "a.py").write_text("x = 1\n")
    # forced single worker never uses processes
    s1 = SurfaceScanner(ScanConfig(target=tmp_path, workers=1))
    assert s1.use_processes(10_000) is False
    # small trees stay on threads (fork overhead not worth it)
    s2 = SurfaceScanner(ScanConfig(target=tmp_path))
    assert s2.use_processes(10) is False
