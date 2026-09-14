"""Core scanning engine: file discovery, concurrent analysis and aggregation.

The engine is deliberately split into small, side-effect free functions so
that a file can be analysed in a worker thread *or* a worker process:

* :class:`FileWalker`   – fast ``os.scandir`` based discovery with noise
                          pruning and optional gitignore / user excludes.
* :class:`RuleIndex`    – groups rules by extension / filename so each file
                          only sees the rules that can apply to it.
* :func:`analyze_file`  – runs path-only, line, multiline and file-level
                          checkers, performs sanitization awareness and
                          returns classified findings.
* :class:`SurfaceScanner` – orchestrates the above with a thread or process
                          pool and aggregates :class:`ScanResult`.
"""

from __future__ import annotations

import logging
import os
import time
from collections import deque
from collections.abc import Callable, Iterable, Iterator, Sequence
from concurrent.futures import Executor, ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

import pathspec

from attack_surface.models import (
    FileContext,
    FileEntry,
    Finding,
    Hit,
    Rule,
    ScanConfig,
    ScanResult,
    ScanStats,
    Severity,
)
from attack_surface.risk_engine import (
    build_finding,
    dedupe,
    filter_by_threshold,
    prioritize,
    summarize,
)
from attack_surface.rules import SURFACE_BY_KEY, load_rules, resolve_surface_keys, rules_for_surfaces

logger = logging.getLogger("attack_surface.scanner")

# --------------------------------------------------------------------------- #
# Discovery configuration
# --------------------------------------------------------------------------- #

#: Directory names that are never descended into.
DEFAULT_IGNORE_DIRS: frozenset[str] = frozenset(
    {
        ".git", ".hg", ".svn", ".bzr", "CVS",
        "node_modules", "bower_components", "jspm_packages", ".pnpm-store", ".yarn",
        "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".nox", ".hypothesis",
        "venv", ".venv", "env", "ENV", ".env.d", "virtualenv", ".virtualenvs", "site-packages",
        "dist", "build", "_build", "out", ".next", ".nuxt", ".svelte-kit", ".angular", ".parcel-cache",
        ".cache", ".gradle", ".idea", ".vscode", ".vs", ".terraform", ".serverless",
        "target", "bin", "obj", "vendor", "Pods", "DerivedData", ".dart_tool", ".pub-cache",
        "coverage", ".nyc_output", "htmlcov", ".eggs", "*.egg-info", ".ipynb_checkpoints",
    }
)

#: Glob patterns (gitwildmatch) for files that are always skipped.
DEFAULT_IGNORE_GLOBS: tuple[str, ...] = (
    "*.min.js", "*.min.css", "*.map", "*.bundle.js", "*.chunk.js",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock",
    "composer.lock", "Cargo.lock", "Gemfile.lock", "go.sum", "*.egg-info/*",
    "*.pyc", "*.pyo", "*.class", "*.o", "*.a", "*.so", "*.dll", "*.dylib", "*.exe",
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.bmp", "*.ico", "*.webp", "*.svgz", "*.psd",
    "*.mp3", "*.mp4", "*.wav", "*.ogg", "*.avi", "*.mov", "*.mkv", "*.flac",
    "*.woff", "*.woff2", "*.ttf", "*.otf", "*.eot",
    "*.pdf", "*.doc", "*.docx", "*.xls", "*.xlsx", "*.ppt", "*.pptx",
    "*.whl", "*.jar", "*.war", "*.ear", "*.apk", "*.ipa", "*.dmg", "*.iso", "*.img",
)

#: Extensions treated as binary without reading a single byte.
BINARY_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff", ".psd",
        ".mp3", ".mp4", ".wav", ".ogg", ".avi", ".mov", ".mkv", ".flac", ".m4a",
        ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".zst",
        ".whl", ".jar", ".war", ".ear", ".apk", ".ipa", ".dmg", ".iso", ".img",
        ".pyc", ".pyo", ".class", ".o", ".a", ".so", ".dll", ".dylib", ".exe", ".bin",
        ".sqlite", ".sqlite3", ".db", ".mdb", ".p12", ".pfx", ".jks", ".keystore", ".der",
    }
)

_TEXT_SAMPLE = 8192


def is_binary_sample(sample: bytes) -> bool:
    """Heuristic binary detection on the first few KB of a file."""
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    # Proportion of non-text bytes (control chars excluding common whitespace).
    text_chars = bytes(range(32, 127)) + b"\n\r\t\b\f\x1b"
    high = sum(1 for b in sample if b > 127)
    control = sum(1 for b in sample if b < 32 and b not in b"\n\r\t\b\f\x1b")
    if control / len(sample) > 0.05:
        return True
    # Mostly high bytes but no valid UTF-8 => binary
    if high / len(sample) > 0.3:
        try:
            sample.decode("utf-8")
        except UnicodeDecodeError:
            return True
    return len(sample.translate(None, text_chars)) / len(sample) > 0.6


def decode_bytes(data: bytes) -> str:
    """Decode with utf-8 (BOM aware) and fall back to latin-1, never raising."""
    for encoding in ("utf-8-sig", "utf-8"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    try:
        return data.decode("utf-16") if data[:2] in (b"\xff\xfe", b"\xfe\xff") else data.decode("latin-1")
    except UnicodeDecodeError:  # pragma: no cover - latin-1 never fails
        return data.decode("latin-1", errors="replace")


# --------------------------------------------------------------------------- #
# File walker
# --------------------------------------------------------------------------- #


class FileWalker:
    """Recursive discovery with pruning of noisy directories."""

    def __init__(
        self,
        root: Path,
        exclude: Iterable[str] = (),
        respect_gitignore: bool = False,
        include_hidden: bool = True,
        ignore_dirs: Iterable[str] = DEFAULT_IGNORE_DIRS,
    ) -> None:
        self.root = Path(root).resolve()
        self.include_hidden = include_hidden
        self.ignore_dirs = frozenset(ignore_dirs)
        patterns = list(DEFAULT_IGNORE_GLOBS) + [p for p in exclude if p]
        if respect_gitignore:
            patterns.extend(self._load_gitignore(self.root))
        self.spec = pathspec.GitIgnoreSpec.from_lines(patterns)
        self.dir_excludes = [p.rstrip("/") for p in exclude if p.endswith("/")]

    @staticmethod
    def _load_gitignore(root: Path) -> list[str]:
        gitignore = root / ".gitignore"
        if not gitignore.is_file():
            return []
        try:
            return [
                line.strip()
                for line in gitignore.read_text("utf-8", errors="ignore").splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
        except OSError:
            return []

    def _dir_excluded(self, name: str, rel: str) -> bool:
        if name in self.ignore_dirs:
            return True
        if not self.include_hidden and name.startswith(".") and name not in {".github", ".gitlab", ".circleci"}:
            return True
        if name.endswith(".egg-info"):
            return True
        return self.spec.match_file(rel + "/") or self.spec.match_file(rel)

    def walk(self) -> Iterator[FileEntry]:
        """Yield :class:`FileEntry` for every candidate file under ``root``."""
        if self.root.is_file():
            try:
                yield FileEntry(self.root, self.root.name, self.root.stat().st_size)
            except OSError:
                return
            return

        stack: deque[Path] = deque([self.root])
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as it:
                    entries = list(it)
            except (PermissionError, FileNotFoundError, NotADirectoryError, OSError) as exc:
                logger.debug("Cannot list %s: %s", current, exc)
                continue
            for entry in sorted(entries, key=lambda e: e.name):
                try:
                    rel = os.path.relpath(entry.path, self.root).replace(os.sep, "/")
                    if entry.is_dir(follow_symlinks=False):
                        if not self._dir_excluded(entry.name, rel):
                            stack.append(Path(entry.path))
                        continue
                    if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                        continue
                    if self.spec.match_file(rel):
                        continue
                    size = entry.stat(follow_symlinks=False).st_size
                except OSError as exc:
                    logger.debug("Cannot stat %s: %s", entry.path, exc)
                    continue
                yield FileEntry(Path(entry.path), rel, size)


# --------------------------------------------------------------------------- #
# Rule index
# --------------------------------------------------------------------------- #


class RuleIndex:
    """Groups rules so that candidate lookup per file is O(1)-ish."""

    def __init__(self, rules: Sequence[Rule]) -> None:
        self.rules = tuple(rules)
        self.by_ext: dict[str, list[Rule]] = {}
        self.any_ext: list[Rule] = []
        self.named: list[Rule] = []
        for rule in self.rules:
            if rule._filename_patterns:
                self.named.append(rule)
                if not rule._extensions:
                    continue
            if rule._extensions:
                for ext in rule._extensions:
                    self.by_ext.setdefault(ext, []).append(rule)
            elif not rule._filename_patterns:
                self.any_ext.append(rule)

    def candidates(self, entry: FileEntry) -> list[Rule]:
        seen: set[str] = set()
        result: list[Rule] = []
        for rule in self.any_ext:
            seen.add(rule.id)
            result.append(rule)
        for rule in self.by_ext.get(entry.ext, ()):
            if rule.id not in seen:
                seen.add(rule.id)
                result.append(rule)
        for rule in self.named:
            if rule.id not in seen and rule.applies_to(entry):
                seen.add(rule.id)
                result.append(rule)
        return result


@lru_cache(maxsize=8)
def _cached_index(surfaces: tuple[str, ...]) -> RuleIndex:
    return RuleIndex(rules_for_surfaces(surfaces))


# --------------------------------------------------------------------------- #
# Per-file analysis
# --------------------------------------------------------------------------- #


def _sanitization(rule: Rule, ctx: FileContext, line_no: int) -> str | None:
    """Return the sanitizer / mitigation indicator found near ``line_no``."""
    match rule.sanitizer_scope:
        case "line":
            text = ctx.line(line_no)
        case "statement":
            text = ctx.statement(line_no)
        case _:
            text = ctx.window(line_no, rule.context_before, rule.context_after)
    found = rule.find_sanitizer(text)
    if found is None and rule.use_surface_indicators:
        found = SURFACE_BY_KEY[rule.surface].find_indicator(text)
    return found


def _accept_hit(rule: Rule, ctx: FileContext, hit: Hit) -> Hit:
    if not hit.skip_sanitizer_check and hit.mitigated_by is None:
        hit.mitigated_by = _sanitization(rule, ctx, hit.line)
    if not hit.snippet:
        hit.snippet = ctx.line(hit.line)
    return hit


def _run_line_rules(ctx: FileContext, rules: Sequence[Rule]) -> Iterator[tuple[Rule, Hit]]:
    lowered = ctx.lower_lines
    for idx, line in enumerate(ctx.lines):
        if not line or len(line) > 20_000:
            continue
        line_no = idx + 1
        low = lowered[idx]
        for rule in rules:
            if not rule.prefilter(low):
                continue
            if not rule.scan_comments and ctx.is_comment(line_no):
                continue
            if ctx.is_suppressed(line_no, rule.id):
                continue
            for pattern in rule._patterns:
                match = pattern.search(line)
                if not match:
                    continue
                if rule.matches_negative(line):
                    break
                if rule.code_only and ctx.offset_in_string_or_comment(ctx.line_start(line_no) + match.start()):
                    break
                hit: Hit | bool | None = True
                if rule.checker is not None:
                    try:
                        hit = rule.checker(rule, ctx, match, line_no)
                    except Exception as exc:  # pragma: no cover - defensive
                        logger.debug("checker %s failed on %s:%d: %s", rule.id, ctx.rel_path, line_no, exc)
                        hit = None
                if hit is None or hit is False:
                    break
                if hit is True:
                    hit = Hit(line=line_no, snippet=line, column=match.start() + 1)
                yield rule, _accept_hit(rule, ctx, hit)
                break


def _run_multiline_rules(ctx: FileContext, rules: Sequence[Rule]) -> Iterator[tuple[Rule, Hit]]:
    for rule in rules:
        if rule._keywords and not any(k in ctx.text.lower() for k in rule._keywords):
            continue
        for pattern in rule._patterns:
            for match in pattern.finditer(ctx.text):
                line_no = ctx.line_at_offset(match.start())
                block = match.group(0)
                if rule.matches_negative(block):
                    continue
                if not rule.scan_comments and ctx.is_comment(line_no):
                    continue
                if ctx.is_suppressed(line_no, rule.id):
                    continue
                if rule.code_only and ctx.offset_in_string_or_comment(match.start()):
                    continue
                hit: Hit | bool | None = True
                if rule.checker is not None:
                    try:
                        hit = rule.checker(rule, ctx, match, line_no)
                    except Exception as exc:  # pragma: no cover - defensive
                        logger.debug("checker %s failed on %s:%d: %s", rule.id, ctx.rel_path, line_no, exc)
                        hit = None
                if hit is None or hit is False:
                    continue
                if hit is True:
                    hit = Hit(line=line_no, snippet=ctx.line(line_no), column=match.start() - ctx.text.rfind("\n", 0, match.start()))
                yield rule, _accept_hit(rule, ctx, hit)


def _run_file_checkers(ctx: FileContext, rules: Sequence[Rule]) -> Iterator[tuple[Rule, Hit]]:
    for rule in rules:
        if rule.file_checker is None:
            continue
        try:
            hits = list(rule.file_checker(rule, ctx))
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("file checker %s failed on %s: %s", rule.id, ctx.rel_path, exc)
            continue
        for hit in hits:
            if not rule.scan_comments and ctx.is_comment(hit.line):
                continue
            if ctx.is_suppressed(hit.line, rule.id):
                continue
            yield rule, _accept_hit(rule, ctx, hit)


def _read_streaming(path: Path, max_size: int) -> str:
    """Read a large file line by line, never holding more than needed twice."""
    chunks: list[str] = []
    read = 0
    with path.open("rb") as fh:
        for raw in fh:
            read += len(raw)
            if read > max_size:
                break
            chunks.append(decode_bytes(raw))
    return "".join(chunks)


def analyze_file(entry: FileEntry, rules: Sequence[Rule], max_file_size: int, stream_threshold: int) -> tuple[list[Finding], str | None]:
    """Analyse one file with the given rules.

    Returns ``(findings, skip_reason)`` where ``skip_reason`` is ``None`` when
    the file content was analysed, otherwise one of ``"binary"``, ``"size"``
    or ``"error"`` (path-only rules still run in every case).
    """
    findings: list[Finding] = []
    path_rules = [r for r in rules if r.path_only]
    content_rules = [r for r in rules if not r.path_only]

    for rule in path_rules:
        try:
            if rule.file_checker is not None:
                hits = list(rule.file_checker(rule, FileContext(entry, "")))
            else:
                hits = [Hit(line=1, snippet=entry.name)]
            for hit in hits:
                hit.skip_sanitizer_check = True
                findings.append(build_finding(rule, hit, entry.rel_path))
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("path rule %s failed on %s: %s", rule.id, entry.rel_path, exc)

    if not content_rules:
        return findings, None
    if entry.ext in BINARY_EXTENSIONS:
        return findings, "binary"
    if entry.size > max_file_size:
        return findings, "size"

    try:
        with entry.path.open("rb") as fh:
            sample = fh.read(_TEXT_SAMPLE)
            if is_binary_sample(sample):
                return findings, "binary"
            if entry.size > stream_threshold:
                fh.seek(0)
                text = _read_streaming(entry.path, max_file_size)
            else:
                text = decode_bytes(sample + fh.read())
    except (OSError, PermissionError) as exc:
        logger.debug("Cannot read %s: %s", entry.rel_path, exc)
        return findings, "error"

    if not text.strip():
        return findings, None

    ctx = FileContext(entry, text)
    large = entry.size > stream_threshold
    # File-level keyword gate: a rule whose keyword never appears anywhere in the
    # file cannot match any line, so drop it before the per-line loop. This is what
    # keeps large/uniform files (e.g. minified-but-unfiltered, generated code) cheap.
    low_text = ctx.text.lower()

    def _gated(candidates: list[Rule]) -> list[Rule]:
        return [r for r in candidates if not r._keywords or any(k in low_text for k in r._keywords)]

    line_rules = _gated([r for r in content_rules if r._patterns and not r.multiline])
    multiline_rules = [] if large else _gated([r for r in content_rules if r._patterns and r.multiline])
    file_rules = [] if large else [r for r in content_rules if r.file_checker is not None]

    seen: set[tuple[str, int]] = set()
    for rule, hit in _run_line_rules(ctx, line_rules):
        key = (rule.id, hit.line)
        if key in seen:
            continue
        seen.add(key)
        findings.append(build_finding(rule, hit, entry.rel_path))
    for rule, hit in _run_multiline_rules(ctx, multiline_rules):
        key = (rule.id, hit.line)
        if key in seen:
            continue
        seen.add(key)
        findings.append(build_finding(rule, hit, entry.rel_path))
    for rule, hit in _run_file_checkers(ctx, file_rules):
        key = (rule.id, hit.line)
        if key in seen:
            continue
        seen.add(key)
        findings.append(build_finding(rule, hit, entry.rel_path))
    return findings, None


def _worker(entry: FileEntry, surfaces: tuple[str, ...], max_file_size: int, stream_threshold: int) -> tuple[FileEntry, list[Finding], str | None]:
    """Process-pool friendly wrapper (rules are rebuilt lazily per process)."""
    index = _cached_index(surfaces)
    findings, reason = analyze_file(entry, index.candidates(entry), max_file_size, stream_threshold)
    return entry, findings, reason


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

ProgressCallback = Callable[[FileEntry, int], None]


class SurfaceScanner:
    """High level scanner: discover files, analyse them concurrently, aggregate."""

    def __init__(
        self,
        config: ScanConfig,
        rules: Sequence[Rule] | None = None,
        on_file: ProgressCallback | None = None,
        on_discovered: Callable[[int], None] | None = None,
    ) -> None:
        self.config = config
        self.surfaces = resolve_surface_keys(config.surfaces)
        self.rules = tuple(rules) if rules is not None else rules_for_surfaces(self.surfaces)
        self.index = RuleIndex(self.rules)
        self.on_file = on_file
        self.on_discovered = on_discovered
        self.stats = ScanStats(rules_loaded=len(self.rules), surfaces_selected=len(self.surfaces))
        self.findings: list[Finding] = []

    # -- public API -------------------------------------------------------- #

    def discover(self) -> list[FileEntry]:
        walker = FileWalker(
            self.config.target,
            exclude=self.config.exclude,
            respect_gitignore=self.config.respect_gitignore,
            include_hidden=self.config.include_hidden,
        )
        entries = list(walker.walk())
        self.stats.files_discovered = len(entries)
        if self.on_discovered:
            self.on_discovered(len(entries))
        return entries

    def use_processes(self, n_entries: int) -> bool:
        """Analysis is CPU-bound (regex + AST), so threads barely parallelise it.

        Use a process pool when the tree is large enough to amortise fork/IPC cost
        and more than one core is available. The user can force either mode:
        ``--processes`` always uses processes; ``-w 1`` keeps it single/threaded.
        """
        cpus = os.cpu_count() or 1
        if self.config.workers == 1 or cpus < 2:
            return False
        if self.config.process_pool:
            return n_entries > 8
        return n_entries >= 400

    def scan(self) -> ScanResult:
        started = datetime.now(UTC)
        t0 = time.perf_counter()
        entries = self.discover()
        workers = self.config.workers or max(2, min(32, (os.cpu_count() or 4) + 2))
        raw: list[Finding] = []

        if entries:
            if self.use_processes(len(entries)):
                raw.extend(self._run_process_pool(entries, workers))
            else:
                raw.extend(self._run_thread_pool(entries, workers))

        findings = prioritize(
            filter_by_threshold(dedupe(raw), self.config.risk_threshold, self.config.hide_mitigated)
        )
        self.findings = findings
        self.stats.duration_seconds = time.perf_counter() - t0
        finished = datetime.now(UTC)
        summary = summarize(findings, self.surfaces, self.rules, self.stats.files_scanned)
        return ScanResult(
            target=str(Path(self.config.target).resolve()),
            started_at=started.isoformat(timespec="seconds"),
            finished_at=finished.isoformat(timespec="seconds"),
            findings=findings,
            stats=self.stats,
            surfaces_run=self.surfaces,
            summary=summary,
        )

    # -- executors --------------------------------------------------------- #

    def _record(self, entry: FileEntry, findings: list[Finding], reason: str | None) -> None:
        match reason:
            case None:
                self.stats.files_scanned += 1
                self.stats.bytes_scanned += entry.size
            case "binary":
                self.stats.files_skipped_binary += 1
            case "size":
                self.stats.files_skipped_size += 1
            case _:
                self.stats.files_skipped_error += 1
        if self.on_file:
            self.on_file(entry, len(findings))

    def _run_thread_pool(self, entries: Sequence[FileEntry], workers: int) -> list[Finding]:
        results: list[Finding] = []
        cfg = self.config
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="att4ck") as pool:
            futures = {
                pool.submit(analyze_file, entry, self.index.candidates(entry), cfg.max_file_size, cfg.stream_threshold): entry
                for entry in entries
            }
            for future in as_completed(futures):
                entry = futures[future]
                try:
                    findings, reason = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    self.stats.errors.append(f"{entry.rel_path}: {exc}")
                    self._record(entry, [], "error")
                    continue
                results.extend(findings)
                self._record(entry, findings, reason)
        return results

    def _run_process_pool(self, entries: Sequence[FileEntry], workers: int) -> list[Finding]:
        results: list[Finding] = []
        cfg = self.config
        try:
            pool: Executor = ProcessPoolExecutor(max_workers=workers)
        except (OSError, ValueError):  # pragma: no cover - platform dependent
            return self._run_thread_pool(entries, workers)
        with pool:
            futures = {
                pool.submit(_worker, entry, self.surfaces, cfg.max_file_size, cfg.stream_threshold): entry
                for entry in entries
            }
            for future in as_completed(futures):
                entry = futures[future]
                try:
                    _, findings, reason = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    self.stats.errors.append(f"{entry.rel_path}: {exc}")
                    self._record(entry, [], "error")
                    continue
                results.extend(findings)
                self._record(entry, findings, reason)
        return results


def scan_path(
    target: str | os.PathLike[str],
    surfaces: Iterable[str] = (),
    exclude: Iterable[str] = (),
    risk_threshold: str | Severity = Severity.INFO,
    workers: int = 0,
    hide_mitigated: bool = False,
    **kwargs: object,
) -> ScanResult:
    """Convenience wrapper: scan ``target`` and return the :class:`ScanResult`."""
    config = ScanConfig(
        target=Path(target),
        surfaces=tuple(surfaces),
        exclude=tuple(exclude),
        workers=workers,
        risk_threshold=Severity.parse(risk_threshold),
        hide_mitigated=hide_mitigated,
        **kwargs,  # type: ignore[arg-type]
    )
    return SurfaceScanner(config).scan()


__all__ = [
    "BINARY_EXTENSIONS",
    "DEFAULT_IGNORE_DIRS",
    "DEFAULT_IGNORE_GLOBS",
    "FileWalker",
    "RuleIndex",
    "SurfaceScanner",
    "analyze_file",
    "decode_bytes",
    "is_binary_sample",
    "load_rules",
    "scan_path",
]
