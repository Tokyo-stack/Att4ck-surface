"""Core data model shared by the rule catalogue, scanner, risk engine and exporters.

Everything here is a plain dataclass or enum so it can be pickled across
process pools and serialised to JSON / CSV / SQLite without adapters.
"""

from __future__ import annotations

import ast
import bisect
import hashlib
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #


class Severity(str, Enum):
    """Finding severity, ordered from least to most severe."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)

    @property
    def weight(self) -> float:
        return _SEVERITY_WEIGHT[self]

    def downgrade(self, steps: int = 1) -> Severity:
        """Return the severity ``steps`` levels lower (bounded at INFO)."""
        return _SEVERITY_ORDER[max(0, self.rank - steps)]

    def upgrade(self, steps: int = 1) -> Severity:
        """Return the severity ``steps`` levels higher (bounded at CRITICAL)."""
        return _SEVERITY_ORDER[min(len(_SEVERITY_ORDER) - 1, self.rank + steps)]

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        try:
            return cls(value.strip().upper())
        except ValueError as exc:  # pragma: no cover - defensive
            raise ValueError(f"Unknown severity: {value!r}") from exc

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)
_SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.INFO: 1.0,
    Severity.LOW: 2.5,
    Severity.MEDIUM: 5.0,
    Severity.HIGH: 8.0,
    Severity.CRITICAL: 10.0,
}


class Status(str, Enum):
    """Whether a detected pattern appears to be mitigated nearby."""

    VULNERABLE = "VULNERABLE"
    POTENTIALLY_MITIGATED = "POTENTIALLY_MITIGATED"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


# --------------------------------------------------------------------------- #
# File context
# --------------------------------------------------------------------------- #

_COMMENT_PREFIXES = ("#", "//", "/*", "*", "--", "<!--", "'''", '"""', ";")

# Any of these on a line means user-controlled data is involved.
INPUT_MARKERS = re.compile(
    r"request\.(args|form|values|GET|POST|json|data|params|query_params|files|FILES|headers|cookies|get_json)"
    r"|req\.(params|query|body|headers|cookies|files?)\b"
    r"|\$_(GET|POST|REQUEST|COOKIE|FILES)\b"
    r"|\bparams\[|\bparams\.(require|permit|fetch)|c\.(Query|Param|PostForm|FormValue)\("
    r"|r\.(URL\.Query|FormValue|PostFormValue)\(|ctx\.(query|params|request)\b"
    r"|getParameter\(|@RequestParam|@PathVariable|@RequestBody"
    r"|searchParams\.get\(|location\.(search|hash)|document\.URL|window\.name"
    r"|\bargv\b|input\(\)|sys\.stdin|event\[|event\.(body|queryStringParameters|pathParameters)",
    re.IGNORECASE,
)


@dataclass(slots=True)
class FileEntry:
    """A file discovered by the walker."""

    path: Path
    rel_path: str
    size: int

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def ext(self) -> str:
        return self.path.suffix.lower()


class FileContext:
    """Decoded content of a file plus lazily-computed helpers.

    A single instance is shared by every rule that inspects the file, so the
    line split, comment map and Python AST are computed at most once.
    """

    __slots__ = (
        "entry",
        "text",
        "lines",
        "_line_starts",
        "_ast",
        "_ast_attempted",
        "_lower_lines",
        "_comment_flags",
        "extra",
    )

    def __init__(self, entry: FileEntry, text: str) -> None:
        self.entry = entry
        self.text = text
        self.lines: list[str] = text.splitlines()
        self._line_starts: list[int] | None = None
        self._ast: ast.AST | None = None
        self._ast_attempted = False
        self._lower_lines: list[str] | None = None
        self._comment_flags: list[bool] | None = None
        self.extra: dict[str, Any] = {}

    # -- basic accessors --------------------------------------------------- #

    @property
    def path(self) -> Path:
        return self.entry.path

    @property
    def rel_path(self) -> str:
        return self.entry.rel_path

    @property
    def name(self) -> str:
        return self.entry.name

    @property
    def ext(self) -> str:
        return self.entry.ext

    @property
    def line_count(self) -> int:
        return len(self.lines)

    def line(self, number: int) -> str:
        """1-based line access, empty string when out of range."""
        if 1 <= number <= len(self.lines):
            return self.lines[number - 1]
        return ""

    @property
    def lower_lines(self) -> list[str]:
        if self._lower_lines is None:
            self._lower_lines = [line.lower() for line in self.lines]
        return self._lower_lines

    # -- comments ---------------------------------------------------------- #

    def is_comment(self, number: int) -> bool:
        """True when the whole line is a comment (language-agnostic heuristic)."""
        if self._comment_flags is None:
            self._comment_flags = [
                line.lstrip().startswith(_COMMENT_PREFIXES) for line in self.lines
            ]
        if 1 <= number <= len(self._comment_flags):
            return self._comment_flags[number - 1]
        return False

    # -- offsets ----------------------------------------------------------- #

    def line_at_offset(self, offset: int) -> int:
        """Convert a character offset into ``text`` into a 1-based line number."""
        if self._line_starts is None:
            starts = [0]
            for match in re.finditer(r"\n", self.text):
                starts.append(match.end())
            self._line_starts = starts
        return bisect.bisect_right(self._line_starts, offset)

    # -- windows ----------------------------------------------------------- #

    def window(self, number: int, before: int, after: int) -> str:
        """Join lines around ``number`` (1-based, inclusive) into one string."""
        lo = max(0, number - 1 - before)
        hi = min(len(self.lines), number + after)
        return "\n".join(self.lines[lo:hi])

    def statement(self, number: int, max_lines: int = 8) -> str:
        """Best-effort join of a statement spanning multiple lines.

        Starting at ``number`` we accumulate lines until parentheses, brackets
        and braces balance, or ``max_lines`` is reached.
        """
        depth = 0
        collected: list[str] = []
        for idx in range(number - 1, min(len(self.lines), number - 1 + max_lines)):
            line = self.lines[idx]
            collected.append(line)
            depth += line.count("(") + line.count("[") + line.count("{")
            depth -= line.count(")") + line.count("]") + line.count("}")
            if depth <= 0 and idx >= number - 1:
                break
        return "\n".join(collected)

    # -- AST --------------------------------------------------------------- #

    @property
    def tree(self) -> ast.AST | None:
        """Parsed Python AST, or ``None`` when the file is not valid Python."""
        if not self._ast_attempted:
            self._ast_attempted = True
            if self.ext in {".py", ".pyw", ".pyi"}:
                try:
                    self._ast = ast.parse(self.text, filename=str(self.path))
                except (SyntaxError, ValueError, RecursionError, MemoryError):
                    self._ast = None
        return self._ast

    def source_segment(self, node: ast.AST) -> str:
        try:
            return ast.get_source_segment(self.text, node) or ""
        except (ValueError, TypeError):  # pragma: no cover - defensive
            return ""

    def has_input_marker(self, number: int, before: int = 0, after: int = 0) -> bool:
        return bool(INPUT_MARKERS.search(self.window(number, before, after)))


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

RegexLike = str | re.Pattern[str]


def compile_all(patterns: Iterable[RegexLike], flags: int = 0) -> tuple[re.Pattern[str], ...]:
    """Compile every pattern (strings and precompiled patterns accepted)."""
    compiled: list[re.Pattern[str]] = []
    for pattern in patterns:
        if isinstance(pattern, re.Pattern):
            compiled.append(pattern)
        else:
            compiled.append(re.compile(pattern, flags))
    return tuple(compiled)


@dataclass(slots=True)
class Hit:
    """A raw detection produced by a rule before risk classification."""

    line: int
    snippet: str
    column: int = 0
    confidence: int | None = None
    severity: Severity | None = None
    mitigated_by: str | None = None
    name: str | None = None
    description: str | None = None
    cwe: str | None = None
    skip_sanitizer_check: bool = False


CheckerFn = Callable[["Rule", FileContext, "re.Match[str]", int], "Hit | bool | None"]
FileCheckerFn = Callable[["Rule", FileContext], Iterable[Hit]]


@dataclass(slots=True)
class Rule:
    """A single detection rule bound to one attack surface.

    Detection modes (any combination):

    * ``patterns``       – regexes evaluated per line (default) or over the
                           whole text when ``multiline`` is set.
    * ``file_checker``   – a callable that receives the :class:`FileContext`
                           and yields :class:`Hit` objects (AST analysis,
                           structural checks, YAML/JSON parsing, ...).
    * ``path_only``      – the finding is about the file itself; content is
                           never read (backup files, private key material).

    ``checker`` refines a regex hit: it can veto it (``False``/``None``),
    accept it (``True``) or return a customised :class:`Hit`.
    """

    id: str
    surface: str
    name: str
    description: str
    severity: Severity
    cwe: str
    patterns: Sequence[RegexLike] = ()
    sanitizers: Sequence[RegexLike] = ()
    negatives: Sequence[RegexLike] = ()
    extensions: Iterable[str] = ()
    filename_patterns: Sequence[RegexLike] = ()
    keywords: Sequence[str] = ()
    confidence: int = 75
    recommendation: str = ""
    remediation: str = ""
    context_before: int = 6
    context_after: int = 6
    multiline: bool = False
    path_only: bool = False
    scan_comments: bool = False
    case_insensitive: bool = True
    checker: CheckerFn | None = None
    file_checker: FileCheckerFn | None = None
    sanitizer_scope: str = "window"  # "window" | "line" | "statement"
    use_surface_indicators: bool = True
    tags: Sequence[str] = ()

    # compiled state (populated in __post_init__)
    _patterns: tuple[re.Pattern[str], ...] = field(default=(), repr=False)
    _sanitizers: tuple[re.Pattern[str], ...] = field(default=(), repr=False)
    _negatives: tuple[re.Pattern[str], ...] = field(default=(), repr=False)
    _filename_patterns: tuple[re.Pattern[str], ...] = field(default=(), repr=False)
    _extensions: frozenset[str] = field(default=frozenset(), repr=False)
    _keywords: tuple[str, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        self.severity = Severity.parse(self.severity)
        # A bare string is a common slip for a one-element tuple; normalise it.
        for attr in ("patterns", "sanitizers", "negatives", "filename_patterns", "keywords", "tags"):
            value = getattr(self, attr)
            if isinstance(value, (str, re.Pattern)):
                setattr(self, attr, (value,))
        if isinstance(self.extensions, str):
            self.extensions = (self.extensions,)
        base_flags = re.IGNORECASE if self.case_insensitive else 0
        line_flags = base_flags | (re.MULTILINE | re.DOTALL if self.multiline else 0)
        self._patterns = compile_all(self.patterns, line_flags)
        self._sanitizers = compile_all(self.sanitizers, re.IGNORECASE)
        self._negatives = compile_all(self.negatives, re.IGNORECASE)
        self._filename_patterns = compile_all(self.filename_patterns, re.IGNORECASE)
        self._extensions = frozenset(e.lower() if e.startswith(".") else f".{e.lower()}" for e in self.extensions)
        self._keywords = tuple(k.lower() for k in self.keywords)
        if not (self._patterns or self.file_checker or self.path_only):
            raise ValueError(f"Rule {self.id} defines no detection logic")
        if not 0 <= self.confidence <= 100:
            raise ValueError(f"Rule {self.id} confidence must be 0-100")
        if self.sanitizer_scope not in {"window", "line", "statement"}:
            raise ValueError(f"Rule {self.id} has invalid sanitizer_scope {self.sanitizer_scope!r}")

    # -- applicability ----------------------------------------------------- #

    @property
    def any_extension(self) -> bool:
        return not self._extensions and not self._filename_patterns

    def applies_to(self, entry: FileEntry) -> bool:
        """True when this rule should run against ``entry``."""
        if self._filename_patterns:
            rel = entry.rel_path.replace("\\", "/")
            if any(p.search(rel) or p.search(entry.name) for p in self._filename_patterns):
                return True
            if not self._extensions:
                return False
        if self._extensions:
            return entry.ext in self._extensions
        return True

    def prefilter(self, lowered_line: str) -> bool:
        """Cheap substring gate applied before running the regexes."""
        if not self._keywords:
            return True
        return any(keyword in lowered_line for keyword in self._keywords)

    def matches_negative(self, text: str) -> bool:
        return any(p.search(text) for p in self._negatives)

    def find_sanitizer(self, text: str) -> str | None:
        for pattern in self._sanitizers:
            match = pattern.search(text)
            if match:
                return match.group(0)
        return None


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class Finding:
    """A classified, exportable security finding."""

    id: str
    rule_id: str
    surface: str
    surface_number: int
    surface_name: str
    package: str
    name: str
    description: str
    severity: Severity
    base_severity: Severity
    confidence: int
    status: Status
    cwe: str
    file: str
    line: int
    column: int
    snippet: str
    recommendation: str
    remediation: str
    mitigation: str | None = None
    risk_score: float = 0.0
    priority: int = 0
    tags: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "surface": self.surface,
            "surface_number": self.surface_number,
            "surface_name": self.surface_name,
            "package": self.package,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "base_severity": self.base_severity.value,
            "confidence": self.confidence,
            "status": self.status.value,
            "cwe": self.cwe,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "mitigation": self.mitigation,
            "recommendation": self.recommendation,
            "remediation": self.remediation,
            "risk_score": self.risk_score,
            "priority": self.priority,
            "tags": list(self.tags),
        }

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}"

    @property
    def is_mitigated(self) -> bool:
        return self.status is Status.POTENTIALLY_MITIGATED


def finding_id(rule_id: str, rel_path: str, line: int, snippet: str) -> str:
    """Stable identifier so re-scans of the same tree produce the same ids."""
    digest = hashlib.sha1(f"{rule_id}|{rel_path}|{line}|{snippet.strip()}".encode("utf-8", "replace")).hexdigest()
    return f"AS-{digest[:12]}"


# --------------------------------------------------------------------------- #
# Scan configuration & results
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class ScanConfig:
    """Everything the scanner needs to run, independent of the CLI layer."""

    target: Path
    surfaces: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    workers: int = 0
    max_file_size: int = 5 * 1024 * 1024
    stream_threshold: int = 1024 * 1024
    respect_gitignore: bool = False
    include_hidden: bool = True
    process_pool: bool = False
    risk_threshold: Severity = Severity.INFO
    hide_mitigated: bool = False
    verbose: bool = False
    debug: bool = False


@dataclass(slots=True)
class ScanStats:
    files_discovered: int = 0
    files_scanned: int = 0
    files_skipped_binary: int = 0
    files_skipped_size: int = 0
    files_skipped_error: int = 0
    bytes_scanned: int = 0
    duration_seconds: float = 0.0
    rules_loaded: int = 0
    surfaces_selected: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_discovered": self.files_discovered,
            "files_scanned": self.files_scanned,
            "files_skipped_binary": self.files_skipped_binary,
            "files_skipped_size": self.files_skipped_size,
            "files_skipped_error": self.files_skipped_error,
            "bytes_scanned": self.bytes_scanned,
            "duration_seconds": round(self.duration_seconds, 3),
            "rules_loaded": self.rules_loaded,
            "surfaces_selected": self.surfaces_selected,
            "errors": list(self.errors),
        }


@dataclass(slots=True)
class ScanResult:
    target: str
    started_at: str
    finished_at: str
    findings: list[Finding]
    stats: ScanStats
    surfaces_run: tuple[str, ...]
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "meta": {
                "target": self.target,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "surfaces_run": list(self.surfaces_run),
            },
            "stats": self.stats.to_dict(),
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }
