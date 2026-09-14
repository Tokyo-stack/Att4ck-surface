"""Shared helpers for rule checkers: AST utilities, taint heuristics, entropy.

Surface modules import from here so that the individual detectors stay short
and focused on *what* to detect rather than *how* to walk source code.
"""

from __future__ import annotations

import ast
import math
import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass

from attack_surface.models import INPUT_MARKERS, FileContext, Hit

# --------------------------------------------------------------------------- #
# Regex fragments reused across surfaces
# --------------------------------------------------------------------------- #

#: Values that are obviously placeholders, never real secrets.
PLACEHOLDER = re.compile(
    r"^\s*$|\$\{|\{\{|%\(|<[^>]*>|^\.\.\.$|^x{3,}$|^\*{3,}$|example|sample|placeholder|dummy|changeme|change_me|"
    r"your[_-]?(api|secret|key|token|password)|your_|todo|fixme|redacted|^null$|^none$|^true$|^false$|"
    r"^undefined$|^\$\w+$|^@\w+$|^\?$|^#|^\s*env\(|^os\.|^process\.|getenv|environ|secrets\.|vault|"
    r"^[a-z_]+$|^(password|secret|token|api_key|apikey|key|value|string|test|testing|pass|passwd)$|^\d{1,5}$|"
    r"^(12345678|123456789|password123|admin123|qwerty|letmein|secret123|s3cr3t)$|lorem|ipsum|"
    r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$",
    re.IGNORECASE,
)

#: Identifiers that denote a credential-like value.
SECRET_KEY_NAMES = (
    r"(?:api[_-]?key|apikey|secret[_-]?key|secret|client[_-]?secret|private[_-]?key|access[_-]?key|"
    r"access[_-]?token|auth[_-]?token|refresh[_-]?token|bearer[_-]?token|token|passwd|password|pwd|"
    r"db[_-]?pass(?:word)?|database[_-]?password|master[_-]?key|encryption[_-]?key|signing[_-]?key|"
    r"aws[_-]?secret[_-]?access[_-]?key|credentials?|connection[_-]?string|jwt[_-]?secret|session[_-]?secret|"
    r"webhook[_-]?secret|app[_-]?secret|consumer[_-]?secret|service[_-]?account[_-]?key)"
)

SENSITIVE_DATA = (
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|credit[_-]?card|card[_-]?number|"
    r"cardnumber|\bcvv\b|\bcvc\b|\bssn\b|social[_-]?security|private[_-]?key|session[_-]?id|cookie|\bjwt\b|"
    r"bearer|\botp\b|\bpin\b|credentials|access[_-]?key|client[_-]?secret|refresh[_-]?token)"
)

PII_DATA = (
    r"(?:\bemail\b|e_mail|phone[_-]?number|\bphone\b|\bdob\b|date[_-]?of[_-]?birth|birth[_-]?date|home[_-]?address|"
    r"street[_-]?address|passport|national[_-]?id|\biban\b|account[_-]?number|tax[_-]?id|driver[_-]?licen[cs]e|"
    r"first[_-]?name|last[_-]?name|full[_-]?name|\bip[_-]?address\b)"
)

ROUTE_DECORATOR = re.compile(
    r"@\s*(?:\w+\.)*(?:route|get|post|put|delete|patch|api_route|view|endpoint|websocket|options|head)\s*\(",
    re.IGNORECASE,
)

AUTH_DECORATOR = re.compile(
    r"login_required|permission_required|jwt_required|requires?_auth|auth_required|roles?_required|"
    r"roles?_accepted|has_perm|user_passes_test|staff_member_required|superuser_required|admin_required|"
    r"authenticated|token_required|api_key_required|Depends\(|permission_classes|IsAuthenticated|IsAdminUser|"
    r"csrf_protect|require_http_methods|@authenticated|@protected|@secure|verify_jwt|check_auth|require_role|"
    r"require_login|login_manager|fresh_login_required|authorize\b|Authorize\(|require_api_key|scope_required|"
    r"require_scope|basic_auth_required|auth\.login_required|api_key_auth",
    re.IGNORECASE,
)

JS_AUTH_MIDDLEWARE = re.compile(
    r"\b(?:auth|authenticate|authenticated|isAuthenticated|isAuth|requireAuth|requireLogin|ensureAuth\w*|"
    r"ensureLoggedIn|verifyToken|verifyJwt|verifyJWT|checkAuth|checkToken|protect|protected|guard|passport\.authenticate|"
    r"jwtCheck|jwt\(|jwtMiddleware|expressjwt|requiresAuth|withAuth|authMiddleware|authorize|authorization|"
    r"isAdmin|requireAdmin|adminOnly|hasRole|checkRole|requireRole|apiKeyAuth|validateApiKey|requireApiKey|"
    r"session\.user|req\.user|clerk|auth0|supabase\.auth|firebase\.auth|getSession|getServerSession|"
    r"authGuard|AuthGuard|UseGuards|@Auth|withApiAuth|withPageAuth)",
    re.IGNORECASE,
)

STRING_LITERAL = re.compile(r"""("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`)""")

# --------------------------------------------------------------------------- #
# Small text helpers
# --------------------------------------------------------------------------- #


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character for ``value`` (0.0 for empty strings)."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def looks_like_secret(value: str, min_length: int = 8, min_entropy: float = 3.0) -> bool:
    """True when ``value`` is long and random enough to be a real credential."""
    value = value.strip().strip("'\"`")
    if len(value) < min_length:
        return False
    if PLACEHOLDER.search(value):
        return False
    if len(set(value)) <= 2:
        return False
    return shannon_entropy(value) >= min_entropy or bool(re.search(r"[A-Z]", value) and re.search(r"[0-9]", value) and len(value) >= 16)


def strip_strings(line: str, keep_interpolation: bool = True) -> str:
    """Remove string literal contents, optionally keeping ``{expr}`` / ``${expr}`` bodies."""

    def _replace(match: re.Match[str]) -> str:
        body = match.group(0)
        if keep_interpolation:
            parts = re.findall(r"\$?\{([^{}]*)\}", body)
            if parts:
                return '"' + " ".join(parts) + '"'
            if body[0] == "`" or re.search(r"%\(", body):
                return '""'
        return '""'

    return STRING_LITERAL.sub(_replace, line)


def is_pure_literal(expr: str) -> bool:
    """True when ``expr`` is only a string literal (no concatenation/interpolation)."""
    expr = expr.strip().rstrip(";").strip()
    if not expr:
        return False
    match = STRING_LITERAL.fullmatch(expr)
    if not match:
        return False
    if expr[0] == "`" and "${" in expr:
        return False
    return True


def has_input(text: str) -> bool:
    return bool(INPUT_MARKERS.search(text))


def lookahead(ctx: FileContext, line_no: int, count: int) -> str:
    return ctx.window(line_no, 0, count)


def lookbehind(ctx: FileContext, line_no: int, count: int) -> str:
    return ctx.window(line_no, count, 0)


def var_from_input(ctx: FileContext, line_no: int, name: str, lookback: int = 15) -> bool:
    """True when ``name`` was assigned from user input within ``lookback`` lines."""
    if not name or not re.match(r"^[A-Za-z_]\w*$", name):
        return False
    window = lookbehind(ctx, line_no, lookback)
    pattern = re.compile(rf"(?:^|[\s(,])(?:const|let|var|\$)?\s*{re.escape(name)}\s*(?::\s*\w+)?\s*=\s*(.+)$", re.MULTILINE)
    for match in pattern.finditer(window):
        if INPUT_MARKERS.search(match.group(1)):
            return True
    return False


def extract_call_arg(text: str, start: int) -> str:
    """Return the balanced parenthesised argument list starting at ``start``."""
    depth = 0
    buf: list[str] = []
    started = False
    for ch in text[start:]:
        if ch == "(":
            depth += 1
            started = True
            if depth == 1:
                continue
        elif ch == ")":
            depth -= 1
            if depth == 0 and started:
                break
        if started:
            buf.append(ch)
        if len(buf) > 2000:
            break
    return "".join(buf)


def first_arg(call_args: str) -> str:
    """First top-level argument of a call argument string."""
    depth = 0
    for idx, ch in enumerate(call_args):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            return call_args[:idx].strip()
    return call_args.strip()


def identifiers_in(expr: str) -> list[str]:
    return re.findall(r"[A-Za-z_]\w*", expr)


def arg_tainted(ctx: FileContext, line_no: int, expr: str, lookback: int = 15) -> bool:
    """True when the expression uses input directly or via a recently tainted variable."""
    if has_input(expr):
        return True
    for ident in identifiers_in(expr):
        if ident in {"request", "req", "params", "self", "this"}:
            continue
        if var_from_input(ctx, line_no, ident, lookback):
            return True
    return False


# --------------------------------------------------------------------------- #
# Python AST helpers
# --------------------------------------------------------------------------- #


def dotted_name(node: ast.AST) -> str:
    """``a.b.c`` for Attribute/Name chains, ``""`` otherwise."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        inner = dotted_name(node.func)
        if inner:
            parts.append(inner + "()")
    else:
        return ""
    return ".".join(reversed(parts))


def call_name(node: ast.Call) -> str:
    return dotted_name(node.func)


def iter_calls(tree: ast.AST) -> Iterator[ast.Call]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node


def iter_functions(tree: ast.AST) -> Iterator[ast.FunctionDef | ast.AsyncFunctionDef]:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def is_constant_str(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def is_dynamic_string(node: ast.AST) -> bool:
    """f-string, ``%`` / ``+`` on strings, ``.format()`` or ``str.join`` on non-literals."""
    match node:
        case ast.JoinedStr():
            return any(isinstance(v, ast.FormattedValue) for v in node.values)
        case ast.BinOp(op=ast.Mod() | ast.Add()):
            return not (isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant))
        case ast.Call(func=ast.Attribute(attr="format")):
            return True
        case ast.Call(func=ast.Attribute(attr="join", value=ast.Constant())):
            return True
        case ast.Name() | ast.Attribute() | ast.Subscript():
            return True
        case _:
            return False


def node_source(ctx: FileContext, node: ast.AST) -> str:
    return ctx.source_segment(node)


def node_tainted(ctx: FileContext, node: ast.AST, lookback: int = 20) -> bool:
    source = node_source(ctx, node)
    if has_input(source):
        return True
    line_no = getattr(node, "lineno", 0)
    for ident in {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}:
        if var_from_input(ctx, line_no, ident, lookback):
            return True
    return False


def keyword_value(call: ast.Call, name: str) -> ast.AST | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def has_keyword(call: ast.Call, name: str) -> bool:
    return any(kw.arg == name for kw in call.keywords)


def constant_value(node: ast.AST | None) -> object:
    if isinstance(node, ast.Constant):
        return node.value
    return None


@dataclass(slots=True)
class RouteInfo:
    """A decorated request handler discovered in Python source."""

    func: ast.FunctionDef | ast.AsyncFunctionDef
    path: str
    methods: tuple[str, ...]
    decorator_source: str
    has_auth: bool
    lineno: int

    @property
    def body_source(self) -> str:
        return ""


_ROUTE_ATTRS = {"route", "get", "post", "put", "delete", "patch", "api_route", "options", "head", "websocket"}


def python_routes(ctx: FileContext) -> Iterator[RouteInfo]:
    """Yield every Flask / FastAPI / Django-style decorated handler in the file."""
    tree = ctx.tree
    if tree is None:
        return
    for func in iter_functions(tree):
        if not func.decorator_list:
            continue
        route_path = ""
        methods: list[str] = []
        is_route = False
        decorator_text_parts: list[str] = []
        for dec in func.decorator_list:
            decorator_text_parts.append(node_source(ctx, dec))
            call = dec if isinstance(dec, ast.Call) else None
            name = dotted_name(call.func if call else dec)
            attr = name.rsplit(".", 1)[-1] if name else ""
            if attr in _ROUTE_ATTRS and call is not None:
                is_route = True
                if attr in {"get", "post", "put", "delete", "patch", "options", "head"}:
                    methods.append(attr.upper())
                if call.args and is_constant_str(call.args[0]):
                    route_path = call.args[0].value  # type: ignore[union-attr]
                methods_kw = keyword_value(call, "methods")
                if isinstance(methods_kw, (ast.List, ast.Tuple)):
                    methods.extend(
                        str(e.value).upper() for e in methods_kw.elts if isinstance(e, ast.Constant)
                    )
        if not is_route:
            continue
        decorator_source = "\n".join(decorator_text_parts)
        signature = node_source(ctx, func).split("\n", 1)[0]
        args_source = " ".join(node_source(ctx, a) for a in func.args.defaults + func.args.kw_defaults if a)
        has_auth = bool(AUTH_DECORATOR.search(decorator_source + " " + args_source + " " + signature))
        yield RouteInfo(
            func=func,
            path=route_path,
            methods=tuple(methods or ("GET",)),
            decorator_source=decorator_source,
            has_auth=has_auth,
            lineno=func.lineno,
        )


def function_body_source(ctx: FileContext, func: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    end = getattr(func, "end_lineno", None) or func.lineno + 30
    return ctx.window(func.lineno, 0, max(0, end - func.lineno))


def function_at_line(ctx: FileContext, line_no: int) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    tree = ctx.tree
    if tree is None:
        return None
    best: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    for func in iter_functions(tree):
        end = getattr(func, "end_lineno", func.lineno)
        if func.lineno <= line_no <= end:
            if best is None or func.lineno > best.lineno:
                best = func
    return best


def handler_block(ctx: FileContext, line_no: int, fallback_lines: int = 30) -> str:
    """Source of the enclosing Python function, else ``fallback_lines`` of lookahead."""
    func = function_at_line(ctx, line_no) if ctx.ext == ".py" else None
    if func is not None:
        return function_body_source(ctx, func)
    return lookahead(ctx, line_no, fallback_lines)


def hit_from_node(ctx: FileContext, node: ast.AST, **kwargs: object) -> Hit:
    line_no = getattr(node, "lineno", 1)
    return Hit(line=line_no, snippet=ctx.line(line_no), column=getattr(node, "col_offset", 0) + 1, **kwargs)  # type: ignore[arg-type]


def make_hit(ctx: FileContext, line_no: int, **kwargs: object) -> Hit:
    return Hit(line=line_no, snippet=ctx.line(line_no), **kwargs)  # type: ignore[arg-type]


def route_path_matches(pattern: re.Pattern[str], route_line: str) -> bool:
    return bool(pattern.search(route_line))


# --------------------------------------------------------------------------- #
# Dependency version helpers
# --------------------------------------------------------------------------- #


def parse_version(text: str) -> tuple[int, ...]:
    """Loose version parser: ``1.2.3rc1`` -> ``(1, 2, 3)``; never raises."""
    parts: list[int] = []
    for chunk in re.split(r"[.\-+]", text.strip().lstrip("v=~^<>! ")):
        match = re.match(r"\d+", chunk)
        if not match:
            break
        parts.append(int(match.group(0)))
        if len(parts) >= 4:
            break
    return tuple(parts) or (0,)


def version_lt(left: str, right: str) -> bool:
    a, b = parse_version(left), parse_version(right)
    length = max(len(a), len(b))
    return a + (0,) * (length - len(a)) < b + (0,) * (length - len(b))


__all__ = [
    "AUTH_DECORATOR",
    "JS_AUTH_MIDDLEWARE",
    "PII_DATA",
    "PLACEHOLDER",
    "ROUTE_DECORATOR",
    "RouteInfo",
    "SECRET_KEY_NAMES",
    "SENSITIVE_DATA",
    "STRING_LITERAL",
    "arg_tainted",
    "call_name",
    "constant_value",
    "dotted_name",
    "extract_call_arg",
    "first_arg",
    "function_at_line",
    "function_body_source",
    "handler_block",
    "has_input",
    "has_keyword",
    "hit_from_node",
    "identifiers_in",
    "is_constant_str",
    "is_dynamic_string",
    "is_pure_literal",
    "iter_calls",
    "iter_functions",
    "keyword_value",
    "lookahead",
    "lookbehind",
    "looks_like_secret",
    "make_hit",
    "node_source",
    "node_tainted",
    "parse_version",
    "python_routes",
    "shannon_entropy",
    "strip_strings",
    "var_from_input",
    "version_lt",
]
