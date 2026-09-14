"""Input surface: dynamic code execution, reflected search parameters, ID
parameters mapped to SQL, GraphQL query construction, SQL injection and
insecure library methods (surfaces 4, 5, 6, 8, 24, 40).
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from attack_surface.analysis import (
    arg_tainted,
    call_name,
    constant_value,
    extract_call_arg,
    first_arg,
    handler_block,
    has_input,
    has_keyword,
    hit_from_node,
    is_constant_str,
    is_dynamic_string,
    iter_calls,
    keyword_value,
    make_hit,
    node_source,
    node_tainted,
)
from attack_surface.models import FileContext, Hit, Rule, Severity

CODE_EXTS = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".rb", ".java", ".go", ".cs", ".kt", ".scala")
WEB_EXTS = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".rb", ".java", ".go", ".kt", ".html", ".ejs", ".hbs", ".pug", ".twig", ".erb", ".jinja", ".jinja2", ".j2", ".vue", ".svelte")
DB_EXTS = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".rb", ".java", ".go", ".cs", ".kt", ".scala", ".sql")

# --------------------------------------------------------------------------- #
# 4. user-inputs
# --------------------------------------------------------------------------- #

_EXEC_SINKS = {"eval", "exec", "os.system", "os.popen", "subprocess.call", "subprocess.run", "subprocess.Popen",
               "subprocess.check_output", "subprocess.check_call", "subprocess.getoutput", "subprocess.getstatusoutput",
               "commands.getoutput", "os.execl", "os.execv", "os.execve", "os.execvp", "os.spawnl", "os.spawnv",
               "pty.spawn", "compile", "__import__", "importlib.import_module"}
_SHELL_FUNCS = {"subprocess.call", "subprocess.run", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call"}


def _user_inputs_python(rule: Rule, ctx: FileContext) -> Iterator[Hit]:
    tree = ctx.tree
    if tree is None:
        return
    for call in iter_calls(tree):
        name = call_name(call)
        if name not in _EXEC_SINKS:
            continue
        if not call.args:
            continue
        target = call.args[0]
        if name in _SHELL_FUNCS:
            shell = constant_value(keyword_value(call, "shell"))
            if shell is not True:
                # list-based argv without a shell is not an injection sink
                if not (isinstance(target, (ast.JoinedStr, ast.BinOp)) or is_dynamic_string(target) and isinstance(target, ast.Call)):
                    continue
                if isinstance(target, ast.List):
                    continue
            if is_constant_str(target) or isinstance(target, ast.List) and all(isinstance(e, ast.Constant) for e in target.elts):
                continue
        elif name in {"subprocess.getoutput", "subprocess.getstatusoutput", "os.system", "os.popen", "commands.getoutput"} or name in {"eval", "exec", "compile", "__import__", "importlib.import_module"}:
            if is_constant_str(target):
                continue
        else:
            if is_constant_str(target):
                continue
        tainted = node_tainted(ctx, call)
        if name in {"__import__", "importlib.import_module", "compile"} and not tainted:
            continue
        source = node_source(ctx, call)
        if re.search(r"shlex\.quote|shlex\.split|escapeshell", source):
            yield hit_from_node(ctx, call, confidence=40, mitigated_by="shlex.quote", skip_sanitizer_check=True)
            continue
        confidence = 95 if tainted else (70 if name in {"eval", "exec"} else 60)
        severity = Severity.CRITICAL if tainted else Severity.HIGH
        yield hit_from_node(ctx, call, confidence=confidence, severity=severity,
                            description=f"{name}() executes a dynamically built value" + (" derived from user input." if tainted else "."))


def _js_exec(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    line = ctx.line(line_no)
    args = extract_call_arg(line, match.end() - 1)
    arg = first_arg(args)
    if not arg or re.fullmatch(r"""(?:"[^"]*"|'[^']*'|`[^`$]*`)""", arg):
        return None
    tainted = arg_tainted(ctx, line_no, args)
    return make_hit(ctx, line_no, column=match.start() + 1, confidence=95 if tainted else 65,
                    severity=Severity.CRITICAL if tainted else Severity.HIGH)


# --------------------------------------------------------------------------- #
# 5. search-parameters
# --------------------------------------------------------------------------- #

_SEARCH_PARAM = re.compile(
    r"(?:request\.(?:args|GET|query_params|values|form|POST)(?:\.get\(\s*|\[\s*)['\"](?P<p1>q|query|search|s|term|keyword|keywords|filter|name|text|title|message|msg|comment|input|callback|redirect|username|user|lang|page|sort|order|category)['\"]"
    r"|req\.(?:query|params|body)\.(?P<p2>q|query|search|s|term|keyword|keywords|filter|name|text|title|message|msg|comment|input|callback|username|user|lang|page|sort|order|category)\b"
    r"|\$_(?:GET|POST|REQUEST)\[\s*['\"](?P<p3>q|query|search|s|term|keyword|keywords|filter|name|text|title|message|msg|comment|input|callback|username|user|lang|page|sort|order|category)['\"]"
    r"|params\[:(?P<p4>q|query|search|term|keyword|name|text|title|message|comment)\]"
    r"|searchParams\.get\(\s*['\"](?P<p5>q|query|search|s|term|keyword|name|text|title|message|comment|input|callback|user|lang|page|sort|order|category)['\"]"
    r"|(?:new\s+)?URLSearchParams\(\s*(?:window\.|document\.)?location\.search\s*\)"
    r"|c\.(?:Query|DefaultQuery|PostForm)\(\s*['\"](?P<p6>q|query|search|term|keyword|name|text|title|message|comment)['\"]"
    r"|r\.URL\.Query\(\)\.Get\(\s*['\"](?P<p7>q|query|search|term|keyword|name|text|title|message|comment)['\"]"
    r"|getParameter\(\s*['\"](?P<p8>q|query|search|term|keyword|name|text|title|message|comment)['\"])",
    re.I,
)

_XSS_SINK = re.compile(
    r"render_template_string\(|Markup\(|mark_safe\(|\|\s*safe\b|HttpResponse\(\s*(?:f['\"]|['\"].*(?:%|\+)|\w+\s*\))|"
    r"Response\(\s*f['\"]|return\s+f['\"][^'\"]*<|return\s+['\"][^'\"]*<[^'\"]*['\"]\s*(?:\+|%|\.format)|"
    r"make_response\(\s*f['\"]|\.innerHTML\s*=|outerHTML\s*=|document\.write(?:ln)?\(|insertAdjacentHTML\(|"
    r"res\.send\(\s*(?:`[^`]*\$\{|['\"][^'\"]*<[^'\"]*['\"]\s*\+|\w)|res\.write\(|res\.end\(\s*(?:`|['\"].*\+)|\.html\(\s*[^)'\"]|"
    r"\becho\b|\bprint\s+\$|\bprint\(|<%=|<%-|\{\{\{|\{\{\s*!|\{!|dangerouslySetInnerHTML|v-html|\[innerHTML\]|"
    r"c\.String\(|fmt\.Fprintf\(\s*w|w\.Write\(\[\]byte\(|io\.WriteString\(\s*w|out\.print(?:ln)?\(|getWriter\(\)\.(?:print|write)|"
    r"response\.getWriter|@Html\.Raw|Response\.Write|html\.raw|raw\(|\.html_safe|render\s+(?:inline|html):|"
    r"return\s+(?:f['\"]|['\"][^'\"]*['\"]\s*(?:\+|%|\.format))|render_to_string\(|template_string|string\.Template\(",
    re.I,
)

_XSS_SAFE = re.compile(
    r"html\.escape|markupsafe\.escape|\bescape\(|\bbleach\b|DOMPurify|sanitize|htmlspecialchars|htmlentities|"
    r"textContent|innerText|createTextNode|encodeURIComponent|render_template\((?!_string)|jsonify\(|JSON\.stringify|"
    r"json\.dumps|application/json|strip_tags|\bxss\(|\bescapeHtml\b|\bhe\.encode|template\.HTMLEscapeString|"
    r"html\.EscapeString|ERB::Util|\bh\(|StringEscapeUtils|Encode\.forHtml|HtmlEncode|\bcgi\.escape|\bquote\(|"
    r"setContent\(|\.text\(|res\.json\(|c\.JSON\(|return\s+jsonify|\bint\(|parseInt|Number\(",
    re.I,
)


def _search_param(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    block = handler_block(ctx, line_no, 20)
    if ctx.ext in {".html", ".ejs", ".hbs", ".pug", ".twig", ".erb", ".jinja", ".jinja2", ".j2", ".vue", ".svelte"}:
        block = ctx.window(line_no, 2, 12)
    sink = _XSS_SINK.search(block)
    if not sink:
        return None
    safe = _XSS_SAFE.search(block)
    param = next((g for g in match.groups() if g), "search")
    return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by=safe.group(0) if safe else None,
                    skip_sanitizer_check=True, confidence=85 if not safe else 40,
                    description=f"Parameter '{param}' is read from the request and rendered via {sink.group(0).strip()}.")


# --------------------------------------------------------------------------- #
# 6. id-parameters
# --------------------------------------------------------------------------- #

_ID_PARAM = re.compile(
    r"(?:request\.(?:args|GET|query_params|values|form|POST|json|data)(?:\.get\(\s*|\[\s*)['\"](?P<p1>\w*(?:id|Id|ID|uid|pk|key|num|no)\w*)['\"]"
    r"|req\.(?:query|params|body)\.(?P<p2>\w*(?:id|Id|ID|uid|pk|key)\w*)\b"
    r"|req\.(?:query|params|body)\[\s*['\"](?P<p3>\w*(?:id|Id|ID|uid|pk)\w*)['\"]"
    r"|\$_(?:GET|POST|REQUEST)\[\s*['\"](?P<p4>\w*(?:id|Id|ID|uid|pk)\w*)['\"]"
    r"|params\[:(?P<p5>\w*id\w*)\]"
    r"|c\.(?:Param|Query|DefaultQuery|PostForm)\(\s*['\"](?P<p6>\w*(?:id|Id|ID|uid)\w*)['\"]"
    r"|r\.URL\.Query\(\)\.Get\(\s*['\"](?P<p7>\w*(?:id|Id|ID|uid)\w*)['\"]"
    r"|mux\.Vars\(r\)\[\s*['\"](?P<p8>\w*(?:id|Id|ID|uid)\w*)['\"]"
    r"|getParameter\(\s*['\"](?P<p9>\w*(?:id|Id|ID|uid)\w*)['\"]"
    r"|@\s*[\w.]+\.(?:route|get|post|put|delete|patch)\s*\(\s*['\"][^'\"]*<(?P<p10>(?!int:|uuid:|float:)(?:string:|path:)?\w*(?:id|uid|pk)\w*)>"
    r"|def\s+\w+\s*\([^)]*\b(?P<p11>\w*(?:_id|Id|ID|uid|pk)\w*)\s*(?:[,)]|:\s*(?:str|Any))(?![^)]*int)"
    r"|\{\s*(?P<p12>\w*(?:id|Id|ID|uid|pk)\w*)\s*\}\s*=\s*req\.(?:params|query|body)"
    r"|(?:const|let|var)\s+(?P<p13>\w*(?:id|Id|ID|uid|pk)\w*)\s*=\s*req\.(?:params|query|body)\.\w+)",
    re.I,
)

_SQL_SINK = re.compile(
    r"(?:\.execute(?:many)?\(|\.executescript\(|\.raw\(|\.query\(|\.exec\(|\bquery\(|\btext\(|\.prepare\(|mysqli_query\(|mysql_query\(|pg_query\(|"
    r"\.select\(|\.where\(|\.filter\(|\bdb\.(?:Query|Exec|QueryRow|Raw|Where)\(|\bDB\.(?:Query|Exec|Raw|Where)\(|\.Where\(|\bsql\s*=|\bquery\s*=|\bstmt\s*=|"
    r"createStatement\(\)\.execute|createQuery\(|\.find_by_sql\(|\.execute_sql\(|\bknex\.raw\(|sequelize\.query\(|\.rawQuery\(|\bcursor\.|"
    r"session\.execute\(|connection\.execute\(|SELECT\s|UPDATE\s|DELETE\s|INSERT\s)",
    re.I,
)
_SQL_DYNAMIC = re.compile(
    r"f['\"][^'\"]*(?:SELECT|UPDATE|DELETE|INSERT|WHERE|FROM)[^'\"]*\{|"
    r"['\"][^'\"]*(?:SELECT|UPDATE|DELETE|INSERT|WHERE|FROM)[^'\"]*['\"]\s*(?:%\s*[\(\w]|\+|\.format\(|\|\||\.)|"
    r"`[^`]*(?:SELECT|UPDATE|DELETE|INSERT|WHERE|FROM)[^`]*\$\{|"
    r"\+\s*['\"][^'\"]*(?:WHERE|AND|OR|=)[^'\"]*['\"]|"
    r"(?:WHERE|AND|OR)\s+\w+\s*=\s*['\"]?\s*['\"]\s*\+|(?:WHERE|AND|OR)\s+\w+\s*=\s*\$\{|"
    r"(?:WHERE|AND|OR)\s+\w+\s*=\s*\{\w|(?:WHERE|AND|OR)\s+\w+\s*=\s*['\"]?\s*\.\s*\$|"
    r"(?:WHERE|AND|OR)\s+\w+\s*=\s*['\"]?\s*\"\s*\+|%s['\"]\s*%\s*\(?\s*\w|\.format\(|"
    r"sprintf\(|String\.format\(|fmt\.Sprintf\(|\"\s*\+\s*\w+\s*\+\s*\"|#\{|<<<|\$\w+\s*['\"]?\s*(?:;|$|\))",
    re.I,
)
_ID_VALIDATION = re.compile(
    r"\bint\(|parseInt\(|Number\(|\buuid\b|UUID\(|ObjectId\(|isdigit\(|isnumeric\(|is_numeric\(|intval\(|\(int\)|"
    r"strconv\.Atoi|strconv\.Parse|Integer\.parseInt|Long\.parseLong|to_i\b|\bvalidate|pydantic|marshmallow|schema|"
    r"get_object_or_404|\.filter\(\s*\w+\s*=\s*|\.filter_by\(|\.get\(\s*\w+\s*=|find_by\(|findById\(|findByPk\(|findOne\(\s*\{|"
    r"where\s*\(\s*\{|\.where\(\s*['\"][^'\"]*\?|:\w+\s*[,)]|\$\d\b|%s|\?\s*[,)]|bind_param|bindValue|prepare\(|"
    r"<int:|<uuid:|:\s*int\b|\bint\s+\w*id|re\.(?:match|fullmatch)\(|isinstance\(|\.isInt|isUUID|Joi\.|z\.number|z\.string\(\)\.uuid|"
    r"param\(['\"][^'\"]+['\"]\)\.isInt|check\(['\"][^'\"]+['\"]\)\.isInt|express-validator|celebrate|Number\.isInteger|Number\.isSafeInteger",
    re.I,
)


def _id_param(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    param = next((g for g in match.groups() if g), "id")
    if re.search(r"width|height|valid|hidden|grid|video|guid|side|idle|provider|identifier|middle|sid[e]|consider|decide|inside|outside|slide|ideal", param, re.I) and not re.search(r"_id$|Id$|^id$|ID$", param):
        return None
    block = handler_block(ctx, line_no, 25)
    lines = block.split("\n")
    sink_line = next((ln for ln in lines if _SQL_SINK.search(ln) and _SQL_DYNAMIC.search(ln)), None)
    if sink_line is None:
        # Check statement continuation: query strings often span lines
        joined = " ".join(ln.strip() for ln in lines)
        if not (_SQL_SINK.search(joined) and _SQL_DYNAMIC.search(joined) and re.search(rf"\b{re.escape(param.split(':')[-1])}\b", joined)):
            return None
        sink_line = joined[:200]
    if not re.search(rf"\b{re.escape(param.split(':')[-1])}\b", sink_line) and not re.search(r"\bid\b|_id\b|\bpk\b", sink_line, re.I):
        return None
    validation = _ID_VALIDATION.search(block)
    return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by=validation.group(0) if validation else None,
                    skip_sanitizer_check=True, confidence=85 if not validation else 40,
                    description=f"Identifier '{param}' flows from the request into a dynamically built SQL statement.")


# --------------------------------------------------------------------------- #
# 8. graphql
# --------------------------------------------------------------------------- #


def _graphql_dynamic(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    block = ctx.window(line_no, 3, 12)
    if re.search(r"variables\s*[:=]|\$\w+\s*:\s*(?:String|ID|Int|Float|Boolean|\[)", block):
        # Interpolation + proper variables usually means only a fragment/operation name is templated.
        return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by="variables", skip_sanitizer_check=True, confidence=35)
    tainted = arg_tainted(ctx, line_no, block, lookback=20)
    return make_hit(ctx, line_no, column=match.start() + 1, confidence=90 if tainted else 70,
                    severity=Severity.HIGH if tainted else Severity.MEDIUM)


# --------------------------------------------------------------------------- #
# 24. database
# --------------------------------------------------------------------------- #

_SQL_METHODS = {"execute", "executemany", "executescript", "raw", "query", "exec", "text", "extra", "prepare",
                "execute_sql", "find_by_sql", "select", "run", "mogrify"}
_SQL_KEYWORDS = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|DROP|ALTER|CREATE|TRUNCATE|UNION|JOIN|INTO|VALUES|SET)\b", re.I)


def _sql_python(rule: Rule, ctx: FileContext) -> Iterator[Hit]:
    tree = ctx.tree
    if tree is None:
        return
    for call in iter_calls(tree):
        name = call_name(call)
        attr = name.rsplit(".", 1)[-1]
        if attr not in _SQL_METHODS or not call.args:
            continue
        target = call.args[0]
        if not is_dynamic_string(target):
            continue
        source = node_source(ctx, target)
        if isinstance(target, (ast.Name, ast.Attribute, ast.Subscript)):
            # Variable passed to execute(): flag only when it was built dynamically nearby.
            ident = source.split(".")[-1]
            window = ctx.window(call.lineno, 15, 0)
            assign = re.search(rf"\b{re.escape(ident)}\s*=\s*(.+)", window)
            if not assign:
                continue
            rhs = assign.group(1)
            if not (_SQL_KEYWORDS.search(rhs) and re.search(r"f['\"]|%\s*[\(\w]|\.format\(|\+\s*\w|\+\s*['\"]", rhs)):
                continue
            source = rhs
        elif not _SQL_KEYWORDS.search(source) and attr not in {"execute", "executemany", "raw"} or not _SQL_KEYWORDS.search(source):
            continue
        if isinstance(target, ast.BinOp) and isinstance(target.op, ast.Mod):
            # "... %s" % (a, b) is still injection (client-side formatting)
            pass
        if re.search(r"sql\.SQL\(|sql\.Identifier|sql\.Literal|quote_ident|quote_literal", source):
            yield hit_from_node(ctx, call, mitigated_by="psycopg2.sql composition", skip_sanitizer_check=True, confidence=30)
            continue
        params_present = len(call.args) > 1 or has_keyword(call, "params") or has_keyword(call, "parameters")
        tainted = node_tainted(ctx, call, lookback=25)
        confidence = 95 if tainted else (85 if not params_present else 70)
        yield hit_from_node(ctx, call, confidence=confidence,
                            severity=Severity.CRITICAL if tainted or not params_present else Severity.HIGH,
                            description="SQL statement is assembled with string formatting/concatenation"
                                        + (" from user-controlled input." if tainted else "."))


_SQL_CONCAT = re.compile(
    r"(?:\.(?:query|execute|exec|raw|prepare|all|get|run|each)|mysqli_query|mysql_query|pg_query|sqlsrv_query|oci_parse|\$wpdb->(?:query|get_results|get_var|get_row)|"
    r"\bdb\.(?:Query|Exec|QueryRow|Raw)|\bDB\.(?:Query|Exec|Raw)|createStatement\(\)\.(?:execute|executeQuery|executeUpdate)|"
    r"\bstmt\.(?:execute|executeQuery)|knex\.raw|sequelize\.query|\.rawQuery|find_by_sql|\.exec_query|\.execute_sql|ExecuteSqlRaw|FromSqlRaw|SqlCommand)\s*\(\s*"
    r"(?:`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^`]*\$\{"
    r"|['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^'\"]*['\"]\s*(?:\+|\.\s*\$|\|\||%|\.format|\.concat)"
    r"|\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^\"]*\$\w"
    r"|\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^\"]*\{\$"
    r"|['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^'\"]*#\{"
    r"|(?:String\.format|fmt\.Sprintf|sprintf|\$\.format)\s*\(\s*['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)"
    r"|\w+\s*\+\s*['\"][^'\"]*(?:WHERE|AND|OR|VALUES|SET|FROM)"
    r"|\w*(?:sql|query|stmt|statement)\w*\s*[,)])",
    re.I,
)

_SQL_ASSIGN = re.compile(
    r"(?:const|let|var|String|\$)?\s*\b\w*(?:sql|query|stmt|statement)\w*\s*(?:=|\+=|\.=)\s*"
    r"(?:['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^'\"]*['\"]\s*(?:\+|\.\s*\$|\|\||%|\.format|\.concat)"
    r"|`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^`]*\$\{"
    r"|\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^\"]*(?:\$\w|\{\$)"
    r"|['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^'\"]*#\{"
    r"|(?:String\.format|fmt\.Sprintf|sprintf)\s*\(\s*['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM))",
    re.I,
)
_SQL_PARAMETERIZED = re.compile(
    r"\?\s*[,)]|\?\s*['\"]|\$\d\b|:\w+\s*[,)\s]|@\w+\b|%s\s*['\"]\s*,|bind_param|bindValue|bindParam|prepare\(|setString\(|setInt\(|"
    r"\.bind\(|placeholders|parameterized|sql\.Named|sql\.Identifier|pg-format|mysql\.escape|\.escape\(|\bescapeId\(|"
    r"real_escape_string|quote\(|sanitize_sql|\bAND\s+\?|\bVALUES\s*\(\s*\?|prepared",
    re.I,
)


def _sql_regex(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    line = ctx.line(line_no)
    if re.search(r"^\s*(?:import|from|require|#|//|\*)", line):
        return None
    if re.search(r"\w*(?:sql|query|stmt|statement)\w*\s*[,)]", match.group(0), re.I) and not re.search(r"\+|\$\{|\.format|sprintf|%", match.group(0)):
        # Variable passed in: only flag if it was built dynamically above.
        ident = re.search(r"(\w*(?:sql|query|stmt|statement)\w*)\s*[,)]", match.group(0), re.I)
        window = ctx.window(line_no, 20, 0)
        if not ident or not re.search(rf"\b{re.escape(ident.group(1))}\b[^\n]*(?:=|\+=|\.=)", window):
            return None
        if not _SQL_ASSIGN.search(window) and not re.search(rf"{re.escape(ident.group(1))}\s*\+=", window):
            return None
    statement = ctx.statement(line_no, 6)
    if _SQL_PARAMETERIZED.search(statement) and not re.search(r"\+\s*\w|\$\{|\.format\(|%\s*\(|%\s*\w", statement):
        return None
    tainted = arg_tainted(ctx, line_no, statement, lookback=25)
    param = _SQL_PARAMETERIZED.search(statement)
    return make_hit(ctx, line_no, column=match.start() + 1, confidence=95 if tainted else 80,
                    severity=Severity.CRITICAL if tainted else Severity.HIGH,
                    mitigated_by=param.group(0) if param else None, skip_sanitizer_check=True)


# --------------------------------------------------------------------------- #
# 40. miscellaneous
# --------------------------------------------------------------------------- #


def _yaml_load(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    statement = ctx.statement(line_no, 3)
    if re.search(r"Loader\s*=\s*(?:yaml\.)?(?:C?SafeLoader|BaseLoader|CBaseLoader)", statement):
        return None
    if re.search(r"Loader\s*=\s*(?:yaml\.)?(?:C?FullLoader)", statement):
        return make_hit(ctx, line_no, column=match.start() + 1, severity=Severity.MEDIUM, confidence=70,
                        description="yaml.load with FullLoader can still instantiate arbitrary Python objects in older PyYAML.")
    return make_hit(ctx, line_no, column=match.start() + 1)


def _random_for_secret(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    window = ctx.window(line_no, 2, 1)
    if not re.search(r"token|secret|password|passwd|otp|session|nonce|salt|\bkey\b|csrf|reset|verification|api_key|\bpin\b|code\b", window, re.I):
        return None
    if re.search(r"random\.SystemRandom|secrets\.|os\.urandom|crypto\.randomBytes|crypto\.getRandomValues|randomUUID|SecureRandom", window):
        return None
    return make_hit(ctx, line_no, column=match.start() + 1)


def _misc_python(rule: Rule, ctx: FileContext) -> Iterator[Hit]:
    tree = ctx.tree
    if tree is None:
        return
    for call in iter_calls(tree):
        name = call_name(call)
        match name:
            case "torch.load":
                weights_only = constant_value(keyword_value(call, "weights_only"))
                if weights_only is not True:
                    yield hit_from_node(ctx, call, name="torch.load without weights_only=True", cwe="CWE-502",
                                        severity=Severity.HIGH, confidence=80,
                                        description="torch.load unpickles arbitrary objects unless weights_only=True.")
            case "tempfile.mktemp":
                yield hit_from_node(ctx, call, name="Insecure temporary file creation (mktemp)", cwe="CWE-377",
                                    severity=Severity.MEDIUM, confidence=90,
                                    description="tempfile.mktemp is racy; use mkstemp/NamedTemporaryFile.")
            case "os.chmod" | "chmod":
                if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant) and call.args[1].value in (0o777, 0o666, 511, 438):
                    yield hit_from_node(ctx, call, name="World-writable permissions", cwe="CWE-732",
                                        severity=Severity.MEDIUM, confidence=90,
                                        description="chmod 0o777/0o666 grants write access to every local user.")
            case "xml.etree.ElementTree.parse" | "xml.etree.ElementTree.fromstring" | "ET.parse" | "ET.fromstring" | "etree.parse" | "etree.fromstring" | "xml.dom.minidom.parse" | "xml.dom.minidom.parseString" | "minidom.parse" | "minidom.parseString" | "xml.sax.parse" | "sax.parse" | "xml.sax.parseString" | "lxml.etree.parse" | "lxml.etree.fromstring" | "xmltodict.parse":
                if "defusedxml" in ctx.text:
                    continue
                source = node_source(ctx, call)
                if name.startswith(("lxml", "etree")) and re.search(r"resolve_entities\s*=\s*False", ctx.window(call.lineno, 8, 2)):
                    continue
                yield hit_from_node(ctx, call, name="XML parsed without XXE protection", cwe="CWE-611",
                                    severity=Severity.MEDIUM, confidence=60 if not has_input(source) else 80,
                                    description="Standard XML parsers can be abused for entity expansion / XXE; use defusedxml.")
            case "ssl._create_unverified_context" | "ssl._create_default_https_context":
                yield hit_from_node(ctx, call, name="TLS certificate verification disabled", cwe="CWE-295",
                                    severity=Severity.HIGH, confidence=95)
            case "hashlib.new":
                if call.args and constant_value(call.args[0]) in ("md4", "md2", "ripemd160", "sha", "sha0"):
                    yield hit_from_node(ctx, call, name="Obsolete hash algorithm", cwe="CWE-328", severity=Severity.MEDIUM, confidence=85)
            case "AES.new" | "Cipher.AES.new" | "DES.new" | "DES3.new" | "ARC4.new" | "Blowfish.new" | "RC4.new":
                mode_src = node_source(ctx, call)
                if name.startswith(("DES", "ARC4", "RC4", "Blowfish")):
                    yield hit_from_node(ctx, call, name="Weak symmetric cipher", cwe="CWE-327", severity=Severity.HIGH, confidence=90,
                                        description=f"{name} is cryptographically weak; use AES-GCM or ChaCha20-Poly1305.")
                elif "MODE_ECB" in mode_src:
                    yield hit_from_node(ctx, call, name="AES in ECB mode", cwe="CWE-327", severity=Severity.HIGH, confidence=95,
                                        description="ECB leaks plaintext structure; use GCM or CBC with random IV + MAC.")
            case "assert":
                pass
    # verify=False on requests/httpx calls
    for call in iter_calls(tree):
        if constant_value(keyword_value(call, "verify")) is False and re.match(r"(?:requests|httpx|session|client|s|self\.session|http)\.", call_name(call) + "."):
            yield hit_from_node(ctx, call, name="TLS certificate verification disabled (verify=False)", cwe="CWE-295",
                                severity=Severity.HIGH, confidence=95,
                                description="Disabling certificate verification enables man-in-the-middle attacks.")


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

RULES: tuple[Rule, ...] = (
    # ---- 4. user-inputs --------------------------------------------------- #
    Rule(
        id="INP-001",
        surface="user-inputs",
        name="Dynamic code/command execution (Python)",
        description="eval/exec/os.system/subprocess(shell=True) invoked with a dynamically built argument.",
        severity=Severity.CRITICAL,
        cwe="CWE-94",
        confidence=85,
        extensions=(".py",),
        file_checker=_user_inputs_python,
        recommendation="Never evaluate user-controlled strings; use ast.literal_eval for data and argv lists without shell=True for commands.",
        remediation="subprocess.run([binary, arg1, arg2], shell=False) with validated arguments; replace eval() with explicit parsing.",
    ),
    Rule(
        id="INP-002",
        surface="user-inputs",
        name="Dynamic code/command execution",
        description="eval/new Function/shell exec called with a non-literal argument.",
        severity=Severity.CRITICAL,
        cwe="CWE-95",
        confidence=80,
        extensions=(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".rb", ".java", ".go", ".cs", ".kt", ".scala", ".pl"),
        keywords=("eval", "function", "exec", "system", "passthru", "shell_exec", "popen", "proc_open", "settimeout", "setinterval", "runtime", "spawn", "instance_eval", "class_eval", "send(", "constantize", "vm.", "%x"),
        patterns=(
            r"(?<![\w.])eval\s*\(",
            r"new\s+Function\s*\(",
            r"\bvm\.(?:runInNewContext|runInThisContext|runInContext|Script)\s*\(",
            r"child_process\.(?:exec|execSync)\s*\(|(?<![\w.])(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|['\"][^'\"]*['\"]\s*\+|\w)",
            r"\b(?:system|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(",
            r"\b(?:setTimeout|setInterval)\s*\(\s*(?:['\"`]|\w+\s*\+)",
            r"Runtime\.getRuntime\(\)\.exec\s*\(",
            r"new\s+ProcessBuilder\s*\(",
            r"\bexec\.Command\s*\(\s*['\"](?:sh|bash|/bin/sh|/bin/bash|cmd)['\"]",
            r"\b(?:instance_eval|class_eval|module_eval|instance_exec)\s*\(",
            r"\bKernel\.(?:system|exec|spawn)|(?<![\w.])(?:system|exec|spawn)\s*\(\s*(?:\"[^\"]*#\{|\w)",
            r"%x\{|`[^`]*#\{",
            r"\.constantize\b|\.send\(\s*params",
            r"Process\.Start\s*\(",
            r"ScriptEngine\w*\.eval\s*\(",
        ),
        negatives=(r"^\s*(?:import|from|require|\*|#|//)", r"\.d\.ts", r"json\.(?:parse|loads)", r"math\.eval", r"safe[_-]?eval", r"literal_eval"),
        checker=_js_exec,
        recommendation="Avoid eval/new Function/shell execution; use JSON.parse, execFile/spawn with argument arrays and strict validation.",
        remediation="child_process.execFile(binary, [args]) — never build a shell string from request data.",
    ),
    # ---- 5. search-parameters -------------------------------------------- #
    Rule(
        id="SRCH-001",
        surface="search-parameters",
        name="Search/query parameter reflected without encoding",
        description="A request parameter is read and rendered into HTML output without escaping (reflected XSS).",
        severity=Severity.HIGH,
        cwe="CWE-79",
        confidence=80,
        extensions=WEB_EXTS,
        keywords=("request.", "req.", "$_get", "$_post", "$_request", "params[", "searchparams", "location.search", "c.query", "r.url", "getparameter"),
        patterns=(_SEARCH_PARAM,),
        negatives=(r"^\s*(?:import|from|require|#|//)",),
        checker=_search_param,
        recommendation="Encode output contextually (HTML entity encoding) or render through an auto-escaping template engine.",
        remediation="Use render_template()/auto-escaping templates, markupsafe.escape() or textContent instead of innerHTML.",
    ),
    Rule(
        id="SRCH-002",
        surface="search-parameters",
        name="Template auto-escaping disabled",
        description="The template engine is configured to render untrusted values without escaping.",
        severity=Severity.HIGH,
        cwe="CWE-79",
        confidence=90,
        extensions=WEB_EXTS + (".json", ".yaml", ".yml"),
        keywords=("autoescape", "escape", "safe", "html_safe", "raw"),
        patterns=(
            r"autoescape\s*[=:]\s*(?:False|false|off|0)\b",
            r"\{%\s*autoescape\s+(?:off|false)\s*%\}",
            r"Environment\([^)]*autoescape\s*=\s*False",
            r"escapeHtml\s*:\s*false|escape\s*:\s*false|noEscape\s*:\s*true",
            r"\|\s*safe\s*\}\}\s*(?!.*\bstatic\b)",
            r"mark_safe\(\s*(?!['\"])\w",
            r"\.html_safe\b",
            r"\{\{\{\s*\w+(?:\.\w+)*\s*\}\}\}",
            r"<%-\s*(?!include)\w",
            r"\|\s*raw\b|\braw\(\s*\w",
            r"@Html\.Raw\(",
        ),
        negatives=(r"static|url_for|csrf|nonce|trans\b|_\(|translate|i18n|gettext|svg|icon|render_field|form\.|widget"),
        sanitizers=(r"\bescape\(", r"markupsafe", r"bleach", r"sanitize", r"DOMPurify", r"htmlspecialchars", r"strip_tags"),
        code_only=True,
        recommendation="Keep auto-escaping enabled and mark only sanitized fragments as safe.",
        remediation="Remove |safe / mark_safe on user-controlled values; sanitize rich text with bleach or DOMPurify before marking safe.",
    ),
    # ---- 6. id-parameters ------------------------------------------------- #
    Rule(
        id="ID-001",
        surface="id-parameters",
        name="Unvalidated ID parameter used in SQL",
        description="An identifier taken from the request reaches a dynamically built SQL query without type validation.",
        severity=Severity.CRITICAL,
        cwe="CWE-89",
        confidence=85,
        extensions=DB_EXTS,
        keywords=("id", "pk", "uid", "key"),
        patterns=(_ID_PARAM,),
        negatives=(r"^\s*(?:import|from|require|#|//)",),
        checker=_id_param,
        recommendation="Cast identifiers to int/UUID (or use route converters) and pass them as bound parameters.",
        remediation="user_id = int(request.args['id']); cursor.execute('SELECT ... WHERE id = %s', (user_id,))",
    ),
    Rule(
        id="ID-002",
        surface="id-parameters",
        name="Object reference taken directly from request (IDOR)",
        description="A record is fetched by an id supplied by the client without scoping it to the current user.",
        severity=Severity.HIGH,
        cwe="CWE-639",
        confidence=65,
        extensions=WEB_EXTS,
        keywords=("id", "pk"),
        patterns=(
            r"\.objects\.get\(\s*(?:pk|id)\s*=\s*(?:request\.(?:GET|POST|args|form|data|json)(?:\.get\()?\s*\[?\s*['\"](?:pk|id|user_id)['\"]|\w*_?id)\s*\)?\s*\)",
            r"(?:findById|findByPk|findOne|findUnique)\s*\(\s*(?:req\.(?:params|query|body)\.\w+|\{\s*(?:where\s*:\s*\{\s*)?id\s*:\s*req\.(?:params|query|body)\.\w+)",
            r"\.find\(\s*params\[:id\]\s*\)",
            r"\.query\.get(?:_or_404)?\(\s*(?:request\.(?:args|form|json)\.get\(\s*['\"](?:id|user_id)['\"]\)|\w*_?id)\s*\)",
            r"get_object_or_404\(\s*\w+\s*,\s*(?:pk|id)\s*=\s*(?:request\.(?:GET|POST)\[?\.?\w*\(?\s*['\"]\w*id['\"]|\w*_?id)\s*\)?\s*\)",
        ),
        negatives=(r"current_user|request\.user|req\.user|owner|user\s*=\s*request|filter\([^)]*user|self\.request\.user|session\[|\bauthorize\b|IsOwner|test_|spec\."),
        sanitizers=(r"current_user", r"request\.user", r"req\.user", r"g\.user", r"session\[", r"owner", r"user_id\s*=\s*", r"authorize", r"permission", r"abort\(\s*403", r"403", r"Forbidden", r"IsOwner", r"can\(", r"policy"),
        context_before=8,
        context_after=12,
        recommendation="Scope lookups to the authenticated user (filter by owner) or enforce object-level permission checks.",
        remediation="Order.objects.get(pk=order_id, owner=request.user) instead of Order.objects.get(pk=order_id).",
    ),
    # ---- 8. graphql ------------------------------------------------------- #
    Rule(
        id="GQL-001",
        surface="graphql",
        name="GraphQL query built by string interpolation",
        description="A GraphQL document is constructed dynamically instead of using typed variables, enabling query injection.",
        severity=Severity.HIGH,
        cwe="CWE-943",
        confidence=80,
        extensions=CODE_EXTS + (".graphql", ".gql", ".vue", ".svelte"),
        keywords=("gql", "graphql", "query", "mutation"),
        patterns=(
            r"\bgql\s*`[^`]*\$\{",
            r"\bgraphql\s*`[^`]*\$\{",
            r"(?:query|mutation|document|gqlQuery|graphqlQuery)\s*[:=]\s*`\s*(?:query|mutation|subscription|\{)[^`]*\$\{",
            r"(?:query|mutation)\s*[:=]\s*f['\"]\s*(?:query|mutation|subscription|\{)[^'\"]*\{",
            r"(?:query|mutation)\s*[:=]\s*['\"]\s*(?:query|mutation|subscription|\{)[^'\"]*['\"]\s*(?:\+|%|\.format\(|\.replace\()",
            r"['\"]\s*(?:query|mutation)\s*\{[^'\"]*['\"]\s*\+\s*\w",
            r"(?:graphql_sync|graphql|execute|schema\.execute|client\.execute)\s*\(\s*(?:schema\s*,\s*)?f['\"]",
            r"(?:schema\.execute|client\.execute|graphql)\s*\(\s*(?:schema\s*,\s*)?['\"][^'\"]*['\"]\s*(?:%|\+|\.format)",
            r"\bgql\s*\(\s*f['\"]",
            r"\bgql\s*\(\s*['\"][^'\"]*['\"]\s*(?:%|\+|\.format)",
            r"query\s*\{[^}]*\$\{[^}]*\}[^}]*\}",
        ),
        negatives=(r"^\s*(?:import|from|require|#|//)", r"__typename", r"fragment\s+\w+\s+on"),
        checker=_graphql_dynamic,
        recommendation="Send user data through GraphQL variables ($id: ID!) and keep documents static.",
        remediation="client.query({ query: gql`query($id: ID!) { user(id: $id) { name } }`, variables: { id } })",
    ),
    Rule(
        id="GQL-002",
        surface="graphql",
        name="GraphQL introspection / playground enabled",
        description="Schema introspection or an interactive IDE is exposed, leaking the full API surface in production.",
        severity=Severity.MEDIUM,
        cwe="CWE-200",
        confidence=80,
        extensions=CODE_EXTS + (".json", ".yaml", ".yml", ".toml"),
        keywords=("introspection", "graphiql", "playground", "graphql"),
        patterns=(
            r"introspection\s*[:=]\s*(?:true|True)\b",
            r"graphiql\s*[:=]\s*(?:true|True)\b",
            r"playground\s*[:=]\s*(?:true|True)\b",
            r"GraphQLView\.as_view\([^)]*graphiql\s*=\s*True",
            r"GraphQLApp\([^)]*graphiql\s*=\s*True",
            r"ApolloServer\(\s*\{[^}]*introspection\s*:\s*true",
        ),
        sanitizers=(r"NODE_ENV\s*!==?\s*['\"]production", r"process\.env", r"os\.environ", r"settings\.DEBUG", r"if\s+DEBUG", r"getenv", r"isDev", r"development"),
        recommendation="Disable introspection and GraphiQL/Playground in production or restrict them to authenticated staff.",
        remediation="introspection: process.env.NODE_ENV !== 'production'; add depth/complexity limits and persisted queries.",
    ),
    Rule(
        id="GQL-003",
        surface="graphql",
        name="GraphQL resolver without depth/complexity limits",
        description="An ApolloServer/graphql-http server is created without validation rules limiting query depth or cost.",
        severity=Severity.LOW,
        cwe="CWE-400",
        confidence=55,
        extensions=(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
        keywords=("apolloserver", "graphqlhttp", "createyoga", "createhandler", "mercurius"),
        patterns=(r"new\s+ApolloServer\s*\(", r"graphqlHTTP\s*\(\s*\{", r"createYoga\s*\(", r"createHandler\s*\(\s*\{\s*schema"),
        sanitizers=(r"depthLimit", r"depth_limit", r"createComplexityLimitRule", r"costAnalysis", r"validationRules", r"maxDepth", r"queryComplexity", r"complexity", r"armor", r"persistedQueries", r"rateLimit"),
        context_before=15,
        context_after=25,
        use_surface_indicators=False,
        recommendation="Add graphql-depth-limit / cost analysis validation rules and rate limiting.",
        remediation="new ApolloServer({ schema, validationRules: [depthLimit(8), createComplexityLimitRule(1000)] })",
    ),
    # ---- 24. database ----------------------------------------------------- #
    Rule(
        id="DB-001",
        surface="database",
        name="SQL injection via string formatting (Python)",
        description="A SQL statement passed to execute()/raw()/text() is built with f-strings, % formatting, .format() or concatenation.",
        severity=Severity.CRITICAL,
        cwe="CWE-89",
        confidence=90,
        extensions=(".py",),
        file_checker=_sql_python,
        recommendation="Use parameterised queries (placeholders + parameter tuple) or the ORM query builder.",
        remediation="cursor.execute('SELECT * FROM users WHERE email = %s', (email,)) — never interpolate values into the SQL text.",
    ),
    Rule(
        id="DB-002",
        surface="database",
        name="SQL injection via string concatenation",
        description="A SQL statement is assembled through concatenation/interpolation before being executed.",
        severity=Severity.CRITICAL,
        cwe="CWE-89",
        confidence=85,
        extensions=(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".rb", ".java", ".go", ".cs", ".kt", ".scala"),
        keywords=("select", "insert", "update", "delete", "where", "from", "query", "sql", "exec"),
        patterns=(_SQL_CONCAT, _SQL_ASSIGN),
        negatives=(r"^\s*(?:import|from|require|#|//|\*)", r"console\.log|logger\.|log\.", r"\.d\.ts"),
        checker=_sql_regex,
        recommendation="Use prepared statements / parameter binding for every value that comes from outside the code.",
        remediation="db.query('SELECT * FROM users WHERE id = $1', [id]) / $stmt = $pdo->prepare('... WHERE id = :id')",
    ),
    Rule(
        id="DB-003",
        surface="database",
        name="ORM raw query with interpolated values",
        description="ORM escape hatches (raw/extra/whereRaw/find_by_sql) receive interpolated strings, bypassing parameterisation.",
        severity=Severity.HIGH,
        cwe="CWE-89",
        confidence=80,
        extensions=DB_EXTS,
        keywords=("raw", "extra", "where", "order", "find_by_sql", "literal", "knex", "sequelize"),
        patterns=(
            r"\.(?:extra|raw|whereRaw|orderByRaw|havingRaw|joinRaw|selectRaw|fromRaw|groupByRaw|find_by_sql|where|order|pluck|group|select|having|joins)\s*\(\s*(?:f['\"]|`[^`]*\$\{|['\"][^'\"]*['\"]\s*(?:\+|%|\.format\(|#\{|\.\s*\$))",
            r"sequelize\.literal\s*\(\s*(?:`[^`]*\$\{|['\"][^'\"]*['\"]\s*\+)",
            r"Sequelize\.literal\s*\(\s*(?:`[^`]*\$\{|['\"][^'\"]*['\"]\s*\+)",
            r"\.where\(\s*\"[^\"]*#\{",
            r"\.where\(\s*\"[^\"]*\"\s*\+\s*\w",
            r"RawSQL\(\s*(?:f['\"]|['\"][^'\"]*['\"]\s*(?:%|\+|\.format))",
            r"\.execute\(\s*text\(\s*f['\"]",
            r"text\(\s*f['\"][^'\"]*\{",
            r"\$wpdb->prepare\(\s*\"[^\"]*(?:\$\w|\{\$)",
            r"\.exec\(\s*['\"][^'\"]*['\"]\s*\+",
        ),
        negatives=(r"^\s*(?:import|from|require|#|//|\*)", r"\?\s*,|:\w+\s*\)|%s\s*['\"]\s*,|bindparams|\.params\(", r"\.where\(\s*\w+\s*:\s*|\.where\(\s*\{|\.where\(\s*['\"]\w+\s*=\s*\?"),
        recommendation="Pass values as bind parameters even when using raw ORM escape hatches.",
        remediation="Model.objects.raw('SELECT ... WHERE id = %s', [id]) / knex.raw('... = ?', [id]) / Model.where('name = ?', name)",
    ),
    Rule(
        id="DB-004",
        surface="database",
        name="Database connection with credentials in URL",
        description="A connection string embeds a username and password directly in source or config.",
        severity=Severity.HIGH,
        cwe="CWE-798",
        confidence=85,
        extensions=DB_EXTS + (".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".xml", ".env", ".txt", ".md", ".sh"),
        keywords=("://",),
        patterns=(
            r"\b(?:postgres(?:ql)?|mysql|mysql2|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver|oracle|clickhouse|cockroachdb|jdbc:\w+|cassandra|neo4j|bolt|couchdb|memcached|ftp|sftp|ssh|ldaps?)://(?P<user>[^:/\s'\"@]+):(?P<pass>[^@/\s'\"]{3,})@",
        ),
        negatives=(
            r"(?i)://(?:user|username|USER|USERNAME|\w*user\w*|admin|root|postgres|guest|\$\{?\w+\}?|\{\{|<\w+>|\w*_user|me|foo|bar|test|example|dbuser|db_user|myuser|someuser|name):(?:pass|password|PASS|PASSWORD|\w*pass\w*|secret|\$\{?\w+\}?|\{\{|<\w+>|%s|\{\w*\}|foo|bar|123|test|example|xxx+|\*+|changeme|\.\.\.)@|"
            r"localhost|127\.0\.0\.1|example\.com|@db:|@database:|@postgres:|@mysql:|@mongo:|@redis:|@rabbitmq:|@host|@server|@hostname|:\{\{|:\$"
        ),
        scan_comments=True,
        sanitizer_scope="line",
        use_surface_indicators=False,
        recommendation="Inject the database URL from the environment or a secrets manager; rotate the exposed credential.",
        remediation="DATABASE_URL = os.environ['DATABASE_URL'] and keep the real value out of version control.",
    ),
    # ---- 40. miscellaneous ------------------------------------------------ #
    Rule(
        id="MISC-001",
        surface="miscellaneous",
        name="yaml.load without SafeLoader",
        description="yaml.load with the default/Full/Unsafe loader can instantiate arbitrary Python objects from untrusted YAML.",
        severity=Severity.HIGH,
        cwe="CWE-502",
        confidence=90,
        extensions=(".py",),
        keywords=("yaml.load", "yaml.load_all", "yaml.unsafe_load", "unsafeloader"),
        patterns=(r"\byaml\.(?:load|load_all)\s*\(", r"\byaml\.unsafe_load(?:_all)?\s*\(", r"UnsafeLoader"),
        negatives=(r"safe_load", r"SafeLoader|BaseLoader"),
        checker=_yaml_load,
        use_surface_indicators=False,
        recommendation="Use yaml.safe_load() or pass Loader=yaml.SafeLoader.",
        remediation="data = yaml.safe_load(stream)",
    ),
    Rule(
        id="MISC-002",
        surface="miscellaneous",
        name="Insecure standard-library usage",
        description="A library call with insecure defaults or known-dangerous semantics was found (torch.load, mktemp, XML parsers, unverified TLS, weak ciphers).",
        severity=Severity.MEDIUM,
        cwe="CWE-20",
        confidence=80,
        extensions=(".py",),
        file_checker=_misc_python,
        recommendation="Prefer secure alternatives: defusedxml, tempfile.mkstemp, weights_only=True, verify=True, AES-GCM.",
        remediation="Replace the flagged call with the secure equivalent named in the finding description.",
    ),
    Rule(
        id="MISC-003",
        surface="miscellaneous",
        name="Insecure random used for security value",
        description="A non-cryptographic PRNG generates a token, password, OTP or session identifier.",
        severity=Severity.HIGH,
        cwe="CWE-338",
        confidence=85,
        extensions=CODE_EXTS,
        keywords=("random", "rand("),
        patterns=(
            r"\brandom\.(?:random|randint|choice|choices|randrange|sample|getrandbits|uniform|shuffle)\s*\(",
            r"\bMath\.random\s*\(",
            r"\b(?:rand|mt_rand|uniqid|lcg_value|array_rand|str_shuffle)\s*\(",
            r"\bnew\s+Random\s*\(|\bjava\.util\.Random\b",
            r"\bmath/rand\b|\brand\.(?:Int|Intn|Int63|Read|Float64)\s*\(",
            r"\bRandom\.new\b|\brand\(",
        ),
        negatives=(r"^\s*(?:import|from|require|#|//)", r"SystemRandom|secrets\.|urandom|randomBytes|getRandomValues|SecureRandom|crypto/rand|randomUUID", r"test|seed|shuffle|sample_size|jitter|backoff|delay|sleep|color|position|animation|fake|mock"),
        checker=_random_for_secret,
        use_surface_indicators=False,
        recommendation="Use a CSPRNG: secrets.token_urlsafe(), crypto.randomBytes(), random_bytes(), SecureRandom, crypto/rand.",
        remediation="token = secrets.token_urlsafe(32)",
    ),
    Rule(
        id="MISC-004",
        surface="miscellaneous",
        name="Insecure library method",
        description="Well-known dangerous API usage in non-Python code (unverified TLS, deprecated ciphers, unsafe deserialisers, unsafe buffer functions).",
        severity=Severity.HIGH,
        cwe="CWE-676",
        confidence=85,
        extensions=(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".rb", ".java", ".go", ".cs", ".kt", ".scala", ".c", ".cpp", ".cc", ".h", ".hpp", ".m", ".swift"),
        keywords=("rejectunauthorized", "node_tls_reject", "createcipher", "insecureskipverify", "curlopt_ssl_verify", "verify_peer", "verify_none", "allowallhostname", "trustall", "gets(", "strcpy", "strcat", "sprintf", "unserialize", "yaml.load", "marshal.load", "objectinputstream", "readobject", "xmldecoder", "des", "rc4", "ecb", "md5", "extract("),
        patterns=(
            r"rejectUnauthorized\s*:\s*false",
            r"NODE_TLS_REJECT_UNAUTHORIZED\s*[\]=:'\"]+\s*['\"]?0",
            r"crypto\.createCipher\s*\(|crypto\.createDecipher\s*\(",
            r"InsecureSkipVerify\s*:\s*true",
            r"CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0|FALSE)",
            r"verify_peer['\"]?\s*(?:=>|=|:)\s*false|VERIFY_NONE|verify_mode\s*=\s*OpenSSL::SSL::VERIFY_NONE",
            r"ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier|TrustAllCerts|TrustAllX509|NoopHostnameVerifier|ServerCertificateValidationCallback\s*[+=]\s*.*true",
            r"\bgets\s*\(|\bstrcpy\s*\(|\bstrcat\s*\(|\bsprintf\s*\(|\bvsprintf\s*\(|\bscanf\s*\(\s*\"%s",
            r"\bunserialize\s*\(\s*\$",
            r"\bYAML\.load\s*\(|\bPsych\.load\s*\(|Marshal\.load\s*\(",
            r"new\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)|new\s+XMLDecoder\s*\(|XStream\(\)|enableDefaultTyping\(",
            r"Cipher\.getInstance\s*\(\s*\"(?:DES|DESede|RC4|RC2|Blowfish|AES/ECB|AES\"|DES/)",
            r"\bDESCryptoServiceProvider\b|\bRC2CryptoServiceProvider\b|CipherMode\.ECB",
            r"MessageDigest\.getInstance\s*\(\s*\"MD[245]\"",
            r"\bextract\s*\(\s*\$_(?:GET|POST|REQUEST)",
            r"\bmd5\s*\(\s*\$\w*(?:pass|pwd)",
            r"BinaryFormatter\(\)|\.Deserialize\s*\(",
            r"node-serialize|serialize\.unserialize\s*\(",
        ),
        negatives=(r"^\s*(?:import|from|require|#|//|\*)", r"strncpy|strlcpy|snprintf|strncat|fgets", r"YAML\.safe_load|Psych\.safe_load", r"\.d\.ts"),
        use_surface_indicators=False,
        recommendation="Replace with the secure API (verified TLS, AEAD ciphers, JSON, bounded string functions).",
        remediation="Enable certificate verification, switch to AES-GCM, use snprintf/strlcpy and JSON-based serialisation.",
    ),
)
