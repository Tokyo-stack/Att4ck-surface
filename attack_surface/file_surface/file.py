"""File surface: uploads, downloads / path traversal, open redirects and
backup files left in the tree (surfaces 10, 11, 12, 34).
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from attack_surface.analysis import (
    arg_tainted,
    extract_call_arg,
    handler_block,
    has_input,
    lookahead,
    lookbehind,
    make_hit,
)
from attack_surface.models import FileContext, Hit, Rule, Severity

WEB_EXTS = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".rb", ".go", ".java", ".kt", ".cs", ".scala")

# --------------------------------------------------------------------------- #
# 10. file-uploads
# --------------------------------------------------------------------------- #

_UPLOAD_SOURCE = re.compile(
    r"request\.files(?:\[|\.get\(|\.getlist\()|request\.FILES|req\.files?\b|\$_FILES\[|multer\s*\(|"
    r"upload\.(?:single|array|fields|any|none)\s*\(|MultipartFile\b|\bFormFile\(|c\.FormFile\(|r\.FormFile\(|"
    r"params\[:\w*(?:file|upload|attachment|image|avatar|photo)\w*\]|\bUploadFile\b|\bformidable\b|\bbusboy\b|"
    r"\.getlist\(\s*['\"]files?['\"]|move_uploaded_file\s*\(|request\.get_data\(\)|@RequestParam\([^)]*MultipartFile",
    re.I,
)
_UPLOAD_SINK = re.compile(
    r"\.save\s*\(|move_uploaded_file\s*\(|copyfileobj\s*\(|shutil\.(?:copy|move)|\bopen\s*\([^)]*['\"]w|writeFile(?:Sync)?\s*\(|"
    r"createWriteStream\s*\(|\.write\s*\(|transferTo\s*\(|os\.rename\s*\(|\.mv\s*\(|storage\.|\.pipe\s*\(|"
    r"put_object\s*\(|upload_fileobj\s*\(|upload_file\s*\(|\.upload\s*\(|Files\.(?:copy|write)|ioutil\.WriteFile|os\.Create\s*\(|"
    r"io\.Copy\s*\(|File\.(?:open|write|binwrite)|FileUtils|\.store(?:As)?\s*\(|Storage::put|diskStorage|dest\s*:|destination\s*:|fs\.rename",
    re.I,
)
_UPLOAD_GUARD = re.compile(
    r"secure_filename|allowed_file|ALLOWED_EXTENSIONS|allowed_extensions|allowed_types|ALLOWED_MIME|fileFilter|\bmimetype\b|"
    r"content_type|contentType|mime_type|splitext|\.endswith\(|\.suffix|extension\s+(?:in|not in)|\bmagic\b|imghdr|python-magic|"
    r"filetype|uuid|uuid4|secrets\.token|random|MAX_CONTENT_LENGTH|fileSize|limits\s*:|max_size|MAX_FILE_SIZE|basename\(|"
    r"sanitize|validate|Image\.open|\.verify\(\)|whitelist|allowlist|rename|hashlib|extname\(|path\.extname|\.originalname\s*\.\w+\(|"
    r"accept\s*:|acceptedFiles|isImage|is_image|clamav|clamd|virus|scan|filter_var|pathinfo|in_array\(\s*\$?\w*ext|check_ext|"
    r"validates?\s*:?\s*\w*(?:file|attachment|content_type)|content_type_allowlist|content_type_whitelist|\.attached\?",
    re.I,
)


def _upload(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    line = ctx.line(line_no)
    if re.search(r"^\s*(?:import|from|require|#|//)|typing|\.d\.ts", line):
        return None
    block = handler_block(ctx, line_no, 30)
    sink = _UPLOAD_SINK.search(block)
    if not sink and not re.search(r"multer\s*\(|upload\.(?:single|array|fields|any)|diskStorage|formidable|busboy", line, re.I):
        return None
    if re.search(r"multer\s*\(\s*\)", line):
        return make_hit(ctx, line_no, column=match.start() + 1, confidence=85,
                        description="multer() is configured without fileFilter or limits; any file type/size is accepted.")
    guard = _UPLOAD_GUARD.search(block) or _UPLOAD_GUARD.search(lookbehind(ctx, line_no, 15))
    if guard and re.search(r"secure_filename|allowed_file|fileFilter|allowed_extensions|ALLOWED_EXTENSIONS|content_type_allowlist|in_array", guard.group(0), re.I) and re.search(r"limits|MAX_CONTENT_LENGTH|fileSize|max_size|MAX_FILE_SIZE|\.size|content_length|getsize", block + lookbehind(ctx, line_no, 40), re.I):
        return None  # both name/type validation and size limits present
    return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by=guard.group(0) if guard else None,
                    skip_sanitizer_check=True, confidence=85 if not guard else 45,
                    description="Uploaded file is stored" + (f" via {sink.group(0).strip()}" if sink else "") + " without filename/type/size validation.")


# --------------------------------------------------------------------------- #
# 11. file-downloads
# --------------------------------------------------------------------------- #

_FILE_SINK = re.compile(
    r"\b(?P<fn>send_file|send_from_directory|FileResponse|StreamingResponse|open|os\.path\.join|Path|io\.open|codecs\.open|"
    r"fs\.readFile(?:Sync)?|fs\.createReadStream|fs\.readdir(?:Sync)?|fs\.stat(?:Sync)?|fs\.unlink(?:Sync)?|fs\.rm(?:Sync)?|fs\.access(?:Sync)?|res\.sendFile|res\.download|res\.attachment|"
    r"path\.join|path\.resolve|file_get_contents|readfile|fopen|file_put_contents|unlink|include|require(?:_once)?|include_once|"
    r"File\.read|File\.open|IO\.read|send_file|File\.join|Rails\.root\.join|"
    r"ioutil\.ReadFile|os\.ReadFile|os\.Open|os\.Remove|http\.ServeFile|filepath\.Join|"
    r"new\s+File|new\s+FileInputStream|Files\.readAllBytes|Paths\.get|Files\.newInputStream|Files\.delete|ResourceUtils\.getFile|"
    r"File\.ReadAllText|File\.ReadAllBytes|File\.OpenRead|Path\.Combine|PhysicalFile|new\s+FileStream)\s*\(",
    re.I,
)
_TRAVERSAL_GUARD = re.compile(
    r"secure_filename|safe_join|\bbasename\(|os\.path\.basename|path\.basename|File\.basename|filepath\.Base|Path\.GetFileName|"
    r"realpath|abspath|\.resolve\(\)|is_relative_to|startswith\(\s*(?:str\(|BASE|ROOT|UPLOAD|SAFE|ALLOWED|base|root|safe|allowed|self\.|os\.path)|"
    r"path\.normalize|filepath\.Clean|\.normalize\(\)|Path\.GetFullPath|\.\.\s*(?:in|not in)|contains\(\s*['\"]\.\.|indexOf\(\s*['\"]\.\.|"
    r"includes\(\s*['\"]\.\.|allowlist|whitelist|ALLOWED_FILES|re\.(?:match|fullmatch)\(|\bisalnum\(|\[a-zA-Z0-9|\[\\w|"
    r"root\s*:|sendFile\([^)]*\{\s*root|toRealPath|getCanonicalPath|startsWith\(|Rack::Utils\.clean_path_info|"
    r"ActiveStorage|Storage::|Flysystem|uuid|UUID|\bint\(|parseInt|get_object_or_404|\.get\(\s*pk|\.objects\.get|"
    r"validate_path|validatePath|safe_path|safePath|sanitize_path|sanitizePath|is_safe_path|isSafePath|pathlib.*relative_to",
    re.I,
)


def _download(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    line = ctx.line(line_no)
    if re.search(r"^\s*(?:import|from|require|#|//)|\.d\.ts|__file__|__dirname\s*[,)]|/dev/null", line):
        return None
    fn = match.group("fn")
    args = extract_call_arg(line, match.end() - 1)
    if not args.strip():
        return None
    if fn in {"open", "Path", "io.open", "codecs.open", "fopen"} and re.fullmatch(r"\s*(?:'[^']*'|\"[^\"]*\")\s*(?:,.*)?", args):
        return None
    if fn == "send_from_directory" and not re.search(r"\.\.|request|req\.", args):
        return None  # safe_join based
    if fn in {"include", "require", "require_once", "include_once"} and ctx.ext != ".php":
        return None
    if fn == "res.sendFile" and re.search(r"root\s*:", ctx.statement(line_no, 4)):
        return None
    direct = has_input(args)
    tainted = direct or arg_tainted(ctx, line_no, args, lookback=20)
    if not tainted:
        # Variables like `filename`/`path`/`file` parameters of a handler
        if not (re.search(r"\b(?:filename|file_name|fname|path|filepath|file_path|name|file|doc|document|attachment|template|page)\b", args) and re.search(r"def\s+\w+\s*\([^)]*\b(?:filename|file_name|fname|path|filepath|file_path|name|file|doc|document|attachment|template|page)\b|\(\s*(?:req|request)\b|params\[|<(?:path:|string:)?(?:filename|file_name|path|name|file)>|:\w*(?:file|path|name)\b", handler_block(ctx, line_no, 0) + lookbehind(ctx, line_no, 12), re.I)):
            return None
    block = lookbehind(ctx, line_no, 12) + "\n" + line + "\n" + lookahead(ctx, line_no, 4)
    guard = _TRAVERSAL_GUARD.search(block)
    if guard and re.search(r"secure_filename|safe_join|basename|Rack::Utils|clean_path_info|GetFileName|filepath\.Base|realpath.*startswith|is_relative_to|toRealPath|getCanonicalPath|resolve\(\)\.\w*\(?.*is_relative_to", block, re.I) and re.search(re.escape(guard.group(0)), line):
        return None  # the sanitizer is applied on the sink line itself
    return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by=guard.group(0) if guard else None,
                    skip_sanitizer_check=True, confidence=90 if direct and not guard else (75 if not guard else 40),
                    severity=Severity.HIGH if not guard else Severity.MEDIUM,
                    description=f"{fn}() receives a path influenced by request input; '../' sequences can escape the intended directory.")


# --------------------------------------------------------------------------- #
# 12. redirects
# --------------------------------------------------------------------------- #

_REDIRECT = re.compile(
    r"(?:\bredirect\s*\(\s*(?P<a>[^)]*)\)"
    r"|HttpResponseRedirect\s*\(\s*(?P<b>[^)]*)\)"
    r"|RedirectResponse\s*\(\s*(?:url\s*=\s*)?(?P<c>[^),]*)"
    r"|res\.redirect\s*\(\s*(?:\d{3}\s*,\s*)?(?P<d>[^)]*)\)"
    r"|(?:ctx|c)\.Redirect\s*\(\s*(?:\d{3}|http\.\w+)\s*,\s*(?P<e>[^)]*)\)"
    r"|http\.Redirect\s*\(\s*\w+\s*,\s*\w+\s*,\s*(?P<f>[^,]*),"
    r"|redirect_to\s*\(?\s*(?P<g>[^)\n]*)"
    r"|header\s*\(\s*['\"]Location:\s*['\"]?\s*\.\s*(?P<h>[^)]*)\)"
    r"|(?:window\.)?location(?:\.href|\.assign\(|\.replace\()?\s*=?\s*\(?\s*(?P<i>[^;)]*)"
    r"|sendRedirect\s*\(\s*(?P<j>[^)]*)\)"
    r"|Redirect\s*\(\s*(?P<k>[^)]*)\)"
    r"|response\.headers\[['\"]Location['\"]\]\s*=\s*(?P<l>.*)$"
    r"|\bLocation\b['\"]?\s*[:,]\s*(?P<m>[^,}\n]*))",
    re.I,
)
_REDIRECT_INPUT = re.compile(
    r"request\.(?:args|form|values|GET|POST|params|referrer|referer|json|query_params|headers)|req\.(?:query|body|params|headers|get\()|"
    r"\$_(?:GET|POST|REQUEST|SERVER)|params\[|params\.fetch|\bnext_?url\b|\bnext\b|\breturn_?to\b|\breturn_?url\b|\bredirect_?(?:url|uri|to)\b|"
    r"\btarget\b|\bcontinue\b|\bback_?url\b|\bgoto\b|\bcallback_?url\b|\bdest(?:ination)?\b|\breferer\b|\breferrer\b|\bret\b|"
    r"searchParams\.get|location\.search|URLSearchParams|getParameter\(|c\.Query\(|r\.URL\.Query|r\.FormValue|\burl\b|\blink\b|\bhref\b|\bfrom\b",
    re.I,
)
_REDIRECT_GUARD = re.compile(
    r"url_has_allowed_host_and_scheme|is_safe_url|url_for\(|reverse\(|ALLOWED_REDIRECT|ALLOWED_HOSTS|allowed_hosts|"
    r"\.netloc\b|urlparse\(|urlsplit\(|new\s+URL\(|startswith\(\s*['\"]/(?!/)|startsWith\(\s*['\"]/(?!/)|safe_redirect|validate_redirect|"
    r"allowlist|whitelist|is_local_url|IsLocalUrl|LocalRedirect|url_is_safe|safe_url|relative|\bsanitize|"
    r"\.host\s*(?:==|!=|in)|hostname\s*(?:==|!=|in)|\bin\s+ALLOWED|redirect_back|only_path|fallback_location|"
    r"allow_other_host\s*:\s*false|\bmatch\(\s*/\^\\\/|re\.(?:match|fullmatch)\(",
    re.I,
)


def _redirect(rule: Rule, ctx: FileContext, match: re.Match[str], line_no: int) -> Hit | None:
    line = ctx.line(line_no)
    if re.search(r"^\s*(?:import|from|require|#|//|\*)|test_|spec\.|describe\(|\.d\.ts|permanent_redirect_|redirect_stdout|redirect_stderr|=\s*redirect\b\s*$", line, re.I):
        return None
    arg = next((g for g in match.groups() if g), "") or ""
    arg = arg.strip()
    if not arg:
        return None
    if re.fullmatch(r"(?:'[^']*'|\"[^\"]*\"|`[^`$]*`)\s*(?:,.*)?", arg):
        return None
    if re.search(r"url_for\(|reverse\(|reverse_lazy\(|route\(|path_for\(|\.url\b|_path\b|_url\(|to_route|url\.route|:back\b", arg) and not _REDIRECT_INPUT.search(arg):
        return None
    if re.search(r"^\s*(?:window\.)?location\b", line) and not re.search(r"=\s*(?!=)", line):
        return None  # reading location, not assigning
    if "location" in match.group(0).lower() and re.search(r"location\.(?:href|search|hash|pathname|origin)\s*(?:===?|!==?|\.|\)|,|;|$)", line) and not re.search(r"location\.\w+\s*=\s*(?!=)", line):
        return None
    direct = bool(_REDIRECT_INPUT.search(arg))
    tainted = direct or arg_tainted(ctx, line_no, arg, lookback=20)
    if not tainted:
        return None
    block = lookbehind(ctx, line_no, 15) + "\n" + line + "\n" + lookahead(ctx, line_no, 3)
    guard = _REDIRECT_GUARD.search(block)
    if guard and re.search(r"url_has_allowed_host_and_scheme|is_safe_url|safe_redirect|validate_redirect|is_local_url|IsLocalUrl|LocalRedirect|url_is_safe|redirect_back|only_path|allow_other_host", guard.group(0), re.I):
        return None
    return make_hit(ctx, line_no, column=match.start() + 1, mitigated_by=guard.group(0) if guard else None,
                    skip_sanitizer_check=True, confidence=88 if direct and not guard else (70 if not guard else 40))


# --------------------------------------------------------------------------- #
# 34. backups
# --------------------------------------------------------------------------- #

_BACKUP_NAME = re.compile(
    r"(?:\.(?:bak|backup|bkp|bck|old|orig|original|prev|previous|save|sav|swp|swo|swn|tmp|temp|copy|dist\.old|rej|"
    r"log\.\d+|\d{8}|\d{4}-\d{2}-\d{2})$|~$|^#.*#$|^\.#|\bcore\.\d+$|\.pyc\.bak$|-backup\b|_backup\b|\.bak\.|"
    r"(?:^|[._-])(?:backup|bkup|dump|snapshot|export)[^/]*\.(?:sql|sql\.gz|sql\.zip|sql\.bz2|dump|tar|tar\.gz|tgz|zip|7z|rar|db|sqlite3?|json|csv|xml)$|"
    r"\.(?:sql\.gz|sql\.zip|sql\.bz2|dump|sqlite3?|db)$|\.env\.(?:bak|backup|old|orig|save|copy|prev)$|"
    r"^Thumbs\.db$|^\.DS_Store$|^desktop\.ini$)",
    re.I,
)


def _backup_file(rule: Rule, ctx: FileContext) -> Iterator[Hit]:
    name = ctx.name
    rel = ctx.rel_path.lower()
    if re.search(r"(?:^|/)(?:migrations?|fixtures?|seeds?|schema|test_?data|testdata|__snapshots__|docs?|examples?)/", rel) and re.search(r"\.(?:sql|json|csv|xml|db|sqlite3?)$", name, re.I) and not re.search(r"backup|dump|bkup|\.bak", name, re.I):
        return
    if not _BACKUP_NAME.search(name):
        return
    lower = name.lower()
    if re.search(r"\.env\.(?:bak|backup|old|orig|save|copy|prev)$", lower) or re.search(r"(?:config|settings|secret|credential|passw|\.pem|\.key|id_rsa)", lower):
        severity, confidence, desc = Severity.HIGH, 90, "Backup copy of a configuration/secret file is committed and may contain credentials."
    elif re.search(r"\.(?:sql|sql\.gz|sql\.zip|sql\.bz2|dump|db|sqlite3?)$|dump|snapshot", lower):
        severity, confidence, desc = Severity.MEDIUM, 85, "Database dump/backup file is committed and may contain production data."
    elif lower in {"thumbs.db", ".ds_store", "desktop.ini"}:
        severity, confidence, desc = Severity.INFO, 95, "Operating-system metadata file committed to the repository."
    else:
        severity, confidence, desc = Severity.LOW, 85, "Editor/backup artifact committed; may leak previous versions of code or secrets."
    yield Hit(line=1, snippet=name, severity=severity, confidence=confidence, description=desc, skip_sanitizer_check=True)


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

RULES: tuple[Rule, ...] = (
    # ---- 10. file-uploads ------------------------------------------------- #
    Rule(
        id="UP-001",
        surface="file-uploads",
        name="File upload stored without filename/type/size validation",
        description="Uploaded content is persisted without sanitising the name, restricting extensions/MIME types or limiting size.",
        severity=Severity.HIGH,
        cwe="CWE-434",
        confidence=85,
        extensions=WEB_EXTS,
        keywords=("files", "file", "upload", "multer", "multipart", "formfile", "formidable", "busboy"),
        patterns=(_UPLOAD_SOURCE,),
        negatives=(r"^\s*(?:import|from|require|#|//)",),
        checker=_upload,
        recommendation="Generate server-side filenames, allow-list extensions and MIME types (verify magic bytes), cap size and store outside the web root.",
        remediation="name = f'{uuid4()}{ext}' where ext in ALLOWED_EXTENSIONS; file.save(os.path.join(UPLOAD_DIR, name)); set MAX_CONTENT_LENGTH.",
    ),
    Rule(
        id="UP-002",
        surface="file-uploads",
        name="Upload directory served from web root or executable",
        description="Uploads are written into a publicly served/executable location (static, public, www) enabling web-shell upload.",
        severity=Severity.HIGH,
        cwe="CWE-434",
        confidence=75,
        extensions=WEB_EXTS + (".conf", ".htaccess", ".yaml", ".yml", ".json"),
        keywords=("upload", "static", "public", "www", "htdocs", "dest", "destination", "php_flag", "engine"),
        patterns=(
            r"(?:UPLOAD_(?:FOLDER|DIR|PATH|ROOT)|upload_(?:folder|dir|path|root)|uploadDir|uploadPath|dest|destination)\s*[:=]\s*['\"](?:\.?/)?(?:static|public|www|htdocs|wwwroot|assets|dist|html)(?:/[^'\"]*)?['\"]",
            r"multer\s*\(\s*\{\s*dest\s*:\s*['\"](?:\.?/)?(?:public|static|www|htdocs)",
            r"php_flag\s+engine\s+on|AddHandler\s+\w*php|SetHandler\s+application/x-httpd-php",
            r"upload_max_filesize\s*=\s*\d{3,}M|post_max_size\s*=\s*\d{3,}M",
        ),
        negatives=(r"\.htaccess.*engine\s+off|php_flag\s+engine\s+off|Options\s+-ExecCGI"),
        use_surface_indicators=False,
        recommendation="Store uploads outside the document root (or in object storage) and serve them through a controlled handler with Content-Disposition.",
        remediation="UPLOAD_FOLDER = '/var/app/uploads' (not under static/); disable script execution in any upload directory.",
    ),
    # ---- 11. file-downloads ----------------------------------------------- #
    Rule(
        id="DL-001",
        surface="file-downloads",
        name="Path traversal in file access",
        description="A filesystem API receives a path built from request data without canonicalisation or containment checks.",
        severity=Severity.HIGH,
        cwe="CWE-22",
        confidence=85,
        extensions=WEB_EXTS,
        keywords=("send_file", "send_from_directory", "fileresponse", "streamingresponse", "open(", "path.join", "path(", "readfile", "createreadstream", "sendfile", "download", "attachment", "file_get_contents", "fopen", "include", "require", "file.read", "file.open", "io.read", "servefile", "filepath.join", "new file", "fileinputstream", "readallbytes", "paths.get", "readalltext", "path.combine", "physicalfile", "filestream", "unlink", "readdir", "os.open", "os.remove", "files.delete", "file_put_contents", "rails.root"),
        patterns=(_FILE_SINK,),
        negatives=(r"^\s*(?:import|from|require|#|//|\*)", r"__file__|__dirname\s*[,)]|os\.path\.dirname\(\s*__file__", r"\.d\.ts"),
        checker=_download,
        recommendation="Resolve the final path and verify it stays inside the intended base directory; prefer id-based lookups over raw filenames.",
        remediation="base = Path(UPLOAD_DIR).resolve(); target = (base / name).resolve(); if not target.is_relative_to(base): abort(400)",
    ),
    Rule(
        id="DL-002",
        surface="file-downloads",
        name="Directory listing / arbitrary file serving enabled",
        description="Static file serving is configured to expose whole directories or sensitive files.",
        severity=Severity.MEDIUM,
        cwe="CWE-548",
        confidence=85,
        extensions=WEB_EXTS + (".conf", ".htaccess", ".yaml", ".yml", ".json", ".xml"),
        keywords=("autoindex", "indexes", "directory", "static", "dotfiles", "serveindex", "serve-index", "listing", "directorybrowsing", "showdir"),
        patterns=(
            r"autoindex\s+on",
            r"Options\s+[^#\n]*\+?Indexes",
            r"serveIndex\s*\(|serve-index",
            r"dotfiles\s*:\s*['\"]allow['\"]",
            r"express\.static\s*\(\s*(?:['\"]\.?/?['\"]|__dirname\s*\)|process\.cwd\(\)\s*\))",
            r"static_folder\s*=\s*['\"](?:\.|/|\.\./)['\"]",
            r"StaticFiles\s*\(\s*directory\s*=\s*['\"](?:\.|/|\.\./)['\"]",
            r"http\.FileServer\s*\(\s*http\.Dir\s*\(\s*['\"](?:\.|/|\.\./)['\"]",
            r"<directoryBrowse\s+enabled\s*=\s*['\"]true['\"]",
            r"directory_listing\s*[:=]\s*(?:true|True)|show_dir(?:ectory)?_listing\s*[:=]\s*(?:true|True)|listing\s*:\s*true",
            r"SimpleHTTPRequestHandler|http\.server\b.*--directory\s+/",
        ),
        negatives=(r"autoindex\s+off|-Indexes"),
        use_surface_indicators=False,
        recommendation="Disable directory listings and serve only a dedicated static directory.",
        remediation="autoindex off; Options -Indexes; express.static(path.join(__dirname, 'public'), { dotfiles: 'deny' })",
    ),
    # ---- 12. redirects ---------------------------------------------------- #
    Rule(
        id="RED-001",
        surface="redirects",
        name="Open redirect from request-controlled URL",
        description="The redirect target is taken from user input without validating the host or restricting to relative paths.",
        severity=Severity.MEDIUM,
        cwe="CWE-601",
        confidence=85,
        extensions=WEB_EXTS + (".html", ".ejs", ".hbs", ".vue", ".svelte", ".jsx", ".tsx"),
        keywords=("redirect", "location", "sendredirect"),
        patterns=(_REDIRECT,),
        checker=_redirect,
        recommendation="Allow only relative paths or an allow-list of hosts; use url_has_allowed_host_and_scheme / is_safe_url helpers.",
        remediation="if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.host}): next_url = '/'",
    ),
    Rule(
        id="RED-002",
        surface="redirects",
        name="Redirect allow-list disabled or wildcarded",
        description="Redirect validation is turned off or accepts any host.",
        severity=Severity.MEDIUM,
        cwe="CWE-601",
        confidence=90,
        extensions=WEB_EXTS + (".json", ".yaml", ".yml", ".toml"),
        keywords=("redirect", "allow_other_host", "allowed_hosts", "safe_redirect"),
        patterns=(
            r"allow_other_host\s*:\s*true",
            r"(?:ALLOWED_REDIRECT_HOSTS|allowed_redirect_hosts|REDIRECT_ALLOWED_HOSTS|allowedRedirectHosts)\s*[:=]\s*\[?\s*['\"]\*['\"]",
            r"(?:validate_redirect|safe_redirect|check_redirect|SAFE_REDIRECT)\w*\s*[:=]\s*(?:False|false)",
            r"LOGIN_REDIRECT_URL\s*=\s*request\.",
            r"raise_on_open_redirect\s*=\s*False|allow_open_redirect\s*[:=]\s*(?:True|true)",
        ),
        use_surface_indicators=False,
        recommendation="Keep redirect validation enabled and enumerate allowed hosts explicitly.",
        remediation="redirect_to params[:next], allow_other_host: false",
    ),
    # ---- 34. backups ------------------------------------------------------ #
    Rule(
        id="BAK-001",
        surface="backups",
        name="Backup / temporary / dump file committed to the code tree",
        description="Editor backups, database dumps and OS metadata files leak previous code versions, data or secrets.",
        severity=Severity.LOW,
        cwe="CWE-530",
        confidence=85,
        path_only=True,
        filename_patterns=(_BACKUP_NAME,),
        file_checker=_backup_file,
        recommendation="Delete the file, add the pattern to .gitignore and purge it from history if it contained data.",
        remediation="git rm --cached <file>; echo '*.bak' >> .gitignore; consider git filter-repo for sensitive dumps.",
    ),
    Rule(
        id="BAK-002",
        surface="backups",
        name="Backup written inside the application/web directory",
        description="Code creates backup or dump files next to the application sources where they can be served or committed.",
        severity=Severity.MEDIUM,
        cwe="CWE-530",
        confidence=75,
        extensions=WEB_EXTS + (".sh", ".bash", ".ps1", ".yaml", ".yml", ".dockerfile"),
        keywords=("backup", "dump", ".bak", "mysqldump", "pg_dump", "mongodump", "tar ", "zip"),
        patterns=(
            r"(?:mysqldump|pg_dump|pg_dumpall|mongodump|sqlite3\s+\S+\s+\.dump|redis-cli\s+--rdb)\b[^\n|>]*(?:>\s*|--out[= ]|-o\s+|--file[= ]|-f\s+)?(?:\.?/?(?:public|static|www|htdocs|wwwroot|app|src|backups?|dumps?)/|[\w./-]*\.(?:sql|dump|bak)\b)",
            r"(?:shutil\.copy\w*|copyfile|os\.rename|shutil\.move|fs\.copyFile(?:Sync)?|fs\.rename(?:Sync)?|copy\s*\(|cp\s+-r?\s)\s*\(?[^)\n]*['\"][^'\"\n]*\.(?:bak|backup|old|orig|dump)['\"]",
            r"['\"][^'\"\n]*(?:public|static|www|htdocs|wwwroot)/[^'\"\n]*(?:backup|dump|\.bak|\.sql|\.zip|\.tar)[^'\"\n]*['\"]",
            r"(?:BACKUP_(?:DIR|PATH|FOLDER)|backup_(?:dir|path|folder)|backupDir|backupPath)\s*[:=]\s*['\"](?:\.?/)?(?:public|static|www|htdocs|wwwroot|app|src|\.)(?:/[^'\"]*)?['\"]",
            r"(?:tar\s+-?c\w*|zip\s+-r)\s+[^\n|]*(?:public|static|www|htdocs)/[^\n|]*(?:backup|\.tar|\.zip)",
        ),
        negatives=(r"^\s*(?:import|from|require|#|//)", r"/tmp/|/var/backups|s3://|gs://|az://|\$\{|\{\{"),
        use_surface_indicators=False,
        recommendation="Write backups to a location outside the web root/source tree (object storage or a dedicated volume) with restricted permissions.",
        remediation="pg_dump ... > /var/backups/app/$(date +%F).sql && chmod 600; upload to S3 with server-side encryption.",
    ),
)
