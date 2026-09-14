# ATT4ck Surface

**Attack Surface Mapping & Security Review Framework**

```text
 █████╗ ████████╗████████╗██╗  ██╗ ██████╗██╗  ██╗     ███████╗██╗   ██╗██████╗ ███████╗ █████╗  ██████╗███████╗
██╔══██╗╚══██╔══╝╚══██╔══╝██║  ██║██╔════╝██║ ██╔╝     ██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝
███████║   ██║      ██║   ███████║██║     █████╔╝      ███████╗██║   ██║██████╔╝█████╗  ███████║██║     █████╗
██╔══██║   ██║      ██║   ╚════██║██║     ██╔═██╗      ╚════██║██║   ██║██╔══██╗██╔══╝  ██╔══██║██║     ██╔══╝
██║  ██║   ██║      ██║        ██║╚██████╗██║  ██╗     ███████║╚██████╔╝██║  ██║██║     ██║  ██║╚██████╗███████╗
╚═╝  ╚═╝   ╚═╝      ╚═╝        ╚═╝ ╚═════╝╚═╝  ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚══════╝
```

[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Surfaces](https://img.shields.io/badge/attack%20surfaces-40-red)](#3-list-of-attack-surfaces)

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [List of Attack Surfaces](#3-list-of-attack-surfaces)
4. [Installation and Environment Setup](#4-installation-and-environment-setup)
5. [Usage](#5-usage)
6. [Detection Engine & Sanitization Awareness](#6-detection-engine--sanitization-awareness)
7. [Risk Engine](#7-risk-engine)
8. [Output Formats](#8-output-formats)
9. [Extending the Scanner](#9-extending-the-scanner)
10. [Testing](#10-testing)
11. [Performance](#11-performance)

---

## 1. Overview

**ATT4ck Surface** is a high-performance, modular command-line **Static Analysis
Security Testing (SAST)** tool. It inspects a codebase across **exactly 40
distinct attack surfaces**, flags vulnerabilities, and — crucially — is
**sanitization-aware**: when a mitigation (parameterised query, output encoding,
HMAC verification, Subresource Integrity attribute, secure cookie flag, …) is
present near a risky pattern, the finding is downgraded and marked
*potentially mitigated* rather than reported as a raw vulnerability.

It combines three analysis techniques for speed and accuracy:

* **Compiled regular expressions** — a fast first pass with keyword pre-filters.
* **Python AST analysis** (`ast`) — precise, syntax-aware detection for Python
  (routes, SQL sinks, dangerous calls, taint-style input tracking).
* **Structured parsers** — JSON/YAML/manifest-aware checkers for dependencies,
  cloud IaC, Dockerfiles, CI pipelines and environment files.

Everything runs in pure Python with a tiny dependency footprint and scales to
large repositories (10k+ files) through concurrent scanning.

**Key features**

| | | |
|---|---|---|
| Endpoint Discovery | Secret Detection | File Upload Analysis |
| API Enumeration | Security Misconfiguration | Parameter Mapping |
| Source Code Review | Risk Classification | Attack Surface Coverage |

* **Developer:** Tokyo
* **Repository:** `github.com/Tokyo-stack/Att4ck-surface`

---

## 2. Architecture

The project is split into a clean, modular structure. Every attack surface lives
in a focused module; `rules.py` is the single source of truth binding the 40
surfaces to their detectors.

```text
Att4ck-surface/
│
├── attack_surface/                     # Core package
│   ├── __init__.py                     # Public API (scan_path, SurfaceScanner, ...)
│   ├── __main__.py                     # python -m attack_surface
│   ├── version.py                      # Single source of the version
│   ├── banner.py                       # ASCII logo, info box, environment banner
│   ├── models.py                       # Dataclasses/enums: Rule, Finding, Severity, FileContext
│   ├── analysis.py                     # Shared helpers: AST utils, taint/entropy heuristics
│   ├── rules.py                        # SINGLE SOURCE OF TRUTH for the 40 surfaces + registry
│   ├── risk_engine.py                  # Scoring, classification, prioritisation, summaries
│   ├── scanner.py                      # File walker + concurrent analysis dispatcher
│   ├── exporter.py                     # JSON / CSV / SQLite / self-contained HTML report
│   ├── cli.py                          # Click CLI: scan / surfaces / rules / crawl / version
│   ├── web_crawler.py                  # Optional live-target crawler (crawl command)
│   ├── xss_scanner.py                  # Optional reflected-XSS prober (crawl --xss)
│   │
│   ├── iam_surface/iam.py              # 1,2,3,13,14,16  auth / authz / session / admin / users / oauth
│   ├── input_surface/input.py         # 4,5,6,8,24,40   exec / XSS / IDs / GraphQL / SQLi / unsafe libs
│   ├── api_surface/api.py             # 7,9,28,29,30,31 API auth / webhooks / metrics / debug / docs / SSRF
│   ├── file_surface/file.py           # 10,11,12,34     uploads / traversal / redirects / backups
│   ├── frontend_surface/frontend.py   # 19,20           SRI / DOM XSS / CSP / storage
│   ├── secret_surface/secret.py       # 15,21,22,33,39  cards / secrets / env / CI tokens / VCS creds
│   ├── infrastructure_surface/…       # 23,25,26,27,32,35,36,37,38  cloud/cache/MQ/logging/deps/…
│   └── communication_surface/…        # 17,18           email header injection / notification leaks
│
├── tests/                              # Unit + integration tests
│   ├── test_rules.py                   # 40-surface contract, rule hygiene
│   ├── test_scanner.py                 # engine: discovery, binary handling, robustness
│   └── test_integration.py            # scans the sandbox; asserts detection + sanitization
│
├── test_sandbox/                       # Vulnerable + sanitized samples for all 40 surfaces
│   ├── vulnerable/<surface>/…
│   └── sanitized/<surface>/…
│
├── output/                             # Generated reports (findings.json/.csv/.db, report.html)
├── main.py                             # Thin CLI entry point (python main.py ...)
├── pyproject.toml                      # Packaging + entry points (att4ck / att4ck-surface)
├── requirements.txt
├── .gitignore
└── README.md
```

### Data flow

```
 discover files  ─►  RuleIndex (per-extension)  ─►  analyze_file (regex + AST + checkers)
       │                                                        │
       ▼                                                        ▼
  FileWalker (prune noise)                          Hit ─► risk_engine ─► Finding
                                                                 │
                                     prioritize / dedupe / threshold filter
                                                                 ▼
                                    ScanResult ─► exporter (JSON / CSV / SQLite / HTML)
```

---

## 3. List of Attack Surfaces

The scanner monitors the following **40 categories**:

1. **authentication**: Weak hashing (MD5/SHA1), hardcoded credentials.
2. **authorization**: Exposed endpoints lacking decorators.
3. **session-management**: Insecure cookie flags or unverified JWTs.
4. **user-inputs**: Dangerous dynamic exec inputs (`eval`, `exec`).
5. **search-parameters**: Insecure search parameters (reflected XSS).
6. **id-parameters**: Unvalidated ID variables mapped to SQL.
7. **api-endpoints**: Unauthenticated API paths.
8. **graphql**: Dynamic GraphQL query constructs.
9. **webhooks**: Webhooks receiving events without HMAC verification.
10. **file-uploads**: Arbitrary file uploads without name checks.
11. **file-downloads**: Path traversal vulnerability in serving files.
12. **redirects**: Open redirect endpoints.
13. **admin-portals**: Unsecured admin route definitions.
14. **user-management**: User password/profile adjustments missing ownership checks.
15. **payment-systems**: Custom credit card detail handling (non-PCI compliance).
16. **oauth-sso**: Missing state checks in OAuth callback hooks.
17. **email-flows**: SMTP connections vulnerable to header injection.
18. **notification-services**: Plaintext sensitive SMS or notifications.
19. **frontend-assets**: Missing Subresource Integrity (SRI) on CDNs.
20. **javascript-analysis**: Raw DOM writes (`innerHTML`, `document.write`).
21. **secrets-config**: Hardcoded keys in config files (`.json`, `.ini`).
22. **environment-files**: Actual secrets stored in env template files.
23. **cloud-storage**: Public read S3 configurations.
24. **database**: SQL injection patterns via string formatting.
25. **cache-services**: Redis/Memcached keys set without encryption or limits.
26. **message-queues**: Insecure deserialization formats (e.g. pickle payload parsing).
27. **logging**: Plaintext login logs or PII logged in file output.
28. **monitoring**: Exposed metrics endpoints without protection.
29. **debug-endpoints**: Active debug mode or debug console routes.
30. **documentation**: Swagger or Redoc files exposed without authorization.
31. **third-party-integrations**: Requests to outbound services missing timeouts (SSRF).
32. **dependencies**: Outdated or unpinned versions in package lists.
33. **ci-cd**: Hardcoded tokens in GitHub Actions YAML files.
34. **backups**: Storing temporary/backup files inside local code.
35. **subdomains**: Hardcoded staging/development server subdomains.
36. **dns**: Insecure DNS resolution implementations.
37. **server-config**: Wide CORS wildcards (`Access-Control-Allow-Origin: *`).
38. **containers**: Dockerfiles using latest tags or running as root.
39. **source-control**: Credentials exposed in VCS clones.
40. **miscellaneous**: Insecure library methods (like standard `yaml.load`).

Run `att4ck surfaces` for the live catalogue (rule counts, CWE, default severity).

---

## 4. Installation and Environment Setup

Requires **Python 3.11+**.

```bash
# Clone
git clone https://github.com/Tokyo-stack/Att4ck-surface.git
cd Att4ck-surface

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# Install (editable) with the console entry points
pip install -e .

# Optional extras
pip install -e ".[live]"           # crawl / XSS probing (requests, beautifulsoup4)
pip install -e ".[dev]"            # pytest, ruff, mypy
```

Or install only the runtime dependencies without packaging:

```bash
pip install -r requirements.txt
python main.py scan .
```

After install, three equivalent entry points are available:

```bash
att4ck --help
att4ck-surface --help
python -m attack_surface --help
```

---

## 5. Usage

`scan` is the default command, so a bare path just works.

```bash
# Scan the current directory (all 40 surfaces, all formats)
att4ck scan .
att4ck .                                  # same thing

# Scan a specific project, write reports to ./reports
att4ck scan /path/to/project -o reports

# Only certain surfaces (by key, number 1-40, or owning package)
att4ck scan . -s database -s authentication
att4ck scan . -s 24,1,7
att4ck scan . -s secret                   # every surface in the secret package

# Only report HIGH and above, and fail CI if anything CRITICAL is found
att4ck scan . -t HIGH --fail-on CRITICAL

# Exclude paths (glob), hide mitigated findings, pick formats
att4ck scan . -x 'vendor/*' -x '*.generated.js' --hide-mitigated -f json -f html

# Large repos: use a process pool and more workers
att4ck scan /huge/monorepo --processes -w 16

# Quiet one-liner (good for scripts) / JSON only
att4ck scan . -q --json
```

### Other commands

```bash
att4ck surfaces                 # list the 40 surfaces (add --json for machine output)
att4ck rules                    # list all detection rules
att4ck rules -s database        # rules for one surface
att4ck version                  # banner + environment + rule count

# Optional live target (needs the 'live' extra)
att4ck crawl https://example.com --max-pages 50 --xss -o reports
#   -> reports/crawl.json  : pages, endpoints, JS files, live + XSS findings
#   -> reports/findings.*  : live HTTP-posture findings (json/csv/db/html),
#                            classified through the same risk engine as static scans
#   Same-origin follows an apex -> www redirect automatically.

# Discovery + posture audit only (no XSS payloads); disable the audit with --no-audit
att4ck crawl https://example.com --no-audit          # discovery only
```

The live audit is **non-intrusive** (it only inspects what the crawler already
fetched) and maps HTTP-level issues onto the 40 surfaces:

| Check | Surface | Notes |
|-------|---------|-------|
| Missing HSTS / CSP / `X-Content-Type-Options` / `X-Frame-Options` / `Referrer-Policy` | server-config, frontend-assets | `frame-ancestors` in CSP satisfies clickjacking |
| Permissive CORS (`Access-Control-Allow-Origin: *`) | server-config | HIGH when paired with `Allow-Credentials: true` |
| Cookies missing `Secure` / `HttpOnly` / `SameSite` | session-management | severity raised for session/auth cookies |
| Third-party `<script>` without Subresource Integrity | frontend-assets | same-origin scripts are exempt |
| `Server` / `X-Powered-By` version disclosure | server-config | INFO; downgraded when no version is exposed |

A hardened response simply produces no finding for that control.

### Key `scan` options

| Option | Description |
|---|---|
| `-o, --output-dir` | Directory for generated reports (default `output`). |
| `-s, --surfaces` | Limit to surfaces (key / number / package). Repeatable or comma-separated. |
| `-x, --exclude` | Glob pattern to exclude. Repeatable. |
| `-f, --format` | `json`, `csv`, `sqlite`, `html` (repeatable; default all four). |
| `--json` / `--html` | Shortcuts for a single format. |
| `-t, --risk-threshold` | Minimum severity to report (`INFO`…`CRITICAL`). |
| `--fail-on` | Exit code `2` if a finding at/above this severity exists (CI gate). |
| `-w, --workers` | Worker count (`0` = auto). |
| `--processes` | Use a process pool instead of threads. |
| `--hide-mitigated` | Drop findings that appear mitigated. |
| `--respect-gitignore` | Also honour `.gitignore` patterns. |
| `--no-hidden` | Skip hidden files/directories. |
| `--max-file-size` | Skip files larger than N bytes (default 5 MiB). |
| `-q, --quiet` / `-v, --verbose` / `--debug` | Output verbosity. |
| `--no-banner` / `--no-export` | Suppress banner / skip writing reports. |

---

## 6. Detection Engine & Sanitization Awareness

Every rule declares the risky patterns **and** the indicators that mean the risk
is handled. During analysis the engine inspects a window around each hit (or the
enclosing statement/function for AST rules) for those mitigations:

| Surface | Mitigation the engine looks for |
|---|---|
| database / id-parameters | parameterised queries (`?`, `%s`, `:name`, `bind_param`) |
| search-parameters / DOM | `html.escape`, `DOMPurify`, `textContent`, template auto-escaping |
| webhooks | `hmac.compare_digest`, `construct_event`, signature headers |
| file-uploads / downloads | `secure_filename`, extension allow-lists, `is_relative_to`, `basename` |
| session-management | `Secure`, `HttpOnly`, `SameSite`, `jwt.verify` |
| frontend-assets | `integrity=` (SRI) + `crossorigin` |
| SSRF / DNS | host allow-lists, private-range checks, `timeout=` |
| secrets | env/`${VAR}`/vault references, low-entropy placeholders |

When a mitigation is found the finding's **status** becomes
`POTENTIALLY_MITIGATED`, its severity is downgraded one level and its confidence
reduced — so it still appears in reports (for review) but ranks below live
vulnerabilities. Use `--hide-mitigated` to drop them entirely.

The engine is robust by design: binary files are detected and skipped, encoding
errors never crash a scan, malformed source falls back from AST to regex, and
oversized files are streamed or skipped.

---

## 7. Risk Engine

Each finding is scored on a **0–10** scale:

```
risk = severity_weight × (confidence / 100) × mitigation_factor
```

* `severity_weight`: INFO 1 · LOW 2.5 · MEDIUM 5 · HIGH 8 · CRITICAL 10
* `mitigation_factor`: 0.5 when potentially mitigated, else 1.0

Findings carry: **severity** (Critical/High/Medium/Low/Info), **confidence**,
**CWE mapping**, attack-surface category, `file:line`, code snippet,
**recommendation** and concrete **remediation** guidance. They are de-duplicated
and prioritised (risk → severity → confidence → location), and the summary
reports coverage %, findings by severity, top risk surfaces and top files.

---

## 8. Output Formats

Every scan writes four artifacts to the output directory:

* **`findings.json`** — full structured results (meta, stats, summary, findings).
* **`findings.csv`** — one row per finding, spreadsheet-friendly.
* **`findings.db`** — SQLite with a proper schema (`scan_meta`, `surfaces`,
  `findings`) and indexes on severity/surface/status/file. Query it directly:

  ```sql
  SELECT surface, severity, file, line FROM findings
  WHERE status = 'VULNERABLE' ORDER BY risk_score DESC;
  ```

* **`report.html`** — a beautiful, **self-contained** report (no network calls):
  severity badges, live filtering/search/sort, per-surface coverage grid,
  top-risk panel and expandable findings with snippets and remediation. Open it
  straight from disk.

---

## 9. Extending the Scanner

Adding a new detector is a two-step, drop-in process:

1. **Write the rule** in the appropriate surface module (e.g.
   `attack_surface/input_surface/input.py`). A `Rule` supports regex patterns,
   an optional per-hit `checker`, a whole-file `file_checker` (for AST/structured
   analysis), sanitizer/negative patterns, extension and filename filters, and
   keyword pre-filters:

   ```python
   Rule(
       id="DB-005",
       surface="database",
       name="NoSQL injection via $where",
       description="User input reaches a MongoDB $where clause.",
       severity=Severity.HIGH,
       cwe="CWE-943",
       extensions=(".js", ".ts", ".py"),
       keywords=("$where",),
       patterns=(r"\$where\s*:\s*(?:req\.|request\.)",),
       sanitizers=(r"parseInt", r"Number\(", r"validate"),
       recommendation="Never build $where from input; use typed query operators.",
   )
   ```

2. **Register it**: append the rule to that module's `RULES` tuple. New *surface
   packages* are added by listing them in `RULE_MODULES` and adding a `Surface`
   entry in `rules.py`. The registry validates on load (unique IDs, valid
   surface, every surface covered).

To add an entirely new **surface**, add a `Surface(...)` to `SURFACES` in
`rules.py`, point it at a package, and drop a module with a `RULES` tuple into
that package — no other wiring required.

---

## 10. Testing

A comprehensive test suite ships with the tool. The `test_sandbox/` contains a
**vulnerable** and a **sanitized** sample for every one of the 40 surfaces; the
integration test asserts that each surface fires in the vulnerable tree and that
the sanitized counterparts produce **no** vulnerable findings (sanitization
awareness).

```bash
pip install -e ".[dev]"
pytest                          # unit + integration
pytest -k integration -q        # sandbox detection + sanitization only
pytest --cov=attack_surface     # with coverage
```

> ⚠️ The sandbox is intentionally insecure example code. Never deploy or import
> it; all "secrets" in it are fake, high-entropy placeholders.

---

## 11. Performance

* **Compiled regexes** with cheap keyword pre-filters gate expensive matching.
* **Per-extension rule index** so each file only runs the rules that can apply.
* **Concurrent scanning** via `ThreadPoolExecutor` (I/O bound) or
  `ProcessPoolExecutor` (`--processes`, CPU bound on very large trees).
* **Fast discovery** with `os.scandir` and aggressive pruning of `node_modules`,
  `.git`, virtualenvs, build output, minified bundles, lockfiles and binaries.
* **Memory-efficient**: large files are streamed; the AST/comment maps for a file
  are computed once and shared by all its rules.
* **Early exit** on binary/oversized files with no wasted reads.

Typical throughput is thousands of files per second; the bundled repository scan
(~40 sandbox files) completes in well under a second.

---

⚡ Made with ❤️ by **Tokyo** — *Stay Secure, Stay Vigilant!*
