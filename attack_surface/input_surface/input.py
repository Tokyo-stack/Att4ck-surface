"""
Input Surface - User Inputs, Parameters, Database, GraphQL
"""

INPUT_RULES = [
    # 4. user-inputs
    {
        "id": "INP-001",
        "category": "user-inputs",
        "name": "Dynamic Code Execution",
        "description": "eval/exec with user input - risk of RCE",
        "file_exts": [".py", ".js", ".php", ".rb"],
        "vuln_patterns": [
            r"eval\s*\(",
            r"exec\s*\(",
            r"system\s*\(",
            r"popen\s*\(",
            r"subprocess\.(Popen|run|call)\s*\(",
            r"new\s+Function\s*\(",
        ],
        "sanitizer_patterns": [
            r"int\s*\(",
            r"float\s*\(",
            r"shlex\.quote",
            r"escape\s*\(",
            r"validation",
            r"sanitize",
            r"ast\.literal_eval",
        ],
        "severity": "CRITICAL",
        "cwe": "CWE-94"
    },
    # 5. search-parameters
    {
        "id": "INP-002",
        "category": "search-parameters",
        "name": "Reflected XSS - Search Parameter",
        "description": "Search parameter directly rendered to page",
        "file_exts": [".py", ".js", ".html", ".php"],
        "vuln_patterns": [
            r"request\.args\.get\s*\(\s*['\"]q['\"]",
            r"req\.query\.search",
            r"location\.search",
            r"$_GET\['q'\]",
        ],
        "sanitizer_patterns": [
            r"html\.escape",
            r"DOMPurify",
            r"escape\s*\(",
            r"textContent",
            r"innerText",
            r"encodeURIComponent",
        ],
        "severity": "HIGH",
        "cwe": "CWE-79"
    },
    # 6. id-parameters
    {
        "id": "INP-003",
        "category": "id-parameters",
        "name": "SQL Injection - ID Parameter",
        "description": "ID parameter used in SQL without validation",
        "file_exts": [".py", ".js", ".php", ".java"],
        "vuln_patterns": [
            r"SELECT.*\s+WHERE\s+id\s*=\s*['\"]?\s*\+\s*\w+",
            r"WHERE\s+id\s*=\s*['\"]?\s*\$",
            r"request\.(args|form)\.get\s*\(\s*['\"]id['\"]",
        ],
        "sanitizer_patterns": [
            r"int\s*\(",
            r"uuid",
            r"ObjectId",
            r"parseInt",
            r"Number\s*\(",
        ],
        "severity": "CRITICAL",
        "cwe": "CWE-89"
    },
    # 24. database
    {
        "id": "INP-004",
        "category": "database",
        "name": "SQL Injection - String Concatenation",
        "description": "SQL query built with string concatenation",
        "file_exts": [".py", ".js", ".php", ".java", ".go"],
        "vuln_patterns": [
            r"\.execute\s*\(\s*['\"].*%\s*.*['\"]\s*%",
            r"\.execute\s*\(\s*f['\"].*\{.*\}",
            r"SELECT.*\s*\+\s*.*\s*FROM",
        ],
        "sanitizer_patterns": [
            r"\.execute\s*\([^,]+,\s*\(",
            r"prepared\s*statement",
            r"bindparam",
            r"\.format\s*\(\s*\[",
        ],
        "severity": "CRITICAL",
        "cwe": "CWE-89"
    },
    # 8. graphql
    {
        "id": "INP-005",
        "category": "graphql",
        "name": "GraphQL Injection",
        "description": "GraphQL query built with string interpolation",
        "file_exts": [".py", ".js", ".java"],
        "vuln_patterns": [
            r"gql\s*`[^`]*\$\{",
            r"graphql\s*`[^`]*\$\{",
            r"\.query\s*\(\s*`[^`]*\$\{",
        ],
        "sanitizer_patterns": [
            r"variables\s*:",
            r"variableValues",
            r"\.setVariable",
            r"\.query\s*\([^,]+,\s*\{",
        ],
        "severity": "HIGH",
        "cwe": "CWE-89"
    },
    # === XSS Rules (from core_application.py) ===
    {
        "id": "INP-006",
        "category": "xss",
        "name": "DOM XSS - Unsafe DOM Manipulation",
        "description": "DOM-based XSS via unsafe DOM manipulation methods",
        "file_exts": [".js", ".jsx", ".ts", ".tsx", ".html", ".htm"],
        "vuln_patterns": [
            r"\.innerHTML\s*=",
            r"\.outerHTML\s*=",
            r"document\.write\s*\(",
            r"document\.writeln\s*\(",
            r"\.insertAdjacentHTML\s*\(",
            r"dangerouslySetInnerHTML",
            r"v-html\s*=",
            r"ng-bind-html\s*=",
            r"\.appendChild\s*\(\s*document\.createElement",
            r"\.createElement\s*\(\s*['\"]script['\"]\s*\)",
            r"javascript:",
            r"location\.href\s*=\s*['\"]javascript:",
            r"window\.location\s*=\s*['\"]javascript:",
        ],
        "sanitizer_patterns": [
            r"textContent\s*=",
            r"innerText\s*=",
            r"DOMPurify",
            r"sanitize\s*\(",
            r"escape\s*\(",
            r"encodeURIComponent\s*\(",
            r"\.createTextNode\s*\(",
            r"validator\.escape",
        ],
        "severity": "HIGH",
        "cwe": "CWE-79"
    },
    {
        "id": "INP-007",
        "category": "xss",
        "name": "Dangerous Code Execution",
        "description": "Dangerous code execution (eval, Function, setTimeout with string)",
        "file_exts": [".js", ".jsx", ".ts", ".tsx"],
        "vuln_patterns": [
            r"eval\s*\(",
            r"new\s+Function\s*\(",
            r"Function\s*\(",
            r"setTimeout\s*\(\s*['\"]",
            r"setInterval\s*\(\s*['\"]",
            r"import\s*\(\s*['\"]",
            r"require\s*\(\s*['\"]",
            r"vm\.runInContext",
            r"vm\.runInNewContext",
        ],
        "sanitizer_patterns": [
            r"JSON\.parse",
            r"validator",
            r"sanitize",
            r"escape",
            r"int\s*\(",
            r"float\s*\(",
        ],
        "severity": "CRITICAL",
        "cwe": "CWE-94"
    },
]