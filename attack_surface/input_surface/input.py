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
            r"json\.loads",
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
            r"request\.GET\.get\s*\(\s*['\"]search['\"]",
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
            r"f['\"]SELECT.*\s+WHERE\s+id\s*=\s*\{",
            r"WHERE\s+id\s*=\s*['\"]?\s*\$",
            r"request\.(args|form)\.get\s*\(\s*['\"]id['\"]",
        ],
        "sanitizer_patterns": [
            r"int\s*\(",
            r"uuid",
            r"ObjectId",
            r"parseInt",
            r"Number\s*\(",
            r"\.escape\s*\(",
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
            r"\.query\s*\(\s*['\"]\s*\+\s*\w+\s*\+\s*['\"]",
            r"SELECT.*\s*\+\s*.*\s*FROM",
        ],
        "sanitizer_patterns": [
            r"\.execute\s*\([^,]+,\s*\(",
            r"prepared\s*statement",
            r"bindparam",
            r"\.format\s*\(\s*\[",
            r"paramstyle",
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
            r"gql\s*\(`[^`]*\$\{",
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
    # 25. cache-services
    {
        "id": "INP-006",
        "category": "cache-services",
        "name": "Unencrypted Cache",
        "description": "Redis/Memcached without encryption or auth",
        "file_exts": [".py", ".js", ".conf", ".yml"],
        "vuln_patterns": [
            r"redis\.Redis\s*\(",
            r"redis\.StrictRedis\s*\(",
            r"memcache\.Client\s*\(",
            r"Cache\s*\(\s*['\"]redis",
        ],
        "sanitizer_patterns": [
            r"ssl\s*=\s*True",
            r"password\s*=",
            r"requirepass",
            r"tls\s*=",
        ],
        "severity": "MEDIUM",
        "cwe": "CWE-311"
    },
    # 26. message-queues
    {
        "id": "INP-007",
        "category": "message-queues",
        "name": "Insecure Deserialization",
        "description": "Using pickle/yaml.load on untrusted data",
        "file_exts": [".py", ".js", ".java"],
        "vuln_patterns": [
            r"pickle\.loads\s*\(",
            r"yaml\.load\s*\(",
            r"serialize\.unserialize\s*\(",
            r"ObjectInputStream\s*\(",
        ],
        "sanitizer_patterns": [
            r"json\.loads",
            r"yaml\.safe_load",
            r"Loader\s*=\s*yaml\.SafeLoader",
            r"SafeSerializer",
        ],
        "severity": "CRITICAL",
        "cwe": "CWE-502"
    },
    # 40. miscellaneous
    {
        "id": "INP-008",
        "category": "miscellaneous",
        "name": "Insecure Library Method",
        "description": "Dangerous library methods that can lead to RCE",
        "file_exts": [".py", ".js", ".php"],
        "vuln_patterns": [
            r"yaml\.load\s*\(",
            r"xml\.etree\.ElementTree\.parse",
            r"eval\s*\(",
            r"pickle\.loads\s*\(",
            r"marshal\.loads\s*\(",
            r"base64\.b64decode\s*\([^)]+\)\s*",
        ],
        "sanitizer_patterns": [
            r"yaml\.safe_load",
            r"defusedxml",
            r"json\.loads",
            r"ast\.literal_eval",
        ],
        "severity": "HIGH",
        "cwe": "CWE-502"
    },
]