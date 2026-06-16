import re

# Categories 36 - 40: High-entropy tokens, system boundaries, and framework defaults
SECRETS_RULES = [
    # 36. dns
    {
        "category": "dns",
        "name": "Unverified Host Resolution Hook",
        "file_exts": [".py", ".js"],
        "vuln_patterns": [r"socket\.gethostbyname\(", r"dns\.resolve\("],
        "sanitizer_patterns": [r"trusted_resolver", r"dnssec", r"validate_ip\("],
        "vuln_desc": "Network routing resolution engines taking host names from parameters without validation layers.",
        "safe_desc": "No attack surface found (Target hosts resolve via verified local secure authority zones)."
    },
    # 37. serverConfig
    {
        "category": "serverConfig",
        "name": "Permissive Wildcard CORS Header",
        "file_exts": [".py", ".js", ".conf"],
        "vuln_patterns": [r"Access-Control-Allow-Origin\s*,\s*['\"]\*['\"]", r"CORS_ORIGIN\s*=\s*['\"]\*['\"]"],
        "sanitizer_patterns": [r"origins\s*=\s*\[.*\]", r"allowed_hosts"],
        "vuln_desc": "Cross-Origin Resource Sharing flags mapping access wide open to any arbitrary location (`*`).",
        "safe_desc": "No attack surface found (Resource controls bound exclusively to validated domain origin lists)."
    },
    # 38. containers
    {
        "category": "containers",
        "name": "Privileged Container Inception",
        "file_exts": ["Dockerfile", ".toml"],
        "vuln_patterns": [r"FROM.*latest", r"(?i)^USER\s+root"],
        "sanitizer_patterns": [r"FROM.*@sha256:", r"USER\s+[A-Za-z0-9_\-]+(?<!root)"], # Cleaned bracket anomaly
        "vuln_desc": "Container files inheriting unchecked base setups or standard root system administrative roles.",
        "safe_desc": "No attack surface found (Containers operate via pinned image digests running under unprivileged user namespaces)."
    },
    # 39. sourceControl
    {
        "category": "sourceControl",
        "name": "Exposed Version Control Context",
        "file_exts": [".py", ".sh"],
        "vuln_patterns": [r"\.git/config", r"git\s+clone\s+https://[A-Za-z0-9]+:[A-Za-z0-9]+@"],
        "sanitizer_patterns": [r"ssh://", r"git_token", r"\.gitcredentials"],
        "vuln_desc": "Repository workflows checking out data using plain token arguments built inside strings.",
        "safe_desc": "No attack surface found (VCS updates processed safely using key-pair authentication loops)."
    },
    # 40. miscellaneous
    {
        "category": "miscellaneous",
        "name": "Insecure Component Defaults",
        "file_exts": [".py"],
        "vuln_patterns": [r"ftplib\.FTP\(", r"telnetlib\.Telnet\("],
        "sanitizer_patterns": [r"paramiko\.SSHClient", r"ftplib\.FTP_TLS\("],
        "vuln_desc": "Legacy cleartext network routing modules configured to pass files or metrics unencrypted.",
        "safe_desc": "No attack surface found (Standard actions route securely through SSH or active TLS configurations)."
    }
]
