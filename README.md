# ATT4ck Surface Security Scanner

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [List of Attack Surfaces](#list-of-attack-surfaces)
4. [Installation and Environment Setup](#installation-and-environment-setup)
5. [Usage](#usage)

---

## 1. Overview

```text
 █████╗ ████████╗████████╗██╗  ██╗ ██████╗██╗  ██╗     ███████╗██╗   ██╗██████╗ ███████╗ █████╗  ██████╗███████╗
██╔══██╗╚══██╔══╝╚══██╔══╝██║  ██║██╔════╝██║ ██╔╝     ██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝
███████║   ██║      ██║   ███████║██║     █████╔╝      ███████╗██║   ██║██████╔╝█████╗  ███████║██║     █████╗  
██╔══██║   ██║      ██║   ╚════██║██║     ██╔═██╗      ╚════██║██║   ██║██╔══██╗██╔══╝  ██╔══██║██║     ██╔══╝  
██║  ██║   ██║      ██║        ██║╚██████╗██║  ██╗     ███████║╚██████╔╝██║  ██║██║     ██║  ██║╚██████╗███████╗
╚═╝  ╚═╝   ╚═╝      ╚═╝        ╚═╝ ╚═════╝╚═╝  ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚══════╝

╔════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                       ATT4ck Surface v1.0.0                                        ║
║                        Attack Surface Mapping & Security Review Framework                          ║
║                                                                                                    ║
║  Features:                                                                                         ║
║   • Endpoint Discovery      • Secret Detection      • File Upload Analysis                         ║
║   • API Enumeration         • Security Misconfig    • Parameter Mapping                            ║
║   • Source Code Review      • Risk Classification   • Attack Surface Coverage                      ║
║                                                                                                    ║
║  Developer : Tokyo                                                                                 ║
║  GitHub    : github.com/Tokyo-stack/Att4ck-surface                                                 ║
╚════════════════════════════════════════════════════════════════════════════════════════════════════╝
```

### Attack Surface Mapping & Security Review

ATT&ck SURFACE is a high-performance modular command-line interface (CLI) static analysis security testing (SAST) tool. It targets 40 distinct security areas (attack surfaces) and inspects codebases for vulnerabilities, accounting for sanitization blocks.

It targets 40 distinct security areas (attack surfaces) and inspects codebases for vulnerabilities, accounting for sanitization blocks.

## 2. Architecture

The project has been split into a clean, modular structure preventing bloated files:

```text
ATT4ckSurface/
├── attack_surface/
│   ├── __init__.py      # Package entry point
│   ├── banner.py        # Terminal formatting and logo banner
│   ├── rules.py         # The 40 attack surface rules
│   └── scanner.py       # Crawler and matching engine
├── main.py              # CLI Executable entry point
├── test_sandbox/        # Sandbox directory for testing matches
└── README.md            # Project guide
```

## 3. List of Attack Surfaces

The scanner monitors the following 40 categories:

1. **authentication**: Weak hashing (MD5/SHA1), hardcoded credentials.
2. **authorization**: Exposed endpoints lacking decorators.
3. **session-management**: Insecure cookie flags or unverified JWTs.
4. **user-inputs**: Dangerous dynamic exec inputs (`eval`, `exec`).
5. **search-parameters**: Insecure search parameters (reflected XSS).
6. **id-parameters**: Unvalidated ID variables mapped to SQL.
7. **api-endpoints**: Unauthenticated API paths.
8. **graphql**: Dynamic GraphQL query constructs.
9. **webhooks**: Webhooks receiving events without hmac verification.
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
33. **ci-cd**: Hardcoded tokens in Github Actions yaml files.
34. **backups**: Storing temporary/backup files inside local code.
35. **subdomains**: Hardcoded staging/development server subdomains.
36. **dns**: Insecure DNS resolution implementations.
37. **server-config**: Wide CORS wildcards (`Access-Control-Allow-Origin: *`).
38. **containers**: Dockerfiles using latest tags or running as root.
39. **source-control**: Credentials exposed in VCS clones.
40. **miscellaneous**: Insecure library methods (like standard `yaml.load`).

---

## 4. Installation and Environment Setup

Initialize and activate a virtual environment (`venv`) to run the tool cleanly:

### On Windows (PowerShell)
```powershell
# Create venv
python -m venv venv

# Activate venv
.\venv\Scripts\Activate.ps1
```

### On macOS / Linux
```bash
# Create venv
python3 -m venv venv

# Activate venv
source venv/bin/activate
```

Install standard dependencies:
```bash
pip install -r requirements.txt
```

---

## 5. Usage

Run the scanner against any directory (defaults to current directory if none provided):

```bash
python main.py <target_directory>
```

For example, to run against the included test sandbox:
```bash
python main.py test_sandbox
```
