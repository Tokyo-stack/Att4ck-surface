"""
Communications Surface - Email, Notifications, Payments, Third-party
"""

COMMUNICATIONS_RULES = [
    {
        "id": "COM-001",
        "category": "payment-systems",
        "name": "Non-PCI Compliant Payment Handling",
        "description": "Custom credit card handling - use PCI compliant gateway",
        "file_exts": [".py", ".js", ".php", ".java"],
        "vuln_patterns": [
            r"card_number",
            r"cvv",
            r"credit_card",
            r"expiry_date",
            r"cc_number",
        ],
        "sanitizer_patterns": [
            r"stripe",
            r"braintree",
            r"paypal",
            r"pci_compliant",
        ],
        "severity": "CRITICAL",
        "cwe": "CWE-312"
    },
    {
        "id": "COM-002",
        "category": "email-flows",
        "name": "SMTP Header Injection",
        "description": "SMTP vulnerable to header injection",
        "file_exts": [".py", ".js", ".php"],
        "vuln_patterns": [
            r"sendmail\s*\(",
            r"smtplib",
            r"nodemailer",
            r"mail\s*\(",
        ],
        "sanitizer_patterns": [
            r"replace\s*\(\s*['\\]n['\\]\s*,\s*['']\s*\)",
            r"validate_email\s*\(",
            r"MIMEText",
        ],
        "severity": "HIGH",
        "cwe": "CWE-77"
    },
    {
        "id": "COM-003",
        "category": "third-party-integrations",
        "name": "SSRF via Third-party Requests",
        "description": "External requests without validation or timeouts",
        "file_exts": [".py", ".js", ".java"],
        "vuln_patterns": [
            r"requests\.(get|post|put|delete)\s*\(\s*['\"]http",
            r"fetch\s*\(\s*['\"]http",
            r"axios\.(get|post)\s*\(\s*['\"]http",
        ],
        "sanitizer_patterns": [
            r"timeout\s*=",
            r"validate_destination",
            r"allow_list",
            r"whitelist",
        ],
        "severity": "HIGH",
        "cwe": "CWE-918"
    },
]