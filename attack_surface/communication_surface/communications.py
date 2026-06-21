"""
Communications Surface - Email, Notifications, Payments, Third-party
"""

COMMUNICATIONS_RULES = [
    # 15. payment-systems
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
            r"card_holder",
            r"cc_number",
        ],
        "sanitizer_patterns": [
            r"stripe",
            r"braintree",
            r"paypal",
            r"pci_compliant",
            r"square",
            r"authorize",
        ],
        "severity": "CRITICAL",
        "cwe": "CWE-312"
    },
    # 17. email-flows
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
            r"send_email\s*\(",
        ],
        "sanitizer_patterns": [
            r"replace\s*\(\s*['\\]n['\\]\s*,\s*['']\s*\)",
            r"validate_email\s*\(",
            r"MIMEText",
            r"EmailMessage",
            r"sanitize_email",
        ],
        "severity": "HIGH",
        "cwe": "CWE-77"
    },
    # 18. notification-services
    {
        "id": "COM-003",
        "category": "notification-services",
        "name": "Plaintext Sensitive Notifications",
        "description": "Sensitive data in SMS/push notifications",
        "file_exts": [".py", ".js"],
        "vuln_patterns": [
            r"send_sms\s*\(",
            r"send_push\s*\(",
            r"twilio\.messages",
            r"firebase\.send",
            r"notification\.",
        ],
        "sanitizer_patterns": [
            r"mask\s*\(",
            r"encrypted",
            r"redact\s*\(",
            r"token_only",
            r"hide_sensitive",
        ],
        "severity": "MEDIUM",
        "cwe": "CWE-312"
    },
    # 31. third-party-integrations
    {
        "id": "COM-004",
        "category": "third-party-integrations",
        "name": "SSRF via Third-party Requests",
        "description": "External requests without validation or timeouts",
        "file_exts": [".py", ".js", ".java"],
        "vuln_patterns": [
            r"requests\.(get|post|put|delete)\s*\(\s*['\"]http",
            r"fetch\s*\(\s*['\"]http",
            r"axios\.(get|post)\s*\(\s*['\"]http",
            r"urllib\.request\.urlopen\s*\(",
            r"http\.request\s*\(",
        ],
        "sanitizer_patterns": [
            r"timeout\s*=",
            r"validate_destination",
            r"allow_list",
            r"whitelist",
            r"validate_url",
        ],
        "severity": "HIGH",
        "cwe": "CWE-918"
    },
]