# attack_surface/rules.py
import re
from attack_surface.rules_catalog.core_application import APPLICATION_RULES
from attack_surface.rules_catalog.core_network import NETWORK_RULES
from attack_surface.rules_catalog.core_operations import OPERATIONS_RULES
from attack_surface.rules_catalog.core_secrets import SECRETS_RULES

class Rule:
    def __init__(self, category, name, file_exts, vuln_patterns, sanitizer_patterns, vuln_desc, safe_desc):
        self.category = category
        self.name = name
        self.file_exts = file_exts
        self.vuln_patterns = []
        self.sanitizer_patterns = []
        self.vuln_desc = vuln_desc
        self.safe_desc = safe_desc

        # Safely compile vulnerability patterns
        for p in vuln_patterns:
            try:
                self.vuln_patterns.append(re.compile(p, re.IGNORECASE))
            except re.error as e:
                print(f"\033[1;33m[!] Scanner Warning: Skipping invalid vuln regex pattern [{p}] in '{category}': {e}\033[0m")

        # Safely compile sanitizer patterns
        for p in sanitizer_patterns:
            try:
                self.sanitizer_patterns.append(re.compile(p, re.IGNORECASE))
            except re.error as e:
                print(f"\033[1;33m[!] Scanner Warning: Skipping invalid sanitizer regex pattern [{p}] in '{category}': {e}\033[0m")

# Merge all four modular rule lists into one unified catalog
RAW_CATALOG = APPLICATION_RULES + NETWORK_RULES + OPERATIONS_RULES + SECRETS_RULES

# Auto-instantiate raw items into compiled Rule engine objects
RULES = [
    Rule(
        category=item["category"],
        name=item["name"],
        file_exts=item["file_exts"],
        vuln_patterns=item["vuln_patterns"],
        sanitizer_patterns=item["sanitizer_patterns"],
        vuln_desc=item["vuln_desc"],
        safe_desc=item["safe_desc"]
    ) for item in RAW_CATALOG
]
