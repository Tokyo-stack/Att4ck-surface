import re
from attack_surface.rules_catalog.core_application import APPLICATION_RULES
from attack_surface.rules_catalog.core_network import NETWORK_RULES
from attack_surface.rules_catalog.core_operations import OPERATIONS_RULES
from attack_surface.rules_catalog.core_secrets import SECRETS_RULES


class Rule:
    def __init__(
        self,
        category,
        name,
        file_exts,
        vuln_patterns,
        sanitizer_patterns,
        vuln_desc,
        safe_desc,
        severity="MEDIUM",
        confidence=70,
        cwe="N/A"
    ):
        self.category = category
        self.name = name
        self.file_exts = file_exts or []

        self.vuln_desc = vuln_desc
        self.safe_desc = safe_desc

        self.severity = severity
        self.confidence = confidence
        self.cwe = cwe

        self.vuln_patterns = []
        self.sanitizer_patterns = []

        # Compile vulnerability patterns
        for p in vuln_patterns:
            try:
                self.vuln_patterns.append(re.compile(p, re.IGNORECASE))
            except re.error as e:
                print(f"[WARN] Invalid vuln regex '{p}' in {category}: {e}")

        # Compile sanitizer patterns
        for p in sanitizer_patterns:
            try:
                self.sanitizer_patterns.append(re.compile(p, re.IGNORECASE))
            except re.error as e:
                print(f"[WARN] Invalid sanitizer regex '{p}' in {category}: {e}")


# Convert raw rule dictionaries into Rule objects safely
def _build_rules(raw_rules, category_name):
    built = []
    for r in raw_rules:
        built.append(
            Rule(
                category=category_name,
                name=r.get("name", category_name),
                file_exts=r.get("file_exts", []),
                vuln_patterns=r.get("patterns", []),
                sanitizer_patterns=r.get("sanitizers", []),
                vuln_desc=r.get("vuln_desc", ""),
                safe_desc=r.get("safe_desc", ""),
                severity=r.get("severity", "MEDIUM"),
                confidence=r.get("confidence", 70),
                cwe=r.get("cwe", "N/A"),
            )
        )
    return built


RULES = (
    _build_rules(APPLICATION_RULES, "APPLICATION") +
    _build_rules(NETWORK_RULES, "NETWORK") +
    _build_rules(OPERATIONS_RULES, "OPERATIONS") +
    _build_rules(SECRETS_RULES, "SECRETS")
)