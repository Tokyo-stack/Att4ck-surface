"""
Rules Module - Defines all scanning rules
"""

import re
from typing import List

# Import from your renamed folder
from attack_surface.attack_rules.core_application import APPLICATION_RULES
from attack_surface.attack_rules.core_network import NETWORK_RULES
from attack_surface.attack_rules.core_operations import OPERATIONS_RULES
from attack_surface.attack_rules.core_secrets import SECRETS_RULES


class Rule:
    """Rule class for vulnerability detection"""
    
    def __init__(
        self,
        category: str,
        name: str,
        file_exts: List[str],
        vuln_patterns: List[str],
        sanitizer_patterns: List[str],
        vuln_desc: str,
        safe_desc: str,
        severity: str = "MEDIUM",
        confidence: int = 70,
        cwe: str = "N/A",
        rule_id: str = ""
    ):
        self.category = category
        self.name = name
        self.file_exts = file_exts or []
        self.vuln_desc = vuln_desc
        self.safe_desc = safe_desc
        self.severity = severity
        self.confidence = confidence
        self.cwe = cwe
        self.rule_id = rule_id

        # Compile patterns
        self.vuln_patterns = []
        self.sanitizer_patterns = []

        for p in vuln_patterns:
            try:
                self.vuln_patterns.append(re.compile(p, re.IGNORECASE | re.MULTILINE))
            except re.error as e:
                print(f"[WARN] Invalid vuln regex '{p}' in {category}: {e}")

        for p in sanitizer_patterns:
            try:
                self.sanitizer_patterns.append(re.compile(p, re.IGNORECASE | re.MULTILINE))
            except re.error as e:
                print(f"[WARN] Invalid sanitizer regex '{p}' in {category}: {e}")


def _build_rules(raw_rules: List[dict], category_name: str) -> List[Rule]:
    """Convert raw rule dictionaries to Rule objects"""
    built = []
    for r in raw_rules:
        built.append(
            Rule(
                category=category_name,
                name=r.get("name", category_name),
                file_exts=r.get("file_exts", []),
                vuln_patterns=r.get("vuln_patterns", []),
                sanitizer_patterns=r.get("sanitizer_patterns", []),
                vuln_desc=r.get("vuln_desc", ""),
                safe_desc=r.get("safe_desc", ""),
                severity=r.get("severity", "MEDIUM"),
                confidence=r.get("confidence", 70),
                cwe=r.get("cwe", "N/A"),
                rule_id=r.get("id", "N/A"),
            )
        )
    return built


# Combined rules from all catalogs
ALL_RULES = (
    _build_rules(APPLICATION_RULES, "APPLICATION") +
    _build_rules(NETWORK_RULES, "NETWORK") +
    _build_rules(OPERATIONS_RULES, "OPERATIONS") +
    _build_rules(SECRETS_RULES, "SECRETS")
)

# Keep RULES for backward compatibility
RULES = ALL_RULES

# Category to rules mapping
RULES_BY_CATEGORY = {}
for rule in ALL_RULES:
    if rule.category not in RULES_BY_CATEGORY:
        RULES_BY_CATEGORY[rule.category] = []
    RULES_BY_CATEGORY[rule.category].append(rule)


def get_rules_by_category(category: str) -> List[Rule]:
    """Get rules by category"""
    return RULES_BY_CATEGORY.get(category, [])


def get_rules_by_severity(severity: str) -> List[Rule]:
    """Get rules by severity"""
    return [r for r in ALL_RULES if r.severity.upper() == severity.upper()]


def get_rule_count() -> int:
    """Get total number of rules"""
    return len(ALL_RULES)


def get_rule_categories() -> List[str]:
    """Get all unique categories"""
    return list(RULES_BY_CATEGORY.keys())