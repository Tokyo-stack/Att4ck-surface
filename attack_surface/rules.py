"""
Rules Module - Defines all scanning rules
"""

import re
from typing import List

# Import from your actual structure
from attack_surface.iam_surface.iam import IAM_RULES
from attack_surface.input_surface.input import INPUT_RULES
from attack_surface.api_surface.api import API_RULES
from attack_surface.file_surface.file import FILE_RULES
from attack_surface.frontend_surface.frontend import FRONTEND_RULES
from attack_surface.secrets_surface.secrets import SECRETS_RULES
from attack_surface.infrastructure_surface.infrastructure import INFRASTRUCTURE_RULES
from attack_surface.communication_surface.communications import COMMUNICATIONS_RULES


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


def _build_rules(raw_rules: List[dict]) -> List[Rule]:
    """Convert raw rule dictionaries to Rule objects"""
    built = []
    for r in raw_rules:
        built.append(
            Rule(
                category=r.get("category", "UNKNOWN"),
                name=r.get("name", "Unnamed Rule"),
                file_exts=r.get("file_exts", []),
                vuln_patterns=r.get("vuln_patterns", []),
                sanitizer_patterns=r.get("sanitizer_patterns", []),
                vuln_desc=r.get("description", ""),
                safe_desc=f"Securely implemented: {r.get('name', '')}",
                severity=r.get("severity", "MEDIUM"),
                confidence=r.get("confidence", 70),
                cwe=r.get("cwe", "N/A"),
                rule_id=r.get("id", "N/A"),
            )
        )
    return built


# Combined rules from all catalogs
ALL_RULES = (
    _build_rules(IAM_RULES) +
    _build_rules(INPUT_RULES) +
    _build_rules(API_RULES) +
    _build_rules(FILE_RULES) +
    _build_rules(FRONTEND_RULES) +
    _build_rules(SECRETS_RULES) +
    _build_rules(INFRASTRUCTURE_RULES) +
    _build_rules(COMMUNICATIONS_RULES)
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