"""
Risk Engine - Risk calculation and classification
"""

from typing import Tuple, Optional

# Category to severity mapping
CATEGORY_SEVERITY = {
    "APPLICATION": ("HIGH", 85),
    "NETWORK": ("HIGH", 80),
    "OPERATIONS": ("MEDIUM", 75),
    "SECRETS": ("CRITICAL", 90),
    "AUTHENTICATION": ("CRITICAL", 90),
    "AUTHORIZATION": ("HIGH", 85),
    "XSS": ("HIGH", 85),
    "INJECTION": ("CRITICAL", 90),
    "SSRF": ("HIGH", 80),
    "CORS": ("MEDIUM", 75),
    "LOGGING": ("MEDIUM", 70),
    "DEBUG": ("HIGH", 80),
    "CONFIG": ("MEDIUM", 75),
    "DEPENDENCIES": ("MEDIUM", 70),
}

# Default severity if not found
DEFAULT_SEVERITY = ("MEDIUM", 70)


def get_risk(category: str) -> Tuple[str, int]:
    """
    Get risk information for a category
    
    Args:
        category: The category name
        
    Returns:
        Tuple of (severity, confidence)
    """
    # Look for exact match
    if category in CATEGORY_SEVERITY:
        return CATEGORY_SEVERITY[category]
    
    # Look for partial match
    category_lower = category.lower()
    for key, value in CATEGORY_SEVERITY.items():
        if key.lower() in category_lower or category_lower in key.lower():
            return value
    
    return DEFAULT_SEVERITY


def calculate_risk_score(severity: str, confidence: int) -> int:
    """Calculate risk score based on severity and confidence"""
    severity_map = {
        "CRITICAL": 10,
        "HIGH": 8,
        "MEDIUM": 5,
        "LOW": 3,
        "INFO": 1
    }
    
    severity_score = severity_map.get(severity.upper(), 5)
    confidence_factor = confidence / 100.0
    
    return int(severity_score * confidence_factor)


def classify_finding(finding: dict) -> dict:
    """Classify a finding with risk information"""
    category = finding.get("category", "UNKNOWN")
    severity, confidence = get_risk(category)
    
    finding["severity"] = severity
    finding["confidence"] = confidence
    finding["risk_score"] = calculate_risk_score(severity, confidence)
    
    return finding


def get_severity_priority(severity: str) -> int:
    """Get priority number for severity level"""
    priority = {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 3,
        "LOW": 4,
        "INFO": 5
    }
    return priority.get(severity.upper(), 3)


def filter_by_severity(findings: list, min_severity: str = "MEDIUM") -> list:
    """Filter findings by minimum severity"""
    severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    min_index = severity_order.index(min_severity.upper())
    
    return [
        f for f in findings
        if severity_order.index(f.get("severity", "MEDIUM").upper()) >= min_index
    ]