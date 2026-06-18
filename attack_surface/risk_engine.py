# attack_surface/risk_engine.py

FEATURE_MAPPING = {
    "1": {"name": "Endpoint Discovery & Admin Portals", "categories": ["APPLICATION"]},
    "2": {"name": "Secrets Detection & Credentials", "categories": ["SECRETS"]},
    "3": {"name": "File Upload & Download Analysis", "categories": ["APPLICATION"]},
    "4": {"name": "API & GraphQL Enumeration", "categories": ["NETWORK"]},
    "5": {"name": "Security Misconfigurations", "categories": ["NETWORK"]},
    "6": {"name": "Parameter & XSS Mapping", "categories": ["APPLICATION"]},
    "7": {"name": "Full Source Code Review", "categories": None}
}


def get_risk(category):
    """
    Returns (severity, confidence) based on category mapping.
    Falls back to safe defaults if category is unknown.
    """
    return CATEGORY_SEVERITY.get(category, ("MEDIUM", 70))