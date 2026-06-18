# attack_surface/risk_engine.py

CATEGORY_SEVERITY = {
    "authentication": ("CRITICAL", 95),
    "authorization": ("CRITICAL", 95),
    "sessionManagement": ("CRITICAL", 90),

    "secretsConfig": ("CRITICAL", 99),

    "fileUploads": ("HIGH", 85),
    "fileDownloads": ("HIGH", 80),

    "apiEndpoints": ("MEDIUM", 80),
    "adminPortals": ("MEDIUM", 70),

    "redirects": ("MEDIUM", 75),

    "documentation": ("LOW", 60),
    "monitoring": ("LOW", 60),
    "logging": ("LOW", 60),

    "javascriptAnalysis": ("INFO", 50)
}


def get_risk(category):
    """
    Returns (severity, confidence) based on category mapping.
    Falls back to safe defaults if category is unknown.
    """
    return CATEGORY_SEVERITY.get(category, ("MEDIUM", 70))