"""
Rules Catalog - Organized by Attack Surface Groups
"""

from attack_surface.rules_catalog.iam import IAM_RULES
from attack_surface.rules_catalog.input import INPUT_RULES
from attack_surface.rules_catalog.api import API_RULES
from attack_surface.rules_catalog.file import FILE_RULES
from attack_surface.rules_catalog.frontend import FRONTEND_RULES
from attack_surface.rules_catalog.secrets import SECRETS_RULES
from attack_surface.rules_catalog.infrastructure import INFRASTRUCTURE_RULES
from attack_surface.rules_catalog.communications import COMMUNICATIONS_RULES

__all__ = [
    'IAM_RULES',
    'INPUT_RULES',
    'API_RULES',
    'FILE_RULES',
    'FRONTEND_RULES',
    'SECRETS_RULES',
    'INFRASTRUCTURE_RULES',
    'COMMUNICATIONS_RULES'
]