"""
Rules Catalog - Organized vulnerability detection rules
"""

from attack_surface.rules_catalog.core_application import APPLICATION_RULES
from attack_surface.rules_catalog.core_network import NETWORK_RULES
from attack_surface.rules_catalog.core_operations import OPERATIONS_RULES
from attack_surface.rules_catalog.core_secrets import SECRETS_RULES

__all__ = [
    'APPLICATION_RULES',
    'NETWORK_RULES',
    'OPERATIONS_RULES',
    'SECRETS_RULES'
]