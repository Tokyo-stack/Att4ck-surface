"""
Attack Rules - Core vulnerability detection rules
"""

from attack_surface.attack_rules.core_application import APPLICATION_RULES
from attack_surface.attack_rules.core_network import NETWORK_RULES
from attack_surface.attack_rules.core_operations import OPERATIONS_RULES
from attack_surface.attack_rules.core_secrets import SECRETS_RULES

__all__ = [
    'APPLICATION_RULES',
    'NETWORK_RULES',
    'OPERATIONS_RULES',
    'SECRETS_RULES'
]