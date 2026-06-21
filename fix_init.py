# save as fix_init.py and run: python fix_init.py
import os

files = {
    "attack_surface/__init__.py": '''"""
ATT4ck Surface - Attack Surface Mapping & Security Review Framework
"""

__version__ = "1.0.0"
__author__ = "Tokyo"

from attack_surface.scanner import SurfaceScanner
from attack_surface.rules import RULES, get_rules_by_category, get_rule_count
from attack_surface.web_crawler import WebCrawler
from attack_surface.exporter import export_results

__all__ = [
    'SurfaceScanner',
    'RULES',
    'get_rules_by_category',
    'get_rule_count',
    'WebCrawler',
    'export_results'
]
''',
    "attack_surface/secrets_surface/__init__.py": '''"""
Secrets Surface - Secrets detection rules
"""
from attack_surface.secrets_surface.secrets import SECRETS_RULES

__all__ = ['SECRETS_RULES']
''',
    "attack_surface/iam_surface/__init__.py": '''"""
IAM Surface - Authentication, Authorization rules
"""
from attack_surface.iam_surface.iam import IAM_RULES

__all__ = ['IAM_RULES']
''',
    "attack_surface/input_surface/__init__.py": '''"""
Input Surface - User input, XSS, SQL injection rules
"""
from attack_surface.input_surface.input import INPUT_RULES

__all__ = ['INPUT_RULES']
''',
    "attack_surface/api_surface/__init__.py": '''"""
API Surface - API endpoints, webhooks, monitoring rules
"""
from attack_surface.api_surface.api import API_RULES

__all__ = ['API_RULES']
''',
    "attack_surface/file_surface/__init__.py": '''"""
File Surface - File uploads, downloads, backups rules
"""
from attack_surface.file_surface.file import FILE_RULES

__all__ = ['FILE_RULES']
''',
    "attack_surface/frontend_surface/__init__.py": '''"""
Frontend Surface - JavaScript, redirects, assets rules
"""
from attack_surface.frontend_surface.frontend import FRONTEND_RULES

__all__ = ['FRONTEND_RULES']
''',
    "attack_surface/infrastructure_surface/__init__.py": '''"""
Infrastructure Surface - Containers, CI/CD, dependencies rules
"""
from attack_surface.infrastructure_surface.infrastructure import INFRASTRUCTURE_RULES

__all__ = ['INFRASTRUCTURE_RULES']
''',
    "attack_surface/communication_surface/__init__.py": '''"""
Communication Surface - Email, payments, third-party rules
"""
from attack_surface.communication_surface.communications import COMMUNICATIONS_RULES

__all__ = ['COMMUNICATIONS_RULES']
'''
}

for path, content in files.items():
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Created: {path}")