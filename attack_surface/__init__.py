"""
ATT4ck Surface - Attack Surface Mapping & Security Review Framework
"""

__version__ = "1.0.0"
__author__ = "Tokyo"

from attack_surface.scanner import SurfaceScanner
from attack_surface.xss_scanner import XSSScanner
from attack_surface.rules import RULES, get_rules_by_category, get_rule_count
from attack_surface.web_crawler import WebCrawler
from attack_surface.exporter import export_results
from attack_surface.risk_engine import get_risk, calculate_risk_score

__all__ = [
    'SurfaceScanner',
    'XSSScanner',
    'RULES',
    'get_rules_by_category',
    'get_rule_count',
    'WebCrawler',
    'export_results',
    'get_risk',
    'calculate_risk_score'
]