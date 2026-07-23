"""
WAF models package.

Django only scans a single models.py by default; since models/ is a
package here (per the required folder structure), every model must be
imported here so the app registry and `makemigrations` can find them.
"""

from .attack_log import AttackLog, AttackType, Severity, HTTPMethod
from .blocked_ip import BlockedIP
from .rule_stats import RuleStats
from .detector_stats import DetectorStats

__all__ = [
    'AttackLog',
    'AttackType',
    'Severity',
    'HTTPMethod',
    'BlockedIP',
    'RuleStats',
    'DetectorStats',
]