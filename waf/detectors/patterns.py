"""
patterns.py

Backward-compatibility shim. The shared pattern registry now lives
in waf_core/patterns.py (framework-independent, single source of
truth). This module re-exports it so any existing `from
waf.detectors.patterns import REGISTRY, Rule, severity_for_score`
keeps working unchanged.
"""

from waf_core.patterns import REGISTRY, Rule, severity_for_score

__all__ = ["REGISTRY", "Rule", "severity_for_score"]
