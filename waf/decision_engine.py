"""
decision_engine.py

Backward-compatibility shim. The real implementation now lives in
waf_core/decision_engine.py (framework-independent, single source of
truth). This module re-exports it so any existing `from
waf.decision_engine import DecisionEngine, Decision` keeps working
unchanged.
"""

from waf_core.decision_engine import Decision, DecisionEngine

__all__ = ["Decision", "DecisionEngine"]
