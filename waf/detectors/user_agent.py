"""
user_agent.py

Backward-compatibility shim. The real detector implementation now
lives in waf_core/detectors/user_agent.py (framework-independent, single
source of truth). This module re-exports its detect() function so
any existing `from waf.detectors.user_agent import detect` keeps
working unchanged.
"""

from waf_core.detectors.user_agent import detect

__all__ = ["detect"]
