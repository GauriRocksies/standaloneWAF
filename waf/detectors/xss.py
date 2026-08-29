"""
xss.py

Backward-compatibility shim. The real detector implementation now
lives in waf_core/detectors/xss.py (framework-independent, single
source of truth). This module re-exports its detect() function so
any existing `from waf.detectors.xss import detect` keeps
working unchanged.
"""

from waf_core.detectors.xss import detect

__all__ = ["detect"]
