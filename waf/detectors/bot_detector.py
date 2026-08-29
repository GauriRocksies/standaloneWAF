"""
bot_detector.py

Backward-compatibility shim. The real detector implementation now
lives in waf_core/detectors/bot_detector.py (framework-independent, single
source of truth). This module re-exports its detect() function so
any existing `from waf.detectors.bot_detector import detect` keeps
working unchanged.
"""

from waf_core.detectors.bot_detector import detect

__all__ = ["detect"]
