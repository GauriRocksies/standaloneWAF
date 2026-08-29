"""
command_injection.py

Backward-compatibility shim. The real detector implementation now
lives in waf_core/detectors/command_injection.py (framework-independent, single
source of truth). This module re-exports its detect() function so
any existing `from waf.detectors.command_injection import detect` keeps
working unchanged.
"""

from waf_core.detectors.command_injection import detect

__all__ = ["detect"]
