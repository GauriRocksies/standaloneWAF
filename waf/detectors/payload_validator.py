"""
payload_validator.py

Backward-compatibility shim. The real detector implementation now
lives in waf_core/detectors/payload_validator.py (framework-independent, single
source of truth). This module re-exports its detect() function so
any existing `from waf.detectors.payload_validator import detect` keeps
working unchanged.
"""

from waf_core.detectors.payload_validator import detect

__all__ = ["detect"]
