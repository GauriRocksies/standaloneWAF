"""
http_method_validator.py

Backward-compatibility shim. The real detector implementation now
lives in waf_core/detectors/http_method_validator.py (framework-independent, single
source of truth). This module re-exports its detect() function so
any existing `from waf.detectors.http_method_validator import detect` keeps
working unchanged.
"""

from waf_core.detectors.http_method_validator import detect

__all__ = ["detect"]
