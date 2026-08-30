"""
directory_traversal.py

Backward-compatibility shim. The real detector implementation now
lives in waf_core/detectors/directory_traversal.py (framework-independent, single
source of truth). This module re-exports its detect() function so
any existing `from waf.detectors.directory_traversal import detect` keeps
working unchanged.
"""

from waf_core.detectors.directory_traversal import detect

__all__ = ["detect"]
