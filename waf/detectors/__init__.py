"""
waf.detectors

Backward-compatibility shim. The real detector registry now lives in
waf_core/detectors/ (framework-independent, single source of truth).
This module re-exports DETECTOR_REGISTRY so any existing
`from waf.detectors import DETECTOR_REGISTRY` keeps working
unchanged.
"""

from waf_core.detectors import DETECTOR_REGISTRY

__all__ = ["DETECTOR_REGISTRY"]
