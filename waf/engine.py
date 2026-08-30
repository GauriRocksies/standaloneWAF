"""
engine.py

Backward-compatibility shim. The detection/decision logic now lives
in waf_core/engine.py (framework-independent, single source of
truth) — this module does not reimplement it.

The standalone WAFEngine takes persistence as an optional
on_detection hook (see waf_core/engine.py's docstring) rather than
calling Member 3's log_attack() directly. Code that still does
`from waf.engine import WAFEngine; WAFEngine()` expects that logging
to keep happening automatically, so this subclass wires the same
log_attack-backed hook used by waf_integration/middleware.py by
default -- preserving the original behavior exactly, without
duplicating the engine itself.
"""

from waf_core.engine import WAFEngine as _CoreWAFEngine
from waf_integration.persistence import make_log_attack_hook


class WAFEngine(_CoreWAFEngine):
    """Same engine as waf_core.engine.WAFEngine, pre-wired to persist
    detections via Member 3's log_attack() unless the caller supplies
    its own on_detection hook."""

    def __init__(self, on_detection=None):
        super().__init__(on_detection=on_detection or make_log_attack_hook())


__all__ = ["WAFEngine"]
