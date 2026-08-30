"""
engine.py

Runs all registered WAF detectors against an incoming WAFRequest
and delegates the final decision to the Decision Engine.

Behavior preserved from the original waf/engine.py:
  * every registered detector runs, exceptions from one detector never
    stop the others (or the request)
  * the decision engine sees every detector's raw result dict and
    makes exactly one final allow/block call
  * detections and the final decision are handed to a persistence
    layer together, in one shot, *after* the decision is made — this
    is what let the original project fix its
    "every row stuck at blocked=False" bug (see original engine.py's
    docstring), and that fix is preserved here.

What changed for framework independence: the original engine called
Member 3's `waf.logging.attack_logger.log_attack()` directly, which
pulls in Django's ORM and `django.utils.timezone`. That is exactly
the kind of Django coupling Section 15 of the extraction spec says
must live outside waf_core. Persistence is now an optional
`on_detection` callback supplied by whoever constructs the engine.
Framework integrations (e.g. waf_integration/middleware.py for
Django) wire this callback to the real log_attack(); the standalone
core itself has no idea persistence exists.
"""

import logging
from typing import Any, Callable, Dict, List, Optional

from waf_core.constants import BLOCK
from waf_core.decision_engine import Decision, DecisionEngine
from waf_core.detectors import DETECTOR_REGISTRY
from waf_core.base_detector import get_headers
from waf_core.request_adapter import WAFRequest

logger = logging.getLogger("waf_core")

# Signature: (request, detector_results, decision) -> None
OnDetectionHook = Callable[[WAFRequest, List[Dict[str, Any]], Decision], None]


class WAFEngine:
    """
    Coordinates execution of all registered detectors.

    Args:
        on_detection: optional callback invoked once per request that
            produced at least one detection, receiving the request,
            the raw list of detector result dicts, and the final
            Decision. Used by framework integrations to persist
            detections (DB rows, log files, auto-block counters)
            without waf_core needing to know how or whether that
            happens. Never required — the core works standalone
            without one.
    """

    def __init__(self, on_detection: Optional[OnDetectionHook] = None):
        self.decision_engine = DecisionEngine()
        self.on_detection = on_detection

    def inspect(self, request: WAFRequest) -> Decision:
        """
        Execute every detector on the request and decide allow/block.

        Returns:
            Decision: Final allow/block decision.
        """

        detector_results: List[Dict[str, Any]] = []

        logger.debug(
            "Running %d detector(s)...",
            len(DETECTOR_REGISTRY)
        )

        for detector in DETECTOR_REGISTRY:
            detector_name = getattr(detector, "__name__", str(detector))

            try:
                result = detector(request)

                if result:
                    detector_results.append(result)

                    logger.debug(
                        "Detector '%s' reported %s (score=%s)",
                        detector_name,
                        result.get("attack"),
                        result.get("score"),
                    )

            except Exception:
                # Never allow one detector to crash the WAF.
                logger.exception(
                    "Detector '%s' crashed and was skipped.",
                    detector_name,
                )
                continue

        decision = self.decision_engine.decide(detector_results)

        logger.info(
            "WAF Decision: %s | Risk Score: %d | Detections: %d",
            decision.action.upper(),
            decision.risk_score,
            len(detector_results),
        )

        self._notify(request, detector_results, decision)

        return decision

    def _notify(self, request, detector_results, decision) -> None:
        """Invoke the persistence hook, if any, exactly once per
        request that produced detections. Never lets a broken hook
        take down request handling."""
        if not detector_results or self.on_detection is None:
            return
        try:
            self.on_detection(request, detector_results, decision)
        except Exception:
            logger.exception("on_detection hook raised; detections were not persisted")


__all__ = ["WAFEngine", "get_headers"]
