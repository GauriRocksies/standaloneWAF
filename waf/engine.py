"""
engine.py

Runs all registered WAF detectors against an incoming request
and delegates the final decision to the Decision Engine.
"""

import logging
from typing import List, Dict, Any

from waf.detectors import DETECTOR_REGISTRY
from waf.decision_engine import DecisionEngine

logger = logging.getLogger(__name__)


class WAFEngine:
    """
    Coordinates execution of all registered detectors.
    """

    def __init__(self):
        self.decision_engine = DecisionEngine()

    def inspect(self, request):
        """
        Execute every detector on the request.

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

        return decision