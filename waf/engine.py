"""
engine.py

Runs all registered WAF detectors against an incoming request
and delegates the final decision to the Decision Engine.
"""

import logging
from typing import List, Dict, Any

from waf.constants import BLOCK, HTTP_FORBIDDEN
from waf.decision_engine import DecisionEngine
from waf.detectors import DETECTOR_REGISTRY
from waf.detectors.base_detector import get_headers
from waf.logging.attack_logger import log_attack

logger = logging.getLogger(__name__)


class WAFEngine:
    """
    Coordinates execution of all registered detectors.
    """

    def __init__(self):
        self.decision_engine = DecisionEngine()

    def inspect(self, request):
        """
        Execute every detector on the request, decide allow/block, and
        persist exactly one AttackLog row per detection with the final
        decision already baked in.

        Detection and decision used to be decoupled: each detector
        logged itself independently (always blocked=False), and the
        middleware tried to patch a single row after the fact. That
        meant multi-detector requests left most of their rows
        permanently marked blocked=False, and BlockedIP never got
        populated at all, since log_attack()'s auto-block only fires
        on blocked=True. Logging here, after self.decision_engine.decide()
        has run, fixes both.

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

        self._log_detections(request, detector_results, decision)

        return decision

    def _log_detections(self, request, detector_results, decision):
        """
        Write one AttackLog row per detection, all sharing the same
        final blocked/response_code taken from the aggregated
        decision rather than a per-detector guess.
        """
        if not detector_results:
            return

        blocked = decision.action == BLOCK
        headers = get_headers(request)
        ip = request.META.get("REMOTE_ADDR")
        ua = request.META.get("HTTP_USER_AGENT", "")

        for result in detector_results:
            try:
                log_attack({
                    "ip_address": ip,
                    "url": request.path,
                    "method": request.method,
                    "attack_type": result.get("attack"),
                    "payload": result.get("_payload"),
                    "headers": headers,
                    "severity": result.get("severity"),
                    "risk_score": result.get("score"),
                    "rule_triggered": result.get("rule"),
                    "detector_name": result.get("detector"),
                    "user_agent": ua,
                    "blocked": blocked,
                    "response_code": HTTP_FORBIDDEN if blocked else None,
                })
            except Exception:
                logger.exception(
                    "failed to log detection for rule=%s detector=%s",
                    result.get("rule"), result.get("detector"),
                )