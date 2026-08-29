"""
decision_engine.py

Responsible for making the final Allow/Block decision
based on the outputs returned by all detectors.

Identical decision logic to the original waf/decision_engine.py —
thresholds, scoring aggregation, and the critical-severity override
are all unchanged. Only the import path (waf.constants ->
waf_core.constants) differs.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any

from waf_core.constants import (
    ALLOW,
    BLOCK,
    DEFAULT_BLOCK_THRESHOLD,
    CRITICAL,
)


@dataclass
class Decision:
    """
    Final decision returned to the caller.
    """

    action: str
    risk_score: int
    detections: List[Dict[str, Any]] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    rules: List[str] = field(default_factory=list)
    detectors: List[str] = field(default_factory=list)


class DecisionEngine:
    """
    Aggregates detector results and decides
    whether a request should be allowed or blocked.
    """

    def __init__(self, threshold=DEFAULT_BLOCK_THRESHOLD):
        self.threshold = threshold

    def decide(self, detector_results: List[Dict[str, Any]]) -> Decision:

        if not detector_results:
            return Decision(
                action=ALLOW,
                risk_score=0,
                detections=[],
                reasons=[],
                rules=[],
                detectors=[]
            )

        # -------- Aggregate -------- #

        total_score = 0

        reasons = []
        rules = []
        detectors = []

        seen_reasons = set()
        seen_rules = set()
        seen_detectors = set()

        critical_found = False

        for result in detector_results:

            score = int(result.get("score", 0))
            total_score += score

            if result.get("severity") == CRITICAL:
                critical_found = True

            reason = result.get("reason")
            if reason and reason not in seen_reasons:
                seen_reasons.add(reason)
                reasons.append(reason)

            rule = result.get("rule")
            if rule and rule not in seen_rules:
                seen_rules.add(rule)
                rules.append(rule)

            detector = result.get("detector")
            if detector and detector not in seen_detectors:
                seen_detectors.add(detector)
                detectors.append(detector)

        # Cap risk score at 100
        total_score = min(total_score, 100)

        # -------- Decision -------- #

        should_block = (
            critical_found or
            total_score >= self.threshold
        )

        return Decision(
            action=BLOCK if should_block else ALLOW,
            risk_score=total_score,
            detections=detector_results,
            reasons=reasons,
            rules=rules,
            detectors=detectors,
        )
