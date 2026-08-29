"""
persistence.py

Builds the on_detection hook that plugs waf_core.WAFEngine into
Member 3's existing persistence layer (waf.logging.attack_logger.
log_attack), which writes AttackLog rows, updates RuleStats/
DetectorStats counters, and handles IP auto-blocking.

This is the ONLY place that connects those two things. waf_core
itself has no idea log_attack (or Django, or a database) exists —
see waf_core/engine.py's on_detection parameter.

Behavior preserved exactly from the pre-extraction waf/engine.py's
_log_detections(): one AttackLog row is written per detection, all
sharing the same final blocked/response_code taken from the
aggregated Decision (not a per-detector guess), using the request's
own headers/IP/User-Agent.
"""

import logging

from waf.constants import BLOCK, HTTP_FORBIDDEN
from waf.logging.attack_logger import log_attack
from waf_core.engine import get_headers

logger = logging.getLogger("waf")


def make_log_attack_hook():
    """
    Returns an on_detection callback suitable for
    waf_core.WAFEngine(on_detection=...).
    """

    def on_detection(request, detector_results, decision):
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

    return on_detection
