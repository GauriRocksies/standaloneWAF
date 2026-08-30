"""
http_method_validator.py

Validates the HTTP method against an allow-list. Simple by design —
this is a cheap, first-line check that doesn't need payload
inspection, so it's efficient to run even under scanner-sweep volume.

Allowed: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD
Flagged: TRACE, CONNECT, TRACK (all three have known abuse history —
TRACE enables cross-site tracing/cookie theft, CONNECT can be abused
for tunneling, TRACK is a legacy IIS variant of TRACE), and any
method outside the allow-list.
"""

import logging
from waf_core.base_detector import build_result, report, safe_detect
from waf_core.patterns import severity_for_score

logger = logging.getLogger("waf_core." + __name__)

DETECTOR_NAME = "method_validator"

ALLOWED_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}

# Methods with documented abuse history get a dedicated rule/score;
# anything else unrecognized falls through to the generic rule.
_FLAGGED_METHODS = {
    "TRACE": ("METHOD-001", 55, "TRACE method (cross-site tracing / cookie theft vector)"),
    "CONNECT": ("METHOD-002", 55, "CONNECT method (tunneling abuse vector)"),
    "TRACK": ("METHOD-003", 50, "TRACK method (legacy TRACE variant)"),
}


@safe_detect
def detect(request):
    """
    Validate the request's HTTP method. Returns the standard detection
    dict if the method is flagged or unrecognized, or None if it's on
    the allow-list.
    """
    method = (request.method or "").upper()

    if method in ALLOWED_METHODS:
        return None

    if method in _FLAGGED_METHODS:
        rule_id, score, reason = _FLAGGED_METHODS[method]
    else:
        rule_id, score, reason = "METHOD-004", 40, f"unrecognized HTTP method '{method}'"

    result = build_result(
        attack="other", score=score, severity=severity_for_score(score),
        reason=reason, rule=rule_id, detector=DETECTOR_NAME,
    )
    report(request, result, payload={"method": method})
    return result
