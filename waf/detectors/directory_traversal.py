"""
directory_traversal.py

Detects path traversal attempts in the URL path itself and in any
request value that might be used to build a filesystem path (query
params, POST body, JSON body). Signature matching comes from the
shared registry (attack_type="path_traversal"), which already covers
plain "../" sequences, single- and double-URL-encoded variants, and
known sensitive-file targets (/etc/passwd, boot.ini, etc.).

This file's own contribution: request.path is checked *unnormalized*
first (to catch raw encoded traversal before Django's URL resolver
has a chance to collapse it), and a request that mixes a traversal
sequence with a sensitive-file target scores higher than either alone
— "../../etc/passwd" is far more dangerous than "../" by itself.
"""

from waf.detectors.base_detector import (
    build_result,
    get_all_text_values,
    match_all,
    report,
    safe_detect,
)
from waf.detectors.patterns import severity_for_score
from waf.logging.logger import get_logger

logger = get_logger(__name__)

DETECTOR_NAME = "directory_detector"
ATTACK_TYPE = "path_traversal"

MULTI_SIGNAL_THRESHOLD = 2
MULTI_SIGNAL_BONUS = 10


@safe_detect
def detect(request):
    """
    Inspect the request path and all text values for directory
    traversal signatures. Returns the standard detection dict, or
    None if none were found.
    """
    values = [request.path] + get_all_text_values(request)

    matched = {}
    for value in values:
        for rule in match_all(value, ATTACK_TYPE):
            matched[rule.rule_id] = rule

    if not matched:
        return None

    best = max(matched.values(), key=lambda r: r.score)
    score = best.score
    reason = best.description

    if len(matched) >= MULTI_SIGNAL_THRESHOLD:
        score = min(100, score + MULTI_SIGNAL_BONUS)
        reason = f"{reason}; combined with {len(matched) - 1} other traversal indicator(s)"
        logger.info(
            "multiple path traversal indicators co-occurred on %s: %s",
            request.path, sorted(matched),
        )

    result = build_result(
        attack=ATTACK_TYPE,
        score=score,
        severity=severity_for_score(score),
        reason=reason,
        rule=best.rule_id,
        detector=DETECTOR_NAME,
    )
    report(request, result, payload={"matched_rules": sorted(matched)})
    return result
