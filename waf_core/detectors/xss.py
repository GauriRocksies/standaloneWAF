"""
xss.py

Detects Cross-Site Scripting across query params, POST body, JSON
body, cookies, and headers. Signature matching comes from the shared
registry (attack_type="xss"); this file adds XSS-specific
corroboration: a tag alone (<svg>, <iframe>) is common in rich-text
input, but a tag plus an inline event handler plus a JS sink
(document.cookie, eval, innerHTML) together is a strong indicator of
an actual payload rather than incidental markup.

Encoded/obfuscated payloads (HTML-entity, URL-encoded, double-encoded,
mixed-case) are handled by base_detector.normalize() before matching
rather than by duplicating patterns here — see match_all().
"""

import logging
from waf_core.base_detector import (
    build_result,
    get_all_text_values,
    match_all,
    report,
    safe_detect,
)
from waf_core.patterns import severity_for_score

logger = logging.getLogger("waf_core." + __name__)

DETECTOR_NAME = "xss_detector"
ATTACK_TYPE = "xss"

# XSS payloads are more compact than SQLi ones, so two corroborating
# indicators (e.g. a tag + an event handler) is already meaningful.
MULTI_SIGNAL_THRESHOLD = 2
MULTI_SIGNAL_BONUS = 10

# Ignore isolated weak XSS indicators.
MIN_XSS_SCORE = 40


@safe_detect
def detect(request):
    """
    Inspect request GET/POST/JSON/cookies/headers for XSS signatures.
    Returns the standard detection dict, or None if none were found.
    """
    values = get_all_text_values(request)

    matched = {}
    for value in values:
        for rule in match_all(value, ATTACK_TYPE):
            matched[rule.rule_id] = rule

    if not matched:
        return None

    best = max(matched.values(), key=lambda r: r.score)
    score = best.score
    reason = best.description

    # Ignore isolated low-confidence detections.
    if score < MIN_XSS_SCORE and len(matched) < MULTI_SIGNAL_THRESHOLD:
        logger.debug(
            "Ignoring weak XSS indicator on %s (score=%d, rules=%s)",
            request.path,
            score,
            sorted(matched),
        )
        return None

    if len(matched) >= MULTI_SIGNAL_THRESHOLD:
        score = min(100, score + MULTI_SIGNAL_BONUS)
        reason = (
            f"{reason}; corroborated by {len(matched)} XSS indicators total"
        )
        logger.info(
            "multiple XSS indicators co-occurred on %s: %s",
            request.path,
            sorted(matched),
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