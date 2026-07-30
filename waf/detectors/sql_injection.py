"""
sql_injection.py

Detects SQL injection across every request source: query params, POST
body, JSON body, cookies, headers, and multipart file names. Pattern
matching itself lives in patterns.py (shared registry, attack_type=
"sql_injection") — this file's own contribution is corroborating
weak signals into a stronger finding, which is genuinely detector-
specific logic and doesn't belong in the shared base layer.

Example: a bare SQL comment marker ("--") is common in legitimate
free-text input and scores low alone. But a comment marker *plus* an
OR-tautology *plus* a UNION SELECT in the same request is not a
coincidence — MULTI_SIGNAL_THRESHOLD bumps the score when that many
independent rules fire together.
"""

from waf.detectors.base_detector import (
    build_result,
    get_all_text_values,
    get_files,
    match_all,
    report,
    safe_detect,
)
from waf.detectors.patterns import severity_for_score
from waf.logging.logger import get_logger

logger = get_logger(__name__)

DETECTOR_NAME = "sqli_detector"
ATTACK_TYPE = "sql_injection"

# Three or more independent SQLi indicators in one request is a strong
# sign of a deliberate injection attempt rather than incidental use of
# a common word/character.
MULTI_SIGNAL_THRESHOLD = 3
MULTI_SIGNAL_BONUS = 10

# Ignore isolated low-confidence detections.
# Legitimate requests should not be flagged because of one weak pattern.
MIN_SQLI_SCORE = 40


@safe_detect
def detect(request):
    """
    Inspect request GET/POST/JSON/cookies/headers/file-names for SQL
    injection signatures. Returns the standard detection dict, or
    None if no SQLi indicators were found.
    """
    values = get_all_text_values(request) + get_files(request)

    matched = {}
    for value in values:
        for rule in match_all(value, ATTACK_TYPE):
            matched[rule.rule_id] = rule

    if not matched:
        return None

    best = max(matched.values(), key=lambda r: r.score)
    score = best.score
    reason = best.description

    # -------------------------------------------------------
    # Ignore isolated weak indicators to reduce false positives.
    # Keep stronger or corroborated detections.
    # -------------------------------------------------------
    if score < MIN_SQLI_SCORE and len(matched) < MULTI_SIGNAL_THRESHOLD:
        logger.debug(
            "Ignoring weak SQLi indicator on %s (score=%d, rules=%s)",
            request.path,
            score,
            sorted(matched),
        )
        return None

    if len(matched) >= MULTI_SIGNAL_THRESHOLD:
        score = min(100, score + MULTI_SIGNAL_BONUS)
        reason = f"{reason}; corroborated by {len(matched)} SQLi indicators total"
        logger.info(
            "multiple SQLi indicators co-occurred on %s: %s",
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