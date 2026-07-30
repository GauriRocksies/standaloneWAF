"""
command_injection.py

Detects OS command injection across query params, POST body, JSON
body, and headers. Signature matching comes from the shared registry
(attack_type="command_injection"): shell metacharacters, shell/binary
names (cmd.exe, powershell, bash, netcat), and reconnaissance commands
(whoami, cat, ls, ping).

Bare shell metacharacters (;, |, &, `) are extremely common in benign
input (email addresses, search queries, code snippets) so they score
low alone in patterns.py. This detector's job is recognizing when a
metacharacter appears *alongside* a suspicious command name — that
combination is what actually indicates an injection attempt.
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

DETECTOR_NAME = "command_detector"
ATTACK_TYPE = "command_injection"

MULTI_SIGNAL_THRESHOLD = 2
MULTI_SIGNAL_BONUS = 15

# Ignore isolated weak indicators (e.g. a single ';' in normal text)
MIN_COMMAND_SCORE = 50


@safe_detect
def detect(request):
    """
    Inspect request GET/POST/JSON/headers for command injection
    signatures. Returns the standard detection dict, or None if none
    were found.
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

    # Ignore isolated weak matches.
    if score < MIN_COMMAND_SCORE and len(matched) < MULTI_SIGNAL_THRESHOLD:
        logger.debug(
            "Ignoring weak command injection indicator on %s (score=%d, rules=%s)",
            request.path,
            score,
            sorted(matched),
        )
        return None

    if len(matched) >= MULTI_SIGNAL_THRESHOLD:
        score = min(100, score + MULTI_SIGNAL_BONUS)
        reason = (
            f"{reason}; metacharacter + command name both present"
        )
        logger.info(
            "multiple command injection indicators co-occurred on %s: %s",
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