"""
cookie_validator.py

Validates cookies for two distinct classes of problem:

  1. Structural anomalies specific to cookies: oversized values,
     suspicious/privileged-looking names, null bytes, and invalid
     control characters. These have no equivalent in the shared
     registry because they're about the cookie's *shape*, not a
     signature within its content.

  2. Known attack payloads riding inside a cookie value — reuses the
     shared registry across sql_injection, xss, command_injection,
     and path_traversal, since a cookie is just another injection
     point for the same signatures those detectors already know.
     When this fires, attack_type reflects what was actually found
     (e.g. "xss"), while detector_name correctly credits
     cookie_validator as the surface that caught it.
"""

import re

from waf.detectors.base_detector import build_result, get_cookies, match_all, report, safe_detect
from waf.detectors.patterns import severity_for_score
from waf.logging.logger import get_logger

logger = get_logger(__name__)

DETECTOR_NAME = "cookie_validator"

MAX_COOKIE_LENGTH = 4096  # RFC 6265 practical per-cookie limit
SUSPICIOUS_NAME_RE = re.compile(
    r"admin|debug|eval|role|is_?auth|bypass|superuser|impersonate", re.IGNORECASE
)
INVALID_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")  # control chars minus \t\n\r

# Attack types whose signatures are worth checking for inside a
# cookie value, in priority order.
_PAYLOAD_ATTACK_TYPES = ("sql_injection", "xss", "command_injection", "path_traversal")


@safe_detect
def detect(request):
    """
    Inspect all cookies on the request. Returns the standard detection
    dict for the first structural or payload issue found, or None if
    the cookies look clean.
    """
    cookies = get_cookies(request)
    if not cookies:
        return None

    for name, value in cookies.items():
        finding = _check_structure(name, value) or _check_payload(name, value)
        if finding:
            report(request, finding, payload={"cookie_name": name, "cookie_value": value[:200]})
            return finding

    return None


def _check_structure(name: str, value: str):
    if "\x00" in value or "\x00" in name:
        return build_result(
            attack="other", score=70, severity=severity_for_score(70),
            reason=f"null byte in cookie '{name}'", rule="COOKIE-001", detector=DETECTOR_NAME,
        )
    if len(value) > MAX_COOKIE_LENGTH:
        return build_result(
            attack="other", score=40, severity=severity_for_score(40),
            reason=f"cookie '{name}' exceeds {MAX_COOKIE_LENGTH} bytes", rule="COOKIE-002",
            detector=DETECTOR_NAME,
        )
    if SUSPICIOUS_NAME_RE.search(name):
        return build_result(
            attack="other", score=35, severity=severity_for_score(35),
            reason=f"suspicious cookie name '{name}'", rule="COOKIE-003", detector=DETECTOR_NAME,
        )
    if INVALID_CHARS_RE.search(value):
        return build_result(
            attack="other", score=45, severity=severity_for_score(45),
            reason=f"invalid control characters in cookie '{name}'", rule="COOKIE-004",
            detector=DETECTOR_NAME,
        )
    return None


def _check_payload(name: str, value: str):
    for attack_type in _PAYLOAD_ATTACK_TYPES:
        hits = match_all(value, attack_type)
        if hits:
            best = max(hits, key=lambda r: r.score)
            logger.info("payload signature found inside cookie '%s': %s", name, best.rule_id)
            return build_result(
                attack=attack_type,
                score=best.score,
                severity=best.severity,
                reason=f"{best.description} found in cookie '{name}'",
                rule=best.rule_id,
                detector=DETECTOR_NAME,
            )
    return None
