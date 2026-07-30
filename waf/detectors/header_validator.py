"""
header_validator.py

Validates the request headers that are most commonly abused: Host,
Referer, Origin, X-Forwarded-For, Forwarded, Content-Type,
Content-Length, Accept, User-Agent.

Checks for:
  * header injection / CRLF splitting (a raw \\r or \\n inside a
    header value — Django's WSGI layer normally strips these, but a
    misconfigured upstream proxy can let them through)
  * oversized headers (a cheap DoS / buffer-abuse vector)
  * duplicate/suspicious X-Forwarded-For chains (many hops is a
    common proxy-spoofing indicator)
  * malformed Content-Length (non-numeric)
  * known attack payloads riding inside a header value, reusing the
    shared registry the same way cookie_validator does
"""

from waf.detectors.base_detector import build_result, get_headers, match_all, report, safe_detect
from waf.detectors.patterns import severity_for_score
from waf.logging.logger import get_logger

logger = get_logger(__name__)

DETECTOR_NAME = "header_validator"

MAX_HEADER_LENGTH = 8192
MAX_XFF_HOPS = 10
_PAYLOAD_ATTACK_TYPES = ("sql_injection", "xss", "command_injection", "path_traversal")

_INSPECTED_HEADERS = (
    "Host",
    "Referer",
    "Origin",
    "X-Forwarded-For",
    "Forwarded",
    "Content-Type",
    "Content-Length",
    "Accept",
    "User-Agent",
)


@safe_detect
def detect(request):
    """
    Inspect the request's headers. Returns the standard detection
    dict for the first issue found, or None if headers look clean.
    """
    headers = get_headers(request)
    if not headers:
        return None

    for name in _INSPECTED_HEADERS:
        value = headers.get(name)
        if value is None:
            continue
        finding = (
            _check_crlf(name, value)
            or _check_size(name, value)
            or _check_content_length(name, value)
            or _check_forwarded_chain(name, value)
            or _check_payload(name, value)
        )
        if finding:
            report(request, finding, payload={"header": name, "value": value[:200]})
            return finding

    return None


def _check_crlf(name: str, value: str):
    if "\r" in value or "\n" in value:
        return build_result(
            attack="other", score=75, severity=severity_for_score(75),
            reason=f"CRLF sequence in header '{name}' (header injection attempt)",
            rule="HDR-001", detector=DETECTOR_NAME,
        )
    return None


def _check_size(name: str, value: str):
    if len(value) > MAX_HEADER_LENGTH:
        return build_result(
            attack="other", score=35, severity=severity_for_score(35),
            reason=f"header '{name}' exceeds {MAX_HEADER_LENGTH} bytes",
            rule="HDR-002", detector=DETECTOR_NAME,
        )
    return None


def _check_content_length(name: str, value: str):
    if name.lower() == "content-length" and value and not value.isdigit():
        return build_result(
            attack="other", score=30, severity=severity_for_score(30),
            reason="malformed Content-Length header (non-numeric)",
            rule="HDR-003", detector=DETECTOR_NAME,
        )
    return None


def _check_forwarded_chain(name: str, value: str):
    if name.lower() in ("x-forwarded-for", "forwarded"):
        hops = [h for h in value.split(",") if h.strip()]
        if len(hops) > MAX_XFF_HOPS:
            return build_result(
                attack="other", score=30, severity=severity_for_score(30),
                reason=f"'{name}' has {len(hops)} hops (possible proxy spoofing)",
                rule="HDR-004", detector=DETECTOR_NAME,
            )
    return None


def _check_payload(name: str, value: str):
    header = name.lower()

    # Browser-generated protocol headers frequently contain punctuation,
    # MIME types and boundaries that resemble attack signatures.
    # Skip payload inspection for Accept entirely.
    if header == "accept":
        return None

    attack_types = _PAYLOAD_ATTACK_TYPES

    # User-Agent and Content-Type should not be checked for command
    # injection because normal browser values contain semicolons.
    if header in ("user-agent", "content-type"):
        attack_types = (
            "sql_injection",
            "xss",
            "path_traversal",
        )

    for attack_type in attack_types:
        hits = match_all(value, attack_type)
        if not hits:
            continue

        best = max(hits, key=lambda r: r.score)

        # Ignore isolated weak matches.
        if best.score < 40:
            continue

        logger.info(
            "payload signature found inside header '%s': %s",
            name,
            best.rule_id,
        )

        return build_result(
            attack=attack_type,
            score=best.score,
            severity=best.severity,
            reason=f"{best.description} found in header '{name}'",
            rule=best.rule_id,
            detector=DETECTOR_NAME,
        )

    return None