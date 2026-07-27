"""
path_validator.py

Validates the structural well-formedness of the request path — as
distinct from directory_traversal.py, which looks for traversal
*semantics* (../, /etc/passwd). This file looks for anomalies in the
path's *encoding and shape* that are themselves suspicious regardless
of what they decode to: they're the kind of thing a fuzzer produces
and a browser never does.

Checks for:
  * overly long URLs (path length far beyond any real route)
  * double URL-encoding (encoding a value twice is a classic filter-
    evasion technique, independent of what the decoded value is)
  * null bytes in the raw path
  * invalid UTF-8 sequences in the raw path
  * control characters in the raw path

Rule ids use a PATHV- prefix (not PATH-) to stay distinct from the
shared registry's path_traversal rule ids in patterns.py.
"""

import re

from waf.detectors.base_detector import build_result, report, safe_detect
from waf.detectors.patterns import severity_for_score
from waf.logging.logger import get_logger

logger = get_logger(__name__)

DETECTOR_NAME = "path_validator"

MAX_PATH_LENGTH = 2048
_DOUBLE_ENCODED_RE = re.compile(r"%25[0-9a-f]{2}", re.IGNORECASE)
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@safe_detect
def detect(request):
    """
    Validate the structural shape of the request path. Returns the
    standard detection dict for the first anomaly found, or None if
    the path looks well-formed.
    """
    path = request.path

    finding = (
        _check_length(path)
        or _check_double_encoding(path)
        or _check_null_byte(path)
        or _check_invalid_utf8(request)
        or _check_control_chars(path)
    )
    if finding:
        report(request, finding, payload={"path": path[:300]})
        return finding
    return None


def _check_length(path: str):
    if len(path) > MAX_PATH_LENGTH:
        return build_result(
            attack="other", score=35, severity=severity_for_score(35),
            reason=f"URL path length ({len(path)}) exceeds {MAX_PATH_LENGTH} chars",
            rule="PATHV-001", detector=DETECTOR_NAME,
        )
    return None


def _check_double_encoding(path: str):
    if _DOUBLE_ENCODED_RE.search(path):
        return build_result(
            attack="path_traversal", score=55, severity=severity_for_score(55),
            reason="double URL-encoded sequence in path (filter evasion attempt)",
            rule="PATHV-002", detector=DETECTOR_NAME,
        )
    return None


def _check_null_byte(path: str):
    if "%00" in path.lower() or "\x00" in path:
        return build_result(
            attack="path_traversal", score=65, severity=severity_for_score(65),
            reason="null byte in URL path",
            rule="PATHV-003", detector=DETECTOR_NAME,
        )
    return None


def _check_invalid_utf8(request):
    raw_path = request.META.get("PATH_INFO", "") or request.path
    try:
        raw_path.encode("utf-8").decode("utf-8", errors="strict")
    except UnicodeError:
        return build_result(
            attack="other", score=40, severity=severity_for_score(40),
            reason="invalid UTF-8 sequence in URL path",
            rule="PATHV-004", detector=DETECTOR_NAME,
        )
    return None


def _check_control_chars(path: str):
    if _CONTROL_CHAR_RE.search(path):
        return build_result(
            attack="other", score=45, severity=severity_for_score(45),
            reason="control characters in URL path",
            rule="PATHV-005", detector=DETECTOR_NAME,
        )
    return None
