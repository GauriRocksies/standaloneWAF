"""
payload_validator.py

Validates the overall request payload shape, independent of any
specific attack signature: GET/POST/JSON/multipart/form data/files.

Checks for:
  * payload size (oversized bodies — resource exhaustion vector)
  * unexpected binary / high non-printable-character ratio in a
    text field (a classic sign of a raw exploit blob or shellcode
    pasted into a form field)
  * null bytes anywhere in the body (used to truncate strings in
    vulnerable C-based parsers, or to bypass extension checks)
  * excessively deep JSON nesting (a small payload can still exhaust
    the parser/stack — a handful of curly braces can nest thousands
    of levels)
  * dangerous MIME types on uploaded files (executables, scripts)
"""

import json
from typing import Any

from waf.detectors.base_detector import build_result, get_json_body, report, safe_detect
from waf.detectors.patterns import severity_for_score
from waf.logging.logger import get_logger

logger = get_logger(__name__)

DETECTOR_NAME = "payload_validator"

MAX_BODY_BYTES = 2 * 1024 * 1024  # 2 MB
MAX_JSON_DEPTH = 20
NON_PRINTABLE_RATIO_THRESHOLD = 0.3
MIN_LENGTH_FOR_BINARY_CHECK = 20

DANGEROUS_MIME_TYPES = {
    "application/x-msdownload", "application/x-executable",
    "application/x-sh", "application/x-shellscript",
    "application/x-httpd-php", "application/java-archive",
    "application/x-dosexec",
}


@safe_detect
def detect(request):
    """
    Inspect the overall request payload for shape-based anomalies.
    Returns the standard detection dict for the first issue found, or
    None if the payload looks reasonable.
    """
    finding = (
        _check_body_size(request)
        or _check_null_bytes(request)
        or _check_binary_in_text(request)
        or _check_json_depth(request)
        or _check_file_mime_types(request)
    )
    if finding:
        report(request, finding)
        return finding
    return None


def _check_body_size(request):
    try:
        length = int(request.META.get("CONTENT_LENGTH") or 0)
    except (TypeError, ValueError):
        return None
    if length > MAX_BODY_BYTES:
        return build_result(
            attack="other", score=35, severity=severity_for_score(35),
            reason=f"request body ({length} bytes) exceeds {MAX_BODY_BYTES} byte limit",
            rule="PAYLOAD-001", detector=DETECTOR_NAME,
        )
    return None


def _check_null_bytes(request):
    try:
        body = request.body
    except Exception:
        return None
    if body and b"\x00" in body:
        return build_result(
            attack="other", score=60, severity=severity_for_score(60),
            reason="null byte found in request body",
            rule="PAYLOAD-002", detector=DETECTOR_NAME,
        )
    return None


def _check_binary_in_text(request):
    """Flag text-typed fields (form/JSON) with a suspiciously high
    ratio of non-printable characters — likely a raw binary/exploit
    blob pasted into a field that should hold plain text."""
    values = list(request.GET.values()) + list(request.POST.values())
    json_body = get_json_body(request)
    if isinstance(json_body, dict):
        values.extend(v for v in json_body.values() if isinstance(v, str))

    for value in values:
        if len(value) < MIN_LENGTH_FOR_BINARY_CHECK:
            continue
        non_printable = sum(1 for ch in value if ord(ch) < 9 or 13 < ord(ch) < 32)
        if non_printable / len(value) > NON_PRINTABLE_RATIO_THRESHOLD:
            return build_result(
                attack="other", score=45, severity=severity_for_score(45),
                reason="high ratio of non-printable characters in a text field",
                rule="PAYLOAD-003", detector=DETECTOR_NAME,
            )
    return None


def _json_depth(obj: Any, current: int = 0) -> int:
    if current > MAX_JSON_DEPTH:
        return current  # bail early, we already know it's too deep
    if isinstance(obj, dict) and obj:
        return max(_json_depth(v, current + 1) for v in obj.values())
    if isinstance(obj, list) and obj:
        return max(_json_depth(v, current + 1) for v in obj)
    return current


def _check_json_depth(request):
    content_type = request.META.get("CONTENT_TYPE", "")
    if "application/json" not in content_type:
        return None
    try:
        raw = request.body.decode("utf-8", errors="replace")
        parsed = json.loads(raw)
    except Exception:
        return None
    depth = _json_depth(parsed)
    if depth > MAX_JSON_DEPTH:
        return build_result(
            attack="other", score=50, severity=severity_for_score(50),
            reason=f"JSON body nested {depth} levels deep (limit {MAX_JSON_DEPTH})",
            rule="PAYLOAD-004", detector=DETECTOR_NAME,
        )
    return None


def _check_file_mime_types(request):
    try:
        files = request.FILES
    except Exception:
        return None
    for f in files.values():
        content_type = (getattr(f, "content_type", "") or "").lower()
        if content_type in DANGEROUS_MIME_TYPES:
            return build_result(
                attack="file_upload", score=75, severity=severity_for_score(75),
                reason=f"uploaded file '{f.name}' has dangerous MIME type '{content_type}'",
                rule="PAYLOAD-005", detector=DETECTOR_NAME,
            )
    return None
