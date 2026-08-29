"""
Orchestrates all decoding layers into one normalize() call, mirroring
(and extending) Member 2's base_detector.normalize(). This is the
single entry point other modules should use.

Order matters: unicode normalization first (so full-width/escaped chars
become plain ASCII before we try to interpret them), then URL-decoding,
then a base64 check as a final pass (base64 payloads are usually a
self-contained blob, not nested inside URL-encoding).
"""
import html

from normalizers.url_decoder import url_decode_repeated
from normalizers.unicode_decoder import unicode_normalize
from normalizers.base64_decoder import try_decode_base64


def normalize(value: str) -> str:
    """
    Best-effort full normalization pipeline for a single string value.
    Never raises - falls back to the original value on any failure.
    """
    if not isinstance(value, str):
        return value

    try:
        result = unicode_normalize(value)
        result = url_decode_repeated(result)
        result = html.unescape(result)
        return result
    except Exception:
        return value


def normalize_with_base64(value: str):
    """
    Returns a list of candidate strings to run signature matching
    against: the normalized value, and - if the value looks like
    base64 - its decoded (and then normalized) contents too.
    Detectors should match against every candidate returned here.
    """
    candidates = [normalize(value)]
    is_b64, decoded = try_decode_base64(value)
    if is_b64 and decoded:
        candidates.append(normalize(decoded))
    return candidates