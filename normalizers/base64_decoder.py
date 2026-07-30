"""
Base64 detection + decoding. Attackers sometimes base64-encode payloads
(e.g. in cookies, headers, or JSON fields) to slip past plaintext pattern
matching. This never raises - malformed/non-base64 input is returned
as-is with is_base64=False.
"""
import base64
import binascii
import re

# Loose heuristic: base64 alphabet, reasonable min length, valid padding
_B64_RE = re.compile(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
MIN_LEN = 8  # ignore tiny strings; too many false positives below this


def looks_like_base64(value: str) -> bool:
    if not isinstance(value, str) or len(value) < MIN_LEN:
        return False
    stripped = value.strip()
    if len(stripped) % 4 != 0:
        return False
    return bool(_B64_RE.match(stripped))


def try_decode_base64(value: str):
    """
    Returns (is_base64, decoded_text_or_None).
    Only returns success if the decoded bytes are valid UTF-8 text -
    binary blobs (images etc.) aren't useful for pattern matching and are
    left alone.
    """
    if not looks_like_base64(value):
        return False, None
    try:
        decoded_bytes = base64.b64decode(value, validate=True)
        decoded_text = decoded_bytes.decode("utf-8")
        return True, decoded_text
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return False, None