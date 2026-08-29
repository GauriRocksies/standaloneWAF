"""URL-decoding normalizer - repeated percent-decoding, capped to avoid a
decode-loop DoS on maliciously nested encoding (e.g. %2525253C...).
"""
from urllib.parse import unquote_plus

MAX_PASSES = 5  # slightly deeper than Member 2's cap (3), since this is
                 # our dedicated decoder and detectors call us upstream


def url_decode_once(value: str) -> str:
    if not isinstance(value, str):
        return value
    return unquote_plus(value)


def url_decode_repeated(value: str, max_passes: int = MAX_PASSES) -> str:
    """
    Keeps decoding until the value stops changing or max_passes is hit -
    catches double/triple URL-encoded payloads used to evade single-pass
    filters (e.g. %2527 -> %27 -> ').
    """
    if not isinstance(value, str):
        return value
    current = value
    for _ in range(max_passes):
        decoded = url_decode_once(current)
        if decoded == current:
            break
        current = decoded
    return current