"""
Unicode normalization - handles \\uXXXX JS-style escapes, NFKC
normalization (which collapses many homoglyph/full-width evasion
tricks), and stripping of zero-width characters sometimes used to split
up signature strings (e.g. "sc<ZWSP>ript").
"""
import re
import unicodedata

_JS_UNICODE_ESCAPE_RE = re.compile(r'\\u([0-9a-fA-F]{4})')
_ZERO_WIDTH_CHARS = (
    '\u200b'  # zero width space
    '\u200c'  # zero width non-joiner
    '\u200d'  # zero width joiner
    '\ufeff'  # BOM / zero width no-break space
)
_ZERO_WIDTH_RE = re.compile('[' + _ZERO_WIDTH_CHARS + ']')


def decode_js_unicode_escapes(value: str) -> str:
    if not isinstance(value, str):
        return value

    def _replace(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    return _JS_UNICODE_ESCAPE_RE.sub(_replace, value)


def strip_zero_width(value: str) -> str:
    if not isinstance(value, str):
        return value
    return _ZERO_WIDTH_RE.sub('', value)


def normalize_form(value: str) -> str:
    """NFKC folds full-width/compatibility characters to their ASCII
    equivalents, e.g. full-width '<' (U+FF1C) -> '<' - a common WAF
    evasion trick."""
    if not isinstance(value, str):
        return value
    return unicodedata.normalize('NFKC', value)


def unicode_normalize(value: str) -> str:
    """Runs all unicode-layer normalizations in sequence."""
    if not isinstance(value, str):
        return value
    value = decode_js_unicode_escapes(value)
    value = strip_zero_width(value)
    value = normalize_form(value)
    return value