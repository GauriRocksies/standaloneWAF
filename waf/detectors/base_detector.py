"""
base_detector.py

Shared plumbing for every detector in waf/detectors/. Nothing in here
is attack-specific — that lives in patterns.py and in each detector's
own file. This module owns:

    * pulling raw values out of a Django request (GET, POST, JSON body,
      cookies, headers, multipart files) in one consistent shape
    * normalizing values before matching (URL-decoding, HTML-unescaping)
      so encoded/obfuscated payloads don't slip past the registry
    * running a value against the shared pattern registry
    * building the standard detector return dict
    * safely calling Member 3's log_attack()

Naming convention: every detector exposes one function, detect(request),
returning either None (no attack) or a dict shaped like:

    {
        "attack": "sql_injection",
        "score": 80,
        "severity": "critical",
        "reason": "UNION-based injection",
        "rule": "SQLI-001",
        "detector": "sqli_detector",
    }

This module is deliberately log-only aware: report() always sends
blocked=False. Whether to block is a decision-engine/middleware
concern, not a detector concern.
"""

import html
import json
from typing import Any, Dict, List, Optional
from urllib.parse import unquote

from waf.detectors.patterns import REGISTRY, Rule
from waf.logging.attack_logger import log_attack
from waf.logging.logger import get_logger

logger = get_logger(__name__)

# Cap on decode passes. Real payloads rarely need more than 2-3 rounds
# of URL-decoding; an unbounded loop is itself a DoS vector against the
# detector under scanner-sweep volume.
_MAX_DECODE_PASSES = 3

_MAX_INSPECTED_LENGTH = 8192  # ignore absurdly long single values (perf)


# --------------------------------------------------------------------
# Normalization
# --------------------------------------------------------------------

def normalize(value: str) -> str:
    """
    Decode a value so obfuscated/encoded payloads match the same
    patterns as their plaintext equivalents.

    Applies repeated URL-decoding (bounded) followed by HTML-entity
    unescaping. The *raw* value is still matched separately by callers
    (see match_ruleset), so a payload that only becomes dangerous after
    decoding is still caught, and a raw double-encoded payload is still
    caught by the dedicated PATH-003 style rules that key off the
    encoding pattern itself.
    """
    if not value:
        return value
    text = value[:_MAX_INSPECTED_LENGTH]
    for _ in range(_MAX_DECODE_PASSES):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    return html.unescape(text)


# --------------------------------------------------------------------
# Request extraction
# --------------------------------------------------------------------

def get_query_params(request) -> Dict[str, str]:
    """Flatten GET params to a simple str->str dict."""
    try:
        return {k: v for k, v in request.GET.items()}
    except Exception:
        return {}


def get_post_data(request) -> Dict[str, str]:
    """Flatten POST params (form-encoded or multipart) to str->str."""
    try:
        return {k: v for k, v in request.POST.items()}
    except Exception:
        return {}


def get_json_body(request) -> Optional[Dict[str, Any]]:
    """
    Best-effort JSON body extraction. Returns None if the body isn't
    JSON or can't be parsed — never raises, since malformed bodies are
    exactly the kind of thing a fuzzer/scanner sends.
    """
    content_type = request.META.get("CONTENT_TYPE", "")
    if "application/json" not in content_type:
        return None
    try:
        raw = request.body.decode("utf-8", errors="replace")
        return json.loads(raw)
    except Exception:
        return None


def get_cookies(request) -> Dict[str, str]:
    try:
        return dict(request.COOKIES)
    except Exception:
        return {}


def get_headers(request) -> Dict[str, str]:
    try:
        return {k: v for k, v in request.headers.items()}
    except Exception:
        return {}


def get_files(request) -> List[str]:
    """Return uploaded file names only (content inspection is
    payload_validator.py's job, not the base extraction layer's)."""
    try:
        return list(request.FILES.keys())
    except Exception:
        return []


def _flatten_json(obj: Any, out: List[str]) -> None:
    """Recursively collect string leaf values from a parsed JSON body."""
    if isinstance(obj, dict):
        for v in obj.values():
            _flatten_json(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _flatten_json(v, out)
    elif isinstance(obj, str):
        out.append(obj)


def get_all_text_values(request) -> List[str]:
    """
    Every inspectable string value on the request, from every source,
    as a flat list. Detectors that scan "the whole request" (payload
    size checks, generic signature sweeps) use this instead of calling
    each extractor individually.
    """
    values: List[str] = []
    values.extend(get_query_params(request).values())
    values.extend(get_post_data(request).values())
    values.extend(get_cookies(request).values())
    values.extend(get_headers(request).values())

    json_body = get_json_body(request)
    if json_body is not None:
        _flatten_json(json_body, values)

    return [v for v in values if isinstance(v, str) and v]


# --------------------------------------------------------------------
# Ruleset matching
# --------------------------------------------------------------------

def match_ruleset(value: str, attack_type: str) -> Optional[Rule]:
    """
    Check a single value against the shared registry for one
    attack_type. Matches both the raw value and its normalized form,
    so encoded payloads are caught without duplicating patterns.

    Returns the highest-scoring Rule that matched, or None.
    """
    if not value:
        return None
    rules = REGISTRY.get(attack_type)
    if not rules:
        return None

    candidates = {value[:_MAX_INSPECTED_LENGTH]}
    normalized = normalize(value)
    if normalized != value:
        candidates.add(normalized)

    # REGISTRY entries are pre-sorted by descending score, so the
    # first match per candidate is already that candidate's strongest.
    best: Optional[Rule] = None
    for candidate in candidates:
        for rule in rules:
            if rule.pattern.search(candidate):
                if best is None or rule.score > best.score:
                    best = rule
                break
    return best


def scan_values(values: List[str], attack_type: str) -> Optional[Rule]:
    """Run match_ruleset across many values, returning the strongest hit."""
    best: Optional[Rule] = None
    for value in values:
        rule = match_ruleset(value, attack_type)
        if rule and (best is None or rule.score > best.score):
            best = rule
    return best


def match_all(value: str, attack_type: str) -> List[Rule]:
    """
    Like match_ruleset, but returns every distinct rule that matched
    (raw or normalized form) instead of only the strongest. Detectors
    use this to detect *corroborating* signals — e.g. a SQL comment
    marker alone is weak, but a comment marker plus an OR-tautology in
    the same request is a much stronger indicator than either alone.
    """
    if not value:
        return []
    rules = REGISTRY.get(attack_type)
    if not rules:
        return []

    candidates = {value[:_MAX_INSPECTED_LENGTH]}
    normalized = normalize(value)
    if normalized != value:
        candidates.add(normalized)

    seen_rule_ids = set()
    hits: List[Rule] = []
    for candidate in candidates:
        for rule in rules:
            if rule.rule_id in seen_rule_ids:
                continue
            if rule.pattern.search(candidate):
                hits.append(rule)
                seen_rule_ids.add(rule.rule_id)
    return hits


# --------------------------------------------------------------------
# Result building + logging
# --------------------------------------------------------------------

def build_result(
    attack: str,
    score: int,
    severity: str,
    reason: str,
    rule: str,
    detector: str,
) -> Dict[str, Any]:
    """Build the standard detector return dict. Keep this the single
    place that defines the shape, so every detector stays identical."""
    return {
        "attack": attack,
        "score": score,
        "severity": severity,
        "reason": reason,
        "rule": rule,
        "detector": detector,
    }


def result_from_rule(rule: Rule, detector: str) -> Dict[str, Any]:
    """Convenience: build a result dict directly from a matched Rule."""
    return build_result(
        attack=rule.attack_type,
        score=rule.score,
        severity=rule.severity,
        reason=rule.description,
        rule=rule.rule_id,
        detector=detector,
    )


def report(request, result: Dict[str, Any], payload: Any = None) -> None:
    """
    Send a detection result to Member 3's log_attack(). Always sends
    blocked=False — this pipeline is detect-and-log only; blocking is
    a decision-engine concern, not a detector concern.

    Never raises: log_attack() already guarantees this, but detectors
    call report() from inside request-handling code, so a defensive
    try/except stays here too.
    """
    try:
        log_attack({
            "ip_address": request.META.get("REMOTE_ADDR"),
            "url": request.path,
            "method": request.method,
            "attack_type": result["attack"],
            "payload": payload,
            "headers": get_headers(request),
            "severity": result["severity"],
            "risk_score": result["score"],
            "rule_triggered": result["rule"],
            "detector_name": result["detector"],
            "user_agent": request.META.get("HTTP_USER_AGENT", ""),
            "blocked": False,
        })
        logger.info(
            "detection reported: rule=%s detector=%s score=%d",
            result["rule"], result["detector"], result["score"],
        )
    except Exception:
        logger.exception("failed to report detection via log_attack")


def safe_detect(func):
    """
    Decorator for detect(request) implementations: guarantees a
    detector can never crash the request cycle. Catches everything,
    logs it, and returns None (treated as "no attack found") on
    failure — matching the "never crash" requirement under
    scanner-sweep-volume malformed input.
    """
    def wrapper(request, *args, **kwargs):
        try:
            return func(request, *args, **kwargs)
        except Exception:
            logger.exception("detector %s raised unexpectedly", func.__module__)
            return None
    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper
