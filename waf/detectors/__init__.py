"""
waf.detectors

Modular attack detection. Every submodule exposes exactly one
function, detect(request), returning either None (no attack found) or
a dict shaped like:

    {
        "attack": "sql_injection",
        "score": 80,
        "severity": "critical",
        "reason": "UNION-based injection",
        "rule": "SQLI-001",
        "detector": "sqli_detector",
    }

Each detect() call also reports independently via
waf.detectors.base_detector.report(), which calls Member 3's
log_attack() with blocked=False — detection here is log-only.
Whether/how to block based on these results is a middleware /
decision-engine concern, outside this package's scope.

DETECTOR_REGISTRY below is a convenience list for whoever wires up the
middleware: iterate it and call each entry against the request rather
than importing every submodule individually.
"""

from waf.detectors import (
    bot_detector,
    command_injection,
    cookie_validator,
    directory_traversal,
    header_validator,
    http_method_validator,
    path_validator,
    payload_validator,
    sql_injection,
    user_agent,
    xss,
)

DETECTOR_REGISTRY = [
    sql_injection.detect,
    xss.detect,
    directory_traversal.detect,
    command_injection.detect,
    cookie_validator.detect,
    header_validator.detect,
    payload_validator.detect,
    user_agent.detect,
    bot_detector.detect,
    http_method_validator.detect,
    path_validator.detect,
]

__all__ = ["DETECTOR_REGISTRY"]
