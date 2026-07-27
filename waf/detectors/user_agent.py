"""
user_agent.py

Detects known scanning/exploitation tools and structurally suspicious
User-Agent headers. This is a coarser, cheaper signal than the
signature detectors — it doesn't need to inspect payload content, so
it's a good early/complementary check that fires even when a scanner
sends otherwise well-formed requests.

Detects:
  * known scanner/tool UA substrings (sqlmap, nikto, acunetix, burp,
    curl, python-requests, libwww, masscan, nmap, wget, fimap, havij,
    nessus, zgrab, Go-http-client)
  * empty User-Agent (real browsers always send one)
  * very short User-Agent (below what any real browser UA looks like)
  * "random"/low-entropy-looking UA strings — a crude heuristic, not
    a substitute for the substring list, kept deliberately simple and
    low-scoring since it's the most false-positive-prone check here
"""

import re

from waf.detectors.base_detector import build_result, report, safe_detect
from waf.detectors.patterns import severity_for_score
from waf.logging.logger import get_logger

logger = get_logger(__name__)

DETECTOR_NAME = "user_agent_detector"

MIN_REALISTIC_UA_LENGTH = 15

# Known scanning / exploitation / scripting tools. Each maps to a
# distinct rule id so the dashboard can show which tool was likely
# used, and to a score reflecting how exclusively offensive that tool
# is (sqlmap has no legitimate reason to hit this app; curl does, so
# it scores much lower and is really just a "not a browser" signal).
_KNOWN_TOOLS = {
    "sqlmap": ("UA-001", 90), "nikto": ("UA-002", 90), "acunetix": ("UA-003", 90),
    "burp": ("UA-004", 80), "havij": ("UA-005", 90), "nessus": ("UA-006", 85),
    "zgrab": ("UA-007", 75), "masscan": ("UA-008", 80), "nmap": ("UA-009", 80),
    "fimap": ("UA-010", 85), "libwww": ("UA-011", 60), "python-requests": ("UA-012", 40),
    "go-http-client": ("UA-013", 40), "curl": ("UA-014", 25), "wget": ("UA-015", 30),
}

_RANDOM_UA_RE = re.compile(r"^[a-z0-9]{20,}$", re.IGNORECASE)


@safe_detect
def detect(request):
    """
    Inspect the request's User-Agent header. Returns the standard
    detection dict, or None if it looks like an ordinary browser UA.
    """
    ua = request.META.get("HTTP_USER_AGENT", "")

    finding = (
        _check_known_tools(ua)
        or _check_empty(ua)
        or _check_too_short(ua)
        or _check_random_looking(ua)
    )
    if finding:
        report(request, finding, payload={"user_agent": ua})
        return finding
    return None


def _check_known_tools(ua: str):
    lowered = ua.lower()
    for tool, (rule_id, score) in _KNOWN_TOOLS.items():
        if tool in lowered:
            return build_result(
                attack="other", score=score, severity=severity_for_score(score),
                reason=f"User-Agent identifies known tool '{tool}'",
                rule=rule_id, detector=DETECTOR_NAME,
            )
    return None


def _check_empty(ua: str):
    if not ua.strip():
        return build_result(
            attack="other", score=35, severity=severity_for_score(35),
            reason="empty User-Agent header", rule="UA-016", detector=DETECTOR_NAME,
        )
    return None


def _check_too_short(ua: str):
    if 0 < len(ua) < MIN_REALISTIC_UA_LENGTH:
        return build_result(
            attack="other", score=25, severity=severity_for_score(25),
            reason=f"unrealistically short User-Agent ('{ua}')",
            rule="UA-017", detector=DETECTOR_NAME,
        )
    return None


def _check_random_looking(ua: str):
    """Crude heuristic: a long run of alphanumerics with no spaces,
    slashes, or parentheses doesn't look like any real browser/OS/
    engine UA string, which always contain that structure."""
    if _RANDOM_UA_RE.match(ua.strip()):
        return build_result(
            attack="other", score=20, severity=severity_for_score(20),
            reason="User-Agent has no browser-like structure (possibly randomized)",
            rule="UA-018", detector=DETECTOR_NAME,
        )
    return None
