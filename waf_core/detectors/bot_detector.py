"""
bot_detector.py

Detects automated / headless-browser traffic, as distinct from the
manual-tool signatures user_agent.py already covers.

Detects:
  * headless browser / automation framework fingerprints in the
    User-Agent (selenium, phantomjs, playwright, puppeteer, headless)
  * automation-revealing headers some frameworks leave behind
    (e.g. a bare "webdriver" indicator)
  * rapid-request bursts from a single IP — heuristic only, as noted
    in the design brief. The original version used Django's cache
    framework as a lightweight per-IP counter; that's a Django
    dependency waf_core can't have (Section 3 of the extraction
    spec), so this uses waf_core.cache instead — a stdlib-only
    thread-safe TTL cache exposing the same get()/set() shape. Fails
    open (returns None) if the cache is unavailable for any reason,
    rather than crashing the request.
"""

import logging
import time

from waf_core.cache import cache
from waf_core.base_detector import build_result, report, safe_detect
from waf_core.patterns import severity_for_score

logger = logging.getLogger("waf_core." + __name__)

DETECTOR_NAME = "bot_detector"

_AUTOMATION_UA_MARKERS = ("headlesschrome", "phantomjs", "selenium", "playwright", "puppeteer")

RAPID_REQUEST_WINDOW_SECONDS = 10
RAPID_REQUEST_THRESHOLD = 30  # requests from one IP within the window
_CACHE_KEY_PREFIX = "waf:bot:reqcount:"


@safe_detect
def detect(request):
    """
    Inspect the request for automation/bot indicators. Returns the
    standard detection dict for the first issue found, or None.
    """
    finding = (
        _check_automation_ua(request)
        or _check_automation_headers(request)
        or _check_rapid_requests(request)
    )
    if finding:
        report(request, finding)
        return finding
    return None


def _check_automation_ua(request):
    ua = request.META.get("HTTP_USER_AGENT", "").lower()
    for marker in _AUTOMATION_UA_MARKERS:
        if marker in ua:
            return build_result(
                attack="other", score=55, severity=severity_for_score(55),
                reason=f"User-Agent reveals automation framework '{marker}'",
                rule="BOT-001", detector=DETECTOR_NAME,
            )
    return None


def _check_automation_headers(request):
    # Some WebDriver-based tools set this non-standard header directly.
    if request.META.get("HTTP_X_WEBDRIVER") or request.META.get("HTTP_WEBDRIVER"):
        return build_result(
            attack="other", score=60, severity=severity_for_score(60),
            reason="WebDriver automation header present",
            rule="BOT-002", detector=DETECTOR_NAME,
        )
    return None


def _check_rapid_requests(request):
    """Heuristic only: counts requests per IP in a fixed time window
    via the cache. Not a substitute for real rate limiting — just a
    soft signal that gets logged, never blocks, in this log-only
    pipeline.

    Uses a time-bucketed cache key (current time // window size)
    rather than refreshing a single key's TTL on every hit, so it
    actually measures "requests in the last N seconds" instead of
    climbing forever under sustained traffic.
    """
    ip = request.META.get("REMOTE_ADDR")
    if not ip:
        return None

    bucket = int(time.time() // RAPID_REQUEST_WINDOW_SECONDS)
    key = f"{_CACHE_KEY_PREFIX}{ip}:{bucket}"
    try:
        count = cache.get(key, 0) + 1
        # Window expires shortly after the bucket ends; no need to
        # keep refreshing it, since a new bucket/key is used each window.
        cache.set(key, count, timeout=RAPID_REQUEST_WINDOW_SECONDS * 2)
    except Exception:
        logger.warning("cache backend unavailable, skipping rapid-request heuristic")
        return None

    if count > RAPID_REQUEST_THRESHOLD:
        return build_result(
            attack="other", score=30, severity=severity_for_score(30),
            reason=(
                f"{count} requests from {ip} within "
                f"{RAPID_REQUEST_WINDOW_SECONDS}s (heuristic only)"
            ),
            rule="BOT-003", detector=DETECTOR_NAME,
        )
    return None
