"""
helpers.py

Shared utilities for the data-driven WAF tests.

Why this file exists
--------------------
1. ``add_cases`` turns a table of cases into one real test method per
   row, so the cases show up individually in both
   ``python -m unittest`` and ``pytest`` (a failing row is named in the
   report instead of hiding inside a loop).

2. ``make_request`` builds a WAFRequest that looks like ordinary browser
   traffic by default, so a test measures the payload it is about and
   not side effects from unrelated detectors:

   * A real browser User-Agent is added unless the test sets one.
     (WAFRequest() with no UA triggers UA-016, "empty User-Agent",
     which adds 35 points to every request.)
   * Every request gets its own REMOTE_ADDR. bot_detector counts
     requests per IP in a process-wide cache and adds BOT-003 (30
     points) after 30 requests in 10 seconds. Without a unique IP, the
     size of the test suite itself would eventually change verdicts.
"""

import itertools

from waf_core import WAFEngine, WAFRequest

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

_ip_counter = itertools.count(1)


def unique_ip() -> str:
    n = next(_ip_counter)
    return f"198.51.{(n >> 8) & 255}.{n & 255}"


def make_request(**kwargs) -> WAFRequest:
    """WAFRequest with a browser UA and a unique client IP by default."""
    headers = dict(kwargs.pop("headers", None) or {})
    headers.setdefault("User-Agent", BROWSER_UA)
    meta = dict(kwargs.pop("meta", None) or {})
    meta.setdefault("REMOTE_ADDR", unique_ip())
    return WAFRequest(headers=headers, meta=meta, **kwargs)


def inspect(**kwargs):
    """Build a request (see make_request) and run it through a fresh engine."""
    return WAFEngine().inspect(make_request(**kwargs))


def matched_rules(decision) -> set:
    """Every rule id that matched, including rules hidden behind the
    'best rule' each detector reports (decision.rules only lists those)."""
    found = set(decision.rules)
    for detection in decision.detections:
        payload = detection.get("_payload")
        if isinstance(payload, dict):
            found.update(payload.get("matched_rules", ()))
    return found


def add_cases(cls, prefix, cases, check):
    """
    Attach one test method per case to ``cls``.

    ``cases`` is a list of tuples whose first item is an identifier
    (letters, digits, underscores) used in the test name; the remaining
    items are passed to ``check(self, *rest)``.
    """
    for case_id, *args in cases:
        def test(self, _args=tuple(args)):
            check(self, *_args)

        test.__name__ = f"{prefix}_{case_id}"
        test.__qualname__ = f"{cls.__name__}.{test.__name__}"
        setattr(cls, test.__name__, test)
