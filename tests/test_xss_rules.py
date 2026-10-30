"""
test_xss_rules.py

Rule-by-rule XSS coverage (waf_core/patterns.py, XSS-*).

xss.detect() ignores a lone indicator scoring < 40 unless 2+ different
XSS rules match together (then +10). A request is blocked at a summed
score >= 70 or on any critical (>= 80) detection.
"""

import unittest

from waf_core.constants import ALLOW, BLOCK
from waf_core.detectors import xss

from tests.helpers import add_cases, inspect, make_request, matched_rules

# (case_id, payload, expected rule id present in decision.rules)
BLOCKED = [
    ("script_tag_uppercase", "<SCRIPT SRC=//evil.example/x.js></SCRIPT>", "XSS-001"),
    ("script_tag_with_space", "<script >run()</script>", "XSS-001"),
    ("javascript_uri", "javascript:void(0)", "XSS-002"),
    ("javascript_uri_spaced", "JaVaScRiPt  :go()", "XSS-002"),
    ("onload_handler", "<body onload=run()>", "XSS-003"),
    ("onclick_handler", "<div onclick=steal()>", "XSS-003"),
    ("onmouseover_handler", "<a onmouseover=track()>x</a>", "XSS-003"),
    ("document_cookie", "document.cookie", "XSS-006"),
    ("svg_onload", "<svg onload=alert(1)>", "XSS-003"),
    ("iframe_srcdoc", "<iframe srcdoc='<b>x</b>'>", "XSS-012"),
    ("triple_url_encoded_script", "%25253Cscript%25253E", "XSS-001"),
    ("onerror_space_before_equals", "<img src=x onerror =run()>", "XSS-003"),
    ("entity_encoded_handler", "&lt;img src=x onerror=run()&gt;", "XSS-003"),
]

# Lone indicators that are detected but stay under the threshold.
# (case_id, payload, expected rule, expected score)
BELOW_THRESHOLD = [
    ("iframe_alone", "<iframe src=//evil.example>", "XSS-004", 60),
    ("svg_alone", "<svg/>", "XSS-005", 40),
    ("alert_alone", "alert(1)", "XSS-007", 50),
    ("eval_alone", "eval(code)", "XSS-008", 60),
    ("inner_html_alone", "el.innerHTML = x", "XSS-011", 40),
]

# Weak indicators (< 40) that must be ignored when they appear alone.
IGNORED_WHEN_ALONE = [
    ("fetch_call", "fetch(url)"),
    ("location_href", "location.href"),
]


def _blocked(self, payload, rule):
    decision = inspect(query_params={"q": payload})
    self.assertEqual(decision.action, BLOCK)
    self.assertIn(rule, matched_rules(decision))


def _below_threshold(self, payload, rule, score):
    result = xss.detect(make_request(query_params={"q": payload}))
    self.assertIsNotNone(result)
    self.assertEqual(result["rule"], rule)
    self.assertEqual(result["score"], score)
    self.assertEqual(inspect(query_params={"q": payload}).action, ALLOW)


def _ignored(self, payload):
    self.assertIsNone(xss.detect(make_request(query_params={"q": payload})))


class TestXSSBlocked(unittest.TestCase):
    pass


class TestXSSBelowThreshold(unittest.TestCase):
    pass


class TestXSSWeakIndicatorsIgnored(unittest.TestCase):
    pass


add_cases(TestXSSBlocked, "test_blocks", BLOCKED, _blocked)
add_cases(TestXSSBelowThreshold, "test_single_signal_scores_below_block", BELOW_THRESHOLD, _below_threshold)
add_cases(TestXSSWeakIndicatorsIgnored, "test_ignored", IGNORED_WHEN_ALONE, _ignored)


class TestXSSCorroboration(unittest.TestCase):
    def test_two_indicators_add_bonus(self):
        # XSS-005 (svg, 40) + XSS-007 (alert, 50) -> 50 + 10
        result = xss.detect(make_request(query_params={"q": "<svg/> alert(1)"}))
        self.assertEqual(result["score"], 60)
        self.assertIn("corroborated by 2", result["reason"])

    def test_corroboration_can_reach_block_threshold(self):
        # iframe (60) + srcdoc-free second signal eval (60) -> 60 + 10 = 70
        decision = inspect(query_params={"q": "<iframe src=x> eval(y)"})
        self.assertEqual(decision.action, BLOCK)
        self.assertEqual(decision.risk_score, 70)

    def test_score_is_capped_at_100(self):
        decision = inspect(
            query_params={"q": "<script>document.cookie</script><iframe srcdoc=x onload=y()>"}
        )
        self.assertEqual(decision.action, BLOCK)
        self.assertLessEqual(decision.risk_score, 100)


class TestXSSRequestLocations(unittest.TestCase):
    PAYLOAD = "<script>alert(1)</script>"

    def test_nested_json_array(self):
        d = inspect(
            method="POST",
            headers={"Content-Type": "application/json"},
            body='{"a": [{"b": "%s"}]}' % self.PAYLOAD,
        )
        self.assertEqual(d.action, BLOCK)
        self.assertIn("XSS-001", d.rules)

    def test_custom_header_is_still_scanned(self):
        # X-Custom is not in header_validator's inspected list, but
        # xss_detector scans every header value.
        d = inspect(headers={"X-Custom": self.PAYLOAD})
        self.assertEqual(d.action, BLOCK)
        self.assertIn("xss_detector", d.detectors)

    def test_origin_header(self):
        d = inspect(headers={"Origin": self.PAYLOAD})
        self.assertEqual(d.action, BLOCK)

    def test_payload_split_across_two_fields_is_not_reassembled(self):
        d = inspect(query_params={"a": "<scr", "b": "ipt>alert(1)</scr" + "ipt>"})
        # Only 'alert(' (XSS-007, 50) is visible in any single value.
        self.assertEqual(d.action, ALLOW)


class TestXSSKnownBypasses(unittest.TestCase):
    """Currently-undetected payloads, kept as documentation. Remove the
    decorator when the pattern set is extended."""

    @unittest.expectedFailure
    def test_less_common_event_handler(self):
        d = inspect(query_params={"q": "<input autofocus onfocus=run()>"})
        self.assertEqual(d.action, BLOCK)


if __name__ == "__main__":
    unittest.main()
