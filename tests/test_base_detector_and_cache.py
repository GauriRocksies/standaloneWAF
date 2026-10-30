"""
test_base_detector_and_cache.py

Shared plumbing: normalize(), rule matching, request value extraction,
result builders, the safe_detect() guard, severity mapping, and the TTL
cache used by bot_detector.
"""

import time
import unittest

from waf_core import base_detector as bd
from waf_core.cache import SimpleCache
from waf_core.patterns import REGISTRY, severity_for_score

from tests.helpers import add_cases, make_request

# ---------------------------------------------------------------- normalize
# (case_id, input, expected)
NORMALIZE_CASES = [
    ("plain_text_unchanged", "hello world", "hello world"),
    ("empty_string", "", ""),
    ("single_url_encoding", "%3Cb%3E", "<b>"),
    ("double_url_encoding", "%253Cb%253E", "<b>"),
    ("triple_url_encoding", "%25253Cb%25253E", "<b>"),
    ("html_entities", "&lt;b&gt;&amp;", "<b>&"),
    ("numeric_html_entity", "&#60;b&#62;", "<b>"),
    ("url_then_html_entity", "%26lt%3B", "<"),
    ("percent_sign_alone_is_kept", "100% sure", "100% sure"),
]


def _normalize(self, raw, expected):
    self.assertEqual(bd.normalize(raw), expected)


class TestNormalize(unittest.TestCase):
    def test_decoding_is_bounded_to_three_passes(self):
        # %25252541 is "A" encoded four times; three passes leave one layer.
        self.assertEqual(bd.normalize("%25252541"), "%41")

    def test_long_values_are_truncated(self):
        self.assertEqual(len(bd.normalize("a" * 10_000)), 8192)


add_cases(TestNormalize, "test", NORMALIZE_CASES, _normalize)

# ---------------------------------------------------------------- severity
SEVERITY_CASES = [
    ("zero", 0, "low"),
    ("29", 29, "low"),
    ("30", 30, "medium"),
    ("59", 59, "medium"),
    ("60", 60, "high"),
    ("79", 79, "high"),
    ("80", 80, "critical"),
    ("100", 100, "critical"),
]


def _severity(self, score, expected):
    self.assertEqual(severity_for_score(score), expected)


class TestSeverityBoundaries(unittest.TestCase):
    pass


add_cases(TestSeverityBoundaries, "test", SEVERITY_CASES, _severity)


# ----------------------------------------------------------------- matching
class TestRuleMatching(unittest.TestCase):
    def test_empty_value_matches_nothing(self):
        self.assertIsNone(bd.match_ruleset("", "sql_injection"))
        self.assertEqual(bd.match_all("", "sql_injection"), [])

    def test_unknown_attack_type_matches_nothing(self):
        self.assertIsNone(bd.match_ruleset("UNION SELECT", "no_such_type"))
        self.assertEqual(bd.match_all("UNION SELECT", "no_such_type"), [])

    def test_match_ruleset_returns_strongest_rule(self):
        rule = bd.match_ruleset("1 UNION SELECT 1; DROP TABLE t", "sql_injection")
        self.assertEqual(rule.rule_id, "SQLI-003")

    def test_match_all_returns_each_distinct_rule_once(self):
        hits = bd.match_all("UNION SELECT 1 -- DROP TABLE t DROP TABLE u", "sql_injection")
        ids = [r.rule_id for r in hits]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue({"SQLI-001", "SQLI-003", "SQLI-019"} <= set(ids))

    def test_encoded_value_matches_via_normalization(self):
        self.assertEqual(bd.match_ruleset("%3Cscript%3E", "xss").rule_id, "XSS-001")

    def test_scan_values_returns_strongest_across_values(self):
        rule = bd.scan_values(["harmless", "alert(1)", "<script>"], "xss")
        self.assertEqual(rule.rule_id, "XSS-001")

    def test_scan_values_with_no_hits(self):
        self.assertIsNone(bd.scan_values(["a", "b"], "xss"))

    def test_registry_is_sorted_by_descending_score(self):
        for attack_type, rules in REGISTRY.items():
            scores = [r.score for r in rules]
            self.assertEqual(scores, sorted(scores, reverse=True), attack_type)

    def test_rule_ids_are_unique_across_registry(self):
        ids = [r.rule_id for rules in REGISTRY.values() for r in rules]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_rule_score_is_within_0_to_100(self):
        for rules in REGISTRY.values():
            for r in rules:
                self.assertTrue(0 <= r.score <= 100, r.rule_id)


# --------------------------------------------------------------- extraction
class TestExtraction(unittest.TestCase):
    def test_json_body_requires_json_content_type(self):
        r = make_request(method="POST", body='{"a": 1}')
        self.assertIsNone(bd.get_json_body(r))

    def test_json_body_parsed_when_content_type_matches(self):
        r = make_request(method="POST", headers={"Content-Type": "application/json"}, body='{"a": 1}')
        self.assertEqual(bd.get_json_body(r), {"a": 1})

    def test_invalid_json_returns_none_instead_of_raising(self):
        r = make_request(method="POST", headers={"Content-Type": "application/json"}, body="{oops")
        self.assertIsNone(bd.get_json_body(r))

    def test_all_text_values_flattens_nested_json(self):
        r = make_request(
            method="POST",
            headers={"Content-Type": "application/json"},
            body='{"a": ["x", {"b": "y"}], "c": {"d": "z"}, "n": 5}',
        )
        values = bd.get_all_text_values(r)
        for expected in ("x", "y", "z"):
            self.assertIn(expected, values)
        self.assertNotIn(5, values)

    def test_all_text_values_covers_every_source(self):
        r = make_request(
            query_params={"q": "query-val"},
            form_data={"f": "form-val"},
            cookies={"c": "cookie-val"},
            headers={"X-H": "header-val"},
        )
        values = bd.get_all_text_values(r)
        for expected in ("query-val", "form-val", "cookie-val", "header-val"):
            self.assertIn(expected, values)

    def test_empty_values_are_dropped(self):
        r = make_request(query_params={"q": ""}, cookies={"c": ""})
        self.assertNotIn("", bd.get_all_text_values(r))

    def test_get_files_returns_field_names_only(self):
        r = make_request(files={"avatar": {"name": "a.png", "content_type": "image/png"}})
        self.assertEqual(bd.get_files(r), ["avatar"])

    def test_extractors_survive_an_object_without_attributes(self):
        broken = object()
        self.assertEqual(bd.get_query_params(broken), {})
        self.assertEqual(bd.get_post_data(broken), {})
        self.assertEqual(bd.get_cookies(broken), {})
        self.assertEqual(bd.get_headers(broken), {})
        self.assertEqual(bd.get_files(broken), [])


# ------------------------------------------------------------------ results
class TestResultBuilders(unittest.TestCase):
    def test_build_result_has_the_standard_shape(self):
        r = bd.build_result("xss", 90, "critical", "why", "XSS-001", "xss_detector")
        self.assertEqual(
            set(r), {"attack", "score", "severity", "reason", "rule", "detector"}
        )

    def test_result_from_rule_copies_rule_fields(self):
        rule = REGISTRY["xss"][0]
        r = bd.result_from_rule(rule, "xss_detector")
        self.assertEqual(
            (r["rule"], r["score"], r["severity"], r["reason"], r["attack"]),
            (rule.rule_id, rule.score, rule.severity, rule.description, rule.attack_type),
        )

    def test_report_attaches_payload(self):
        r = bd.build_result("xss", 90, "critical", "why", "XSS-001", "d")
        bd.report(make_request(), r, payload={"k": "v"})
        self.assertEqual(r["_payload"], {"k": "v"})

    def test_report_never_raises_on_a_malformed_result(self):
        bd.report(make_request(), {}, payload=None)  # no 'rule' key: must not raise


class TestSafeDetect(unittest.TestCase):
    def test_exceptions_become_none(self):
        @bd.safe_detect
        def boom(request):
            raise ValueError("bad input")

        self.assertIsNone(boom(make_request()))

    def test_return_value_passes_through(self):
        @bd.safe_detect
        def ok(request):
            return {"score": 1}

        self.assertEqual(ok(make_request()), {"score": 1})

    def test_name_and_doc_are_preserved(self):
        @bd.safe_detect
        def documented(request):
            """doc text"""

        self.assertEqual((documented.__name__, documented.__doc__), ("documented", "doc text"))




# -------------------------------------------------------------------- cache
class TestSimpleCache(unittest.TestCase):
    def test_missing_key_returns_default(self):
        c = SimpleCache()
        self.assertIsNone(c.get("nope"))
        self.assertEqual(c.get("nope", 7), 7)

    def test_set_then_get(self):
        c = SimpleCache()
        c.set("k", 5)
        self.assertEqual(c.get("k"), 5)

    def test_overwrite(self):
        c = SimpleCache()
        c.set("k", 1)
        c.set("k", 2)
        self.assertEqual(c.get("k"), 2)

    def test_entry_expires_after_timeout(self):
        c = SimpleCache()
        c.set("k", 1, timeout=0.02)
        self.assertEqual(c.get("k"), 1)
        time.sleep(0.05)
        self.assertIsNone(c.get("k"))

    def test_entry_without_timeout_does_not_expire(self):
        c = SimpleCache()
        c.set("k", 1)
        time.sleep(0.03)
        self.assertEqual(c.get("k"), 1)

    def test_instances_do_not_share_state(self):
        a, b = SimpleCache(), SimpleCache()
        a.set("k", 1)
        self.assertIsNone(b.get("k"))


if __name__ == "__main__":
    unittest.main()
