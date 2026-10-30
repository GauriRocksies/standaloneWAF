"""
test_sqli_rules.py

Rule-by-rule SQL injection coverage (waf_core/patterns.py, SQLI-*).

Scoring facts these tests rely on (see decision_engine.py / sql_injection.py):
  * a request is blocked when its summed score is >= 70, OR any single
    detection has severity "critical" (score >= 80);
  * sql_injection.detect() ignores a lone indicator scoring < 40 unless
    3+ different SQLi rules match together (then +10).
"""

import unittest

from waf_core.constants import ALLOW, BLOCK
from waf_core.detectors import sql_injection

from tests.helpers import add_cases, inspect, make_request

# (case_id, payload, expected rule id)
BLOCKED = [
    ("union_select", "1 UNION SELECT username,password FROM users", "SQLI-001"),
    ("union_select_mixed_case", "1 uNiOn   sElEcT NULL,NULL,NULL", "SQLI-001"),
    ("union_select_newline", "1 UNION\nSELECT 1,2", "SQLI-001"),
    ("drop_table", "x'; DROP TABLE accounts; --", "SQLI-003"),
    ("information_schema", "SELECT table_name FROM information_schema.tables", "SQLI-009"),
    ("load_file", "LOAD_FILE('/tmp/data')", "SQLI-012"),
    ("into_outfile", "SELECT 1 INTO OUTFILE '/tmp/o'", "SQLI-013"),
    ("xp_cmdshell", "EXEC xp_cmdshell 'dir'", "SQLI-014"),
    ("url_encoded_union", "1%20UNION%20SELECT%201%2C2", "SQLI-001"),
    ("double_encoded_union", "1%2520UNION%2520SELECT%25201", "SQLI-001"),
    ("html_entity_drop", "&#39;; DROP TABLE users", "SQLI-003"),
]

# Single indicators that score under the block threshold (70) on their
# own. These tests pin down the CURRENT scoring so a rule change is a
# conscious decision. (case_id, payload, expected rule, expected score)
BELOW_THRESHOLD = [
    ("or_tautology", "' OR 1=1 --", "SQLI-007", 45),
    ("and_tautology", "1 AND 1=1", "SQLI-008", 40),
    ("insert_into", "1; INSERT INTO t VALUES (1)", "SQLI-004", 50),
    ("update_set", "1; UPDATE users SET admin=1", "SQLI-005", 50),
    ("delete_from", "1; DELETE FROM users", "SQLI-006", 60),
    ("mysql_sleep", "1 AND SLEEP(5)", "SQLI-010", 65),
    # SQLI-020 (pg_sleep) matches too, but the unanchored MySQL sleep()
    # pattern (SQLI-010) matches "pg_sleep(5)" as well and is listed first.
    ("pg_sleep", "1; SELECT pg_sleep(5)", "SQLI-010", 65),
    ("exec_call", "1; EXEC('x')", "SQLI-015", 55),
]

# Weak indicators (< 40) that must be ignored when they appear alone.
IGNORED_WHEN_ALONE = [
    ("select_star", "select * from"),
    ("concat_call", "concat(a,b)"),
    ("char_literal", "char(65)"),
    ("hex_literal", "0x41424344"),
    ("comment_marker", "see section 4 -- details"),
]


def _blocked(self, payload, rule):
    decision = inspect(query_params={"q": payload})
    self.assertEqual(decision.action, BLOCK)
    self.assertIn(rule, decision.rules)


def _below_threshold(self, payload, rule, score):
    result = sql_injection.detect(make_request(query_params={"q": payload}))
    self.assertIsNotNone(result)
    self.assertEqual(result["rule"], rule)
    self.assertEqual(result["score"], score)
    self.assertEqual(inspect(query_params={"q": payload}).action, ALLOW)


def _ignored(self, payload):
    self.assertIsNone(sql_injection.detect(make_request(query_params={"q": payload})))


class TestSQLiBlocked(unittest.TestCase):
    pass


class TestSQLiBelowThreshold(unittest.TestCase):
    pass


class TestSQLiWeakIndicatorsIgnored(unittest.TestCase):
    pass


add_cases(TestSQLiBlocked, "test_blocks", BLOCKED, _blocked)
add_cases(TestSQLiBelowThreshold, "test_single_signal_scores_below_block", BELOW_THRESHOLD, _below_threshold)
add_cases(TestSQLiWeakIndicatorsIgnored, "test_ignored", IGNORED_WHEN_ALONE, _ignored)


class TestSQLiCorroboration(unittest.TestCase):
    def test_three_weak_signals_add_bonus(self):
        # SQLI-007 (45) + SQLI-019 (20) + SQLI-016 (20) -> 45 + 10 bonus
        result = sql_injection.detect(
            make_request(query_params={"q": "' OR 1=1 -- concat(a,b)"})
        )
        self.assertEqual(result["score"], 55)
        self.assertIn("corroborated by 3", result["reason"])

    def test_tautology_plus_scanner_user_agent_is_blocked(self):
        decision = inspect(
            query_params={"id": "' OR 1=1 --"},
            headers={"User-Agent": "sqlmap/1.7"},
        )
        self.assertEqual(decision.action, BLOCK)

    def test_sub_threshold_payloads_in_different_fields_corroborate(self):
        # SQLI-007 (45) and SQLI-006 (60) are each below the threshold
        # alone, but together with the comment marker (SQLI-019) they
        # make 3 distinct indicators: 60 + 10 bonus = 70 -> block.
        decision = inspect(
            query_params={"a": "' OR 1=1 --"}, form_data={"b": "1; DELETE FROM t"}
        )
        self.assertEqual(decision.action, BLOCK)
        self.assertEqual(decision.risk_score, 70)


class TestSQLiRequestLocations(unittest.TestCase):
    PAYLOAD = "1 UNION SELECT username,password FROM users"

    def test_form_field(self):
        d = inspect(method="POST", form_data={"user": self.PAYLOAD})
        self.assertEqual(d.action, BLOCK)

    def test_nested_json_value(self):
        d = inspect(
            method="POST",
            headers={"Content-Type": "application/json"},
            body='{"filter": {"ids": [{"v": "%s"}]}}' % self.PAYLOAD,
        )
        self.assertEqual(d.action, BLOCK)
        self.assertIn("SQLI-001", d.rules)

    def test_upload_field_name(self):
        # get_files() returns the multipart FIELD names, which are inspected.
        d = inspect(
            method="POST",
            files={"a' UNION SELECT 1": {"name": "x.png", "content_type": "image/png"}},
        )
        self.assertEqual(d.action, BLOCK)

    def test_payload_in_second_of_many_params(self):
        d = inspect(query_params={"page": "2", "sort": "name", "q": self.PAYLOAD})
        self.assertEqual(d.action, BLOCK)


class TestSQLiKnownBypasses(unittest.TestCase):
    """Payloads that SHOULD be caught but currently are not. They are
    marked expectedFailure so they stay in the suite as documentation;
    when a pattern is fixed, the test starts 'unexpectedly passing' and
    the decorator should be removed."""

    @unittest.expectedFailure
    def test_inline_comment_between_union_and_select(self):
        self.assertEqual(
            inspect(query_params={"id": "1 UNION/**/SELECT/**/1,2"}).action, BLOCK
        )

    @unittest.expectedFailure
    def test_sqli_in_uploaded_filename(self):
        # Only upload field names are inspected, not the filename itself.
        d = inspect(
            method="POST",
            files={"f": {"name": "a' UNION SELECT 1.png", "content_type": "image/png"}},
        )
        self.assertEqual(d.action, BLOCK)


if __name__ == "__main__":
    unittest.main()
