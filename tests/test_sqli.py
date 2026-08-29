"""
test_sqli.py

SQL injection detection using representative payloads drawn from the
existing SQLi ruleset in waf_core/patterns.py (Section 17): OR-based
tautology, UNION-based injection, and destructive DDL, across
multiple request locations.
"""

import unittest

from waf_core import WAFEngine, WAFRequest
from waf_core.constants import BLOCK


class TestSQLInjection(unittest.TestCase):
    def setUp(self):
        self.engine = WAFEngine()

    def test_or_tautology_in_login_form(self):
        decision = self.engine.inspect(
            WAFRequest(
                path="/login",
                method="POST",
                form_data={"username": "admin' OR '1'='1", "password": "x"},
            )
        )
        self.assertEqual(decision.action, BLOCK)
        self.assertIn("SQLI-007", decision.rules)

    def test_union_select_in_query_param(self):
        decision = self.engine.inspect(
            WAFRequest(
                path="/search",
                query_params={"id": "1 UNION SELECT username, password FROM users"},
            )
        )
        self.assertEqual(decision.action, BLOCK)
        self.assertIn("SQLI-001", decision.rules)

    def test_drop_table_in_query_param(self):
        decision = self.engine.inspect(
            WAFRequest(path="/search", query_params={"q": "'; DROP TABLE users;--"})
        )
        self.assertEqual(decision.action, BLOCK)
        self.assertIn("SQLI-003", decision.rules)

    def test_sqli_in_cookie(self):
        decision = self.engine.inspect(
            WAFRequest(path="/", cookies={"id": "1' OR '1'='1"})
        )
        self.assertEqual(decision.action, BLOCK)

    def test_sqli_in_header(self):
        decision = self.engine.inspect(
            WAFRequest(path="/", headers={"X-Forwarded-For": "1' UNION SELECT 1--"})
        )
        self.assertEqual(decision.action, BLOCK)


if __name__ == "__main__":
    unittest.main()
