"""
test_encoded_payloads.py

Section 18 (mandatory): proves that the standalone core still detects
malicious input after it has gone through the real normalization
pipeline (base_detector.normalize(): bounded URL-decoding + HTML-entity
unescaping), not a fake test that manually decodes the payload before
handing it to the WAF. Every request below is constructed with the RAW
encoded string exactly as an attacker would send it; only WAFEngine
sees it, and only WAFEngine's own normalization decides whether it's
caught.
"""

import unittest

from waf_core import WAFEngine, WAFRequest
from waf_core.constants import BLOCK


class TestEncodedPayloads(unittest.TestCase):
    def setUp(self):
        self.engine = WAFEngine()

    def test_url_encoded_xss_in_query_param(self):
        decision = self.engine.inspect(
            WAFRequest(
                path="/search",
                query_params={"q": "%3Cscript%3Ealert(1)%3C/script%3E"},
            )
        )
        self.assertEqual(decision.action, BLOCK)
        self.assertIn("XSS-001", decision.rules)

    def test_double_url_encoded_xss(self):
        decision = self.engine.inspect(
            WAFRequest(
                path="/search",
                query_params={"q": "%253Cscript%253Ealert(1)%253C/script%253E"},
            )
        )
        self.assertEqual(decision.action, BLOCK)

    def test_html_entity_encoded_xss(self):
        decision = self.engine.inspect(
            WAFRequest(
                path="/comment",
                method="POST",
                form_data={"body": "&lt;script&gt;alert(1)&lt;/script&gt;"},
            )
        )
        self.assertEqual(decision.action, BLOCK)

    def test_url_encoded_path_traversal(self):
        decision = self.engine.inspect(
            WAFRequest(
                path="/download",
                query_params={"file": "..%2f..%2f..%2fetc%2fpasswd"},
            )
        )
        self.assertEqual(decision.action, BLOCK)
        self.assertIn("PATH-004", decision.rules)

    def test_url_encoded_sqli(self):
        decision = self.engine.inspect(
            WAFRequest(
                path="/search",
                query_params={
                    "id": "1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--"
                },
            )
        )
        self.assertEqual(decision.action, BLOCK)
        self.assertIn("SQLI-001", decision.rules)


if __name__ == "__main__":
    unittest.main()
