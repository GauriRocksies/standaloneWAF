"""
test_xss.py

XSS detection across every request location the existing engine
supports for it (Section 17): query params, POST/form data, headers,
cookies, and JSON body. Each is exercised through the real,
standalone WAFEngine/WAFRequest pipeline — not a fake test that
manually strips the payload before asserting.
"""

import unittest

from waf_core import WAFEngine, WAFRequest
from waf_core.constants import BLOCK


class TestXSS(unittest.TestCase):
    def setUp(self):
        self.engine = WAFEngine()

    def test_xss_in_query_params(self):
        decision = self.engine.inspect(
            WAFRequest(path="/search", query_params={"q": "<script>alert(1)</script>"})
        )
        self.assertEqual(decision.action, BLOCK)
        self.assertIn("XSS-001", decision.rules)

    def test_xss_in_post_form_data(self):
        decision = self.engine.inspect(
            WAFRequest(
                path="/comment",
                method="POST",
                form_data={"body": "<script>document.cookie</script>"},
            )
        )
        self.assertEqual(decision.action, BLOCK)

    def test_xss_in_cookie(self):
        decision = self.engine.inspect(
            WAFRequest(path="/", cookies={"session": "<script>alert(1)</script>"})
        )
        self.assertEqual(decision.action, BLOCK)
        self.assertTrue(any(d.get("detector") == "cookie_validator" for d in decision.detections))

    def test_xss_in_header(self):
        decision = self.engine.inspect(
            WAFRequest(
                path="/",
                headers={"Referer": "<script>document.cookie</script>http://evil.example"},
            )
        )
        self.assertEqual(decision.action, BLOCK)
        self.assertTrue(any(d.get("detector") == "header_validator" for d in decision.detections))

    def test_xss_in_json_body(self):
        decision = self.engine.inspect(
            WAFRequest(
                path="/api/comments",
                method="POST",
                headers={"Content-Type": "application/json"},
                body='{"comment": "<script>alert(1)</script>"}',
            )
        )
        self.assertEqual(decision.action, BLOCK)

    def test_event_handler_xss(self):
        decision = self.engine.inspect(
            WAFRequest(
                path="/comment",
                method="POST",
                form_data={"body": "<img src=x onerror=alert(1)>"},
            )
        )
        self.assertEqual(decision.action, BLOCK)
        self.assertIn("XSS-003", decision.rules)


if __name__ == "__main__":
    unittest.main()
