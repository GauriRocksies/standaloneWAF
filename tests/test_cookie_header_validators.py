"""
test_cookie_header_validators.py

Structural checks done by cookie_validator (COOKIE-*) and
header_validator (HDR-*): null bytes, size limits, CRLF injection,
forwarded-chain length, suspicious names, and payloads hidden in them.
"""

import unittest

from waf_core.constants import ALLOW, BLOCK
from waf_core.detectors import cookie_validator, header_validator

from tests.helpers import add_cases, inspect, make_request

# ----------------------------------------------------------------- cookies
# (case_id, cookies dict, expected rule, expected score)
COOKIE_FINDINGS = [
    ("null_byte_in_value", {"sid": "a\x00b"}, "COOKIE-001", 70),
    ("null_byte_in_name", {"s\x00id": "abc"}, "COOKIE-001", 70),
    ("oversized_value", {"sid": "a" * 4097}, "COOKIE-002", 40),
    ("suspicious_name_admin", {"admin": "1"}, "COOKIE-003", 35),
    ("suspicious_name_role", {"role": "superuser"}, "COOKIE-003", 35),
    ("suspicious_name_is_auth", {"is_auth": "true"}, "COOKIE-003", 35),
    ("control_character", {"sid": "ab\x01cd"}, "COOKIE-004", 45),
    ("structure_checked_before_payload", {"sid": "<script>\x00"}, "COOKIE-001", 70),
]

COOKIES_CLEAN = [
    ("session_token", {"sessionid": "abc123XYZ"}),
    ("base64_value", {"token": "dGVzdC10b2tlbg=="}),
    ("exactly_max_length", {"sid": "a" * 4096}),
    ("name_containing_admin_as_substring", {"administrator_x": "1"}),
    ("multiple_ordinary_cookies", {"theme": "dark", "lang": "en", "csrftoken": "q9Z"}),
    ("tab_in_value_is_allowed", {"note": "a\tb"}),
]


def _cookie_finding(self, cookies, rule, score):
    result = cookie_validator.detect(make_request(cookies=cookies))
    self.assertIsNotNone(result)
    self.assertEqual((result["rule"], result["score"]), (rule, score))


def _cookie_clean(self, cookies):
    self.assertIsNone(cookie_validator.detect(make_request(cookies=cookies)))


class TestCookieFindings(unittest.TestCase):
    pass


class TestCookiesClean(unittest.TestCase):
    pass


add_cases(TestCookieFindings, "test_flags", COOKIE_FINDINGS, _cookie_finding)
add_cases(TestCookiesClean, "test_accepts", COOKIES_CLEAN, _cookie_clean)


class TestCookieDecisions(unittest.TestCase):
    def test_null_byte_cookie_is_blocked(self):
        self.assertEqual(inspect(cookies={"sid": "a\x00b"}).action, BLOCK)

    def test_oversized_cookie_alone_is_allowed(self):
        self.assertEqual(inspect(cookies={"sid": "a" * 5000}).action, ALLOW)

    def test_sqli_payload_in_cookie_blocks_and_names_cookie(self):
        d = inspect(cookies={"id": "1 UNION SELECT 1,2"})
        self.assertEqual(d.action, BLOCK)
        self.assertTrue(any("cookie 'id'" in r for r in d.reasons))

    def test_command_payload_in_cookie(self):
        self.assertEqual(inspect(cookies={"x": "; whoami"}).action, BLOCK)

    def test_traversal_payload_in_cookie(self):
        self.assertEqual(inspect(cookies={"x": "/etc/passwd"}).action, BLOCK)

    def test_only_first_problem_cookie_is_reported(self):
        result = cookie_validator.detect(
            make_request(cookies={"admin": "1", "sid": "a\x00b"})
        )
        self.assertEqual(result["rule"], "COOKIE-003")  # first in dict order


# ----------------------------------------------------------------- headers
# (case_id, headers dict, expected rule, expected score)
HEADER_FINDINGS = [
    ("crlf_in_referer", {"Referer": "http://a.example\r\nSet-Cookie: x=1"}, "HDR-001", 75),
    ("bare_lf_in_origin", {"Origin": "http://a.example\nX: y"}, "HDR-001", 75),
    ("oversized_referer", {"Referer": "a" * 8193}, "HDR-002", 35),
    ("non_numeric_content_length", {"Content-Length": "abc"}, "HDR-003", 30),
    ("too_many_forwarded_hops", {"X-Forwarded-For": ", ".join(["1.2.3.4"] * 11)}, "HDR-004", 30),
    ("host_header_traversal", {"Host": "../../etc/passwd"}, "PATH-004", 90),
    ("referer_sqli_union", {"Referer": "http://a/?q=1 UNION SELECT 1"}, "SQLI-001", 80),
    ("x_forwarded_for_xss", {"X-Forwarded-For": "<script>x</script>"}, "XSS-001", 90),
]

HEADERS_CLEAN = [
    ("typical_browser_headers", {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://example.com/products?id=5",
    }),
    ("ten_forwarded_hops", {"X-Forwarded-For": ", ".join(["1.2.3.4"] * 10)}),
    ("exact_max_header_length", {"Referer": "a" * 8192}),
    ("numeric_content_length", {"Content-Length": "42"}),
    ("content_type_form", {"Content-Type": "application/x-www-form-urlencoded"}),
]


def _header_finding(self, headers, rule, score):
    result = header_validator.detect(make_request(headers=headers))
    self.assertIsNotNone(result)
    self.assertEqual((result["rule"], result["score"]), (rule, score))


def _header_clean(self, headers):
    self.assertIsNone(header_validator.detect(make_request(headers=headers)))


class TestHeaderFindings(unittest.TestCase):
    pass


class TestHeadersClean(unittest.TestCase):
    pass


add_cases(TestHeaderFindings, "test_flags", HEADER_FINDINGS, _header_finding)
add_cases(TestHeadersClean, "test_accepts", HEADERS_CLEAN, _header_clean)


class TestHeaderDecisions(unittest.TestCase):
    def test_crlf_header_injection_is_blocked(self):
        d = inspect(headers={"Referer": "http://a.example\r\nSet-Cookie: x=1"})
        self.assertEqual(d.action, BLOCK)
        self.assertIn("HDR-001", d.rules)

    def test_oversized_header_alone_is_allowed(self):
        self.assertEqual(inspect(headers={"Referer": "a" * 9000}).action, ALLOW)

    def test_canonical_case_header_name_is_inspected(self):
        d = inspect(headers={"Referer": "http://a.example\r\nX: y"})
        self.assertEqual(d.action, BLOCK)

    @unittest.expectedFailure
    def test_lowercase_header_name_is_inspected(self):
        """KNOWN GAP: header_validator looks headers up by canonical name
        (headers.get("Referer")) on the plain dict that get_headers()
        builds, so "referer" / "REFERER" are never inspected. HTTP/2 and
        Starlette deliver lowercase names, so CRLF injection, oversize
        and forwarded-chain checks are skipped for them. Fix: compare
        names case-insensitively in header_validator.detect(). Remove
        this decorator once fixed."""
        d = inspect(headers={"referer": "http://a.example\r\nX: y"})
        self.assertEqual(d.action, BLOCK)

    def test_accept_header_is_not_payload_scanned_by_header_validator(self):
        # header_validator skips 'Accept' for payload checks, so only
        # the other detectors can object to it.
        result = header_validator.detect(make_request(headers={"Accept": "text/html;q=1 UNION SELECT"}))
        self.assertIsNone(result)

    def test_user_agent_header_is_payload_scanned(self):
        d = inspect(headers={"User-Agent": "Mozilla/5.0 <script>x</script>"})
        self.assertEqual(d.action, BLOCK)


if __name__ == "__main__":
    unittest.main()
