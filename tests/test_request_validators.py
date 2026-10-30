"""
test_request_validators.py

Structural/shape validators that look at the request itself rather than
attack signatures: http_method_validator (METHOD-*), path_validator
(PATHV-*) and payload_validator (PAYLOAD-*).
"""

import unittest

from waf_core.constants import ALLOW, BLOCK
from waf_core.detectors import http_method_validator, path_validator, payload_validator

from tests.helpers import add_cases, inspect, make_request

# ------------------------------------------------------------------ methods
ALLOWED_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "get", "Post"]

# (case_id, method, expected rule, expected score)
FLAGGED_METHODS = [
    ("trace", "TRACE", "METHOD-001", 55),
    ("connect", "CONNECT", "METHOD-002", 55),
    ("track", "TRACK", "METHOD-003", 50),
    ("lowercase_trace", "trace", "METHOD-001", 55),
    ("unknown_verb", "FOOBAR", "METHOD-004", 40),
    ("webdav_propfind", "PROPFIND", "METHOD-004", 40),
]


def _allowed_method(self, method):
    self.assertIsNone(http_method_validator.detect(make_request(method=method)))


def _flagged_method(self, method, rule, score):
    result = http_method_validator.detect(make_request(method=method))
    self.assertEqual((result["rule"], result["score"]), (rule, score))


class TestMethodsAllowed(unittest.TestCase):
    pass


class TestMethodsFlagged(unittest.TestCase):
    pass


add_cases(TestMethodsAllowed, "test_allows", [(m, m) for m in ALLOWED_METHODS], _allowed_method)
add_cases(TestMethodsFlagged, "test_flags", FLAGGED_METHODS, _flagged_method)


class TestMethodDecisions(unittest.TestCase):
    def test_trace_alone_is_allowed(self):
        self.assertEqual(inspect(method="TRACE").action, ALLOW)

    def test_trace_with_scanner_user_agent_is_blocked(self):
        d = inspect(method="TRACE", headers={"User-Agent": "nikto/2.1"})
        self.assertEqual(d.action, BLOCK)

    def test_empty_method_defaults_to_get(self):
        self.assertIsNone(http_method_validator.detect(make_request(method="")))


# --------------------------------------------------------------------- paths
PATH_FINDINGS = [
    ("too_long", "/" + "a" * 2048, "PATHV-001", 35),
    ("double_encoded", "/files/%2541", "PATHV-002", 55),
    ("null_byte_encoded", "/download%00.png", "PATHV-003", 65),
    ("null_byte_encoded_uppercase", "/download%00", "PATHV-003", 65),
    ("null_byte_raw", "/download\x00.png", "PATHV-003", 65),
    ("control_character", "/a\x07b", "PATHV-005", 45),
    ("invalid_utf8_surrogate", "/a\udc80b", "PATHV-004", 40),
    ("double_encoding_wins_over_null_byte", "/%2541%00", "PATHV-002", 55),
]

PATHS_CLEAN = [
    ("root", "/"),
    ("nested", "/blog/2024/05/hello-world"),
    ("exactly_max_length", "/" + "a" * 2047),
    ("single_encoded_space", "/my%20file.txt"),
    ("unicode_path", "/caf\u00e9/men\u00fc"),
    ("trailing_slash_and_extension", "/static/app.min.js"),
]


def _path_finding(self, path, rule, score):
    result = path_validator.detect(make_request(path=path))
    self.assertIsNotNone(result)
    self.assertEqual((result["rule"], result["score"]), (rule, score))


def _path_clean(self, path):
    self.assertIsNone(path_validator.detect(make_request(path=path)))


class TestPathFindings(unittest.TestCase):
    pass


class TestPathsClean(unittest.TestCase):
    pass


add_cases(TestPathFindings, "test_flags", PATH_FINDINGS, _path_finding)
add_cases(TestPathsClean, "test_accepts", PATHS_CLEAN, _path_clean)


class TestPathDecisions(unittest.TestCase):
    def test_long_path_alone_is_allowed(self):
        self.assertEqual(inspect(path="/" + "a" * 3000).action, ALLOW)

    def test_null_byte_path_alone_is_allowed(self):
        self.assertEqual(inspect(path="/download%00.png").action, ALLOW)

    def test_null_byte_plus_traversal_is_blocked(self):
        self.assertEqual(inspect(path="/download/../../etc/hosts%00").action, BLOCK)


# ------------------------------------------------------------------ payloads
def _nested_json(depth):
    return '{"a":' * depth + "1" + "}" * depth


JSON = {"Content-Type": "application/json"}

PAYLOAD_FINDINGS = [
    (
        "oversized_content_length",
        dict(headers={"Content-Length": str(2 * 1024 * 1024 + 1)}),
        "PAYLOAD-001", 35,
    ),
    ("null_byte_in_body", dict(method="POST", body=b"abc\x00def"), "PAYLOAD-002", 60),
    (
        "binary_blob_in_form_field",
        dict(method="POST", form_data={"bio": "\x01" * 30}),
        "PAYLOAD-003", 45,
    ),
    (
        "binary_blob_in_query_param",
        dict(query_params={"q": "\x02\x03" * 20}),
        "PAYLOAD-003", 45,
    ),
    (
        "json_nested_too_deep",
        dict(method="POST", headers=JSON, body=_nested_json(21)),
        "PAYLOAD-004", 50,
    ),
    (
        "php_upload",
        dict(method="POST", files={"f": {"name": "s.php", "content_type": "application/x-httpd-php"}}),
        "PAYLOAD-005", 75,
    ),
    (
        "shell_script_upload_uppercase_mime",
        dict(method="POST", files={"f": {"name": "s.sh", "content_type": "APPLICATION/X-SH"}}),
        "PAYLOAD-005", 75,
    ),
    (
        "windows_executable_upload",
        dict(method="POST", files={"f": {"name": "a.exe", "content_type": "application/x-msdownload"}}),
        "PAYLOAD-005", 75,
    ),
]

PAYLOADS_CLEAN = [
    ("empty_get", dict()),
    ("content_length_at_limit", dict(headers={"Content-Length": str(2 * 1024 * 1024)})),
    ("short_control_chars_under_min_length", dict(method="POST", form_data={"x": "\x01" * 10})),
    ("json_at_depth_limit", dict(method="POST", headers=JSON, body=_nested_json(20))),
    ("invalid_json_body_does_not_crash", dict(method="POST", headers=JSON, body="{not json")),
    ("png_upload", dict(method="POST", files={"f": {"name": "a.png", "content_type": "image/png"}})),
    ("pdf_upload", dict(method="POST", files={"f": {"name": "a.pdf", "content_type": "application/pdf"}})),
    ("non_numeric_content_length_ignored", dict(meta={"CONTENT_LENGTH": "abc"})),
    ("multiline_text_field", dict(method="POST", form_data={"msg": "line one\nline two\r\nline three padded"})),
]


def _payload_finding(self, kwargs, rule, score):
    result = payload_validator.detect(make_request(**kwargs))
    self.assertIsNotNone(result)
    self.assertEqual((result["rule"], result["score"]), (rule, score))


def _payload_clean(self, kwargs):
    self.assertIsNone(payload_validator.detect(make_request(**kwargs)))


class TestPayloadFindings(unittest.TestCase):
    pass


class TestPayloadsClean(unittest.TestCase):
    pass


add_cases(TestPayloadFindings, "test_flags", PAYLOAD_FINDINGS, _payload_finding)
add_cases(TestPayloadsClean, "test_accepts", PAYLOADS_CLEAN, _payload_clean)


class TestPayloadDecisions(unittest.TestCase):
    def test_dangerous_upload_is_blocked(self):
        d = inspect(
            method="POST",
            files={"f": {"name": "s.php", "content_type": "application/x-httpd-php"}},
        )
        self.assertEqual(d.action, BLOCK)
        self.assertIn("PAYLOAD-005", d.rules)

    def test_null_byte_body_alone_is_allowed(self):
        self.assertEqual(inspect(method="POST", body=b"abc\x00def").action, ALLOW)

    def test_upload_reason_names_the_file(self):
        d = inspect(
            method="POST",
            files={"f": {"name": "evil.php", "content_type": "application/x-httpd-php"}},
        )
        self.assertTrue(any("evil.php" in r for r in d.reasons))


if __name__ == "__main__":
    unittest.main()
