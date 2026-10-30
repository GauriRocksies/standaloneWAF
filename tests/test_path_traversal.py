"""
test_path_traversal.py

Directory traversal / sensitive-file detection (PATH-* rules and
directory_traversal.detect()), including encoded and obfuscated forms
and the benign look-alikes that must not be flagged.
"""

import unittest

from waf_core.constants import ALLOW, BLOCK
from waf_core.detectors import directory_traversal

from tests.helpers import add_cases, inspect, make_request, matched_rules

# (case_id, value for ?file=, expected rule id)
BLOCKED = [
    ("dotdot_slash", "../../secret.txt", "PATH-001"),
    ("dotdot_backslash", "..\\..\\secret.txt", "PATH-001"),
    ("etc_passwd", "/etc/passwd", "PATH-004"),
    ("etc_shadow", "/etc/shadow", "PATH-008"),
    ("boot_ini", "C:\\boot.ini", "PATH-005"),
    ("windows_system32", "C:\\Windows\\System32\\drivers", "PATH-006"),
    ("proc_self", "/proc/self/environ", "PATH-007"),
    ("url_encoded_dotdot", "%2e%2e%2f%2e%2e%2fsecret", "PATH-001"),
    ("url_encoded_uppercase", "%2E%2E%2Fsecret", "PATH-001"),
    ("double_encoded_dotdot", "%252e%252e%252fsecret", "PATH-003"),
    ("url_encoded_etc_passwd", "%2fetc%2fpasswd", "PATH-004"),
]

# (case_id, value, expected rule, expected score): detected, but not
# enough on their own to cross the block threshold.
BELOW_THRESHOLD = [
    ("etc_hosts", "/etc/hosts", "PATH-009", 55),
    ("raw_encoded_dots_without_slash", "%2e%2e", "PATH-002", 50),
]

# Values that merely look like traversal and must stay allowed.
BENIGN = [
    ("plain_relative_file", "reports/2024/summary.pdf"),
    ("double_dot_in_name", "release..notes.txt"),
    ("version_number", "release-1.2.3.tar.gz"),
    ("single_dot_segment", "./local/file.txt"),
    ("ellipsis_text", "wait...what"),
    ("url_path", "/blog/2024/05/post-title"),
]


def _blocked(self, value, rule):
    decision = inspect(query_params={"file": value})
    self.assertEqual(decision.action, BLOCK)
    self.assertIn(rule, matched_rules(decision))


def _below_threshold(self, value, rule, score):
    result = directory_traversal.detect(make_request(query_params={"file": value}))
    self.assertEqual((result["rule"], result["score"]), (rule, score))
    self.assertEqual(inspect(query_params={"file": value}).action, ALLOW)


def _benign(self, value):
    self.assertIsNone(directory_traversal.detect(make_request(query_params={"file": value})))
    self.assertEqual(inspect(query_params={"file": value}).action, ALLOW)


class TestTraversalBlocked(unittest.TestCase):
    pass


class TestTraversalBelowThreshold(unittest.TestCase):
    pass


class TestTraversalBenign(unittest.TestCase):
    pass


add_cases(TestTraversalBlocked, "test_blocks", BLOCKED, _blocked)
add_cases(TestTraversalBelowThreshold, "test_detected_but_allowed", BELOW_THRESHOLD, _below_threshold)
add_cases(TestTraversalBenign, "test_allows", BENIGN, _benign)


class TestTraversalLocations(unittest.TestCase):
    def test_traversal_in_url_path(self):
        d = inspect(path="/static/../../etc/passwd")
        self.assertEqual(d.action, BLOCK)
        self.assertIn("directory_detector", d.detectors)

    def test_traversal_in_form_field(self):
        d = inspect(method="POST", form_data={"template": "../../etc/passwd"})
        self.assertEqual(d.action, BLOCK)

    def test_traversal_in_json_body(self):
        d = inspect(
            method="POST",
            headers={"Content-Type": "application/json"},
            body='{"path": "..\\\\..\\\\boot.ini"}',
        )
        self.assertEqual(d.action, BLOCK)

    def test_traversal_in_cookie(self):
        d = inspect(cookies={"theme": "../../etc/passwd"})
        self.assertEqual(d.action, BLOCK)

    def test_two_indicators_add_bonus(self):
        # PATH-001 (70) + PATH-004 (90): best score 90, +10 bonus = 100
        result = directory_traversal.detect(
            make_request(query_params={"file": "../../etc/passwd"})
        )
        self.assertEqual(result["score"], 100)
        self.assertIn("combined with", result["reason"])


if __name__ == "__main__":
    unittest.main()
