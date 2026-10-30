"""
test_command_injection.py

Command-injection coverage (CMD-* rules and command_injection.detect()).

command_injection.detect() ignores a lone indicator scoring < 50 unless
the shell-metacharacter rule (CMD-001) matches together with another
CMD rule (then +15).
"""

import unittest

from waf_core.constants import ALLOW, BLOCK
from waf_core.detectors import command_injection

from tests.helpers import add_cases, inspect, make_request, matched_rules

# (case_id, payload, expected rule id)
BLOCKED = [
    ("semicolon_whoami", "; whoami", "CMD-007"),
    ("and_and_whoami", "&& whoami", "CMD-007"),
    ("or_or_ls", "|| ls -la", "CMD-001"),
    ("backtick_whoami", "`whoami`", "CMD-007"),
    ("dollar_paren_whoami", "$(whoami)", "CMD-007"),
    ("cmd_exe", "cmd.exe /c dir", "CMD-002"),
    ("powershell", "powershell -enc AAAA", "CMD-003"),
    ("url_encoded_semicolon", "%3B%20whoami", "CMD-007"),
    ("double_encoded_ampersands", "%2526%2526%2520whoami", "CMD-007"),
]

# (case_id, payload, expected rule, expected score): detected, but under
# the block threshold when nothing else corroborates them.
BELOW_THRESHOLD = [
    ("command_substitution_alone", "$(id)", "CMD-001", 60),
    ("backticks_alone", "`id`", "CMD-001", 60),
    ("netcat_alone", "nc -e target 4444", "CMD-006", 55),
    ("shell_sleep", "sleep 10", "CMD-010", 50),
]

# Weak words that must be ignored when used in ordinary text.
IGNORED = [
    ("cat_and_ping_in_prose", "my cat is called Ping"),
    ("bash_word", "I prefer bash for scripting"),
    ("curl_word", "curl the edges of the paper"),
    ("directory_word", "dir"),
]


def _blocked(self, payload, rule):
    decision = inspect(query_params={"cmd": payload})
    self.assertEqual(decision.action, BLOCK)
    self.assertIn(rule, matched_rules(decision))


def _below_threshold(self, payload, rule, score):
    result = command_injection.detect(make_request(query_params={"cmd": payload}))
    self.assertEqual((result["rule"], result["score"]), (rule, score))
    self.assertEqual(inspect(query_params={"cmd": payload}).action, ALLOW)


def _ignored(self, payload):
    self.assertIsNone(command_injection.detect(make_request(query_params={"cmd": payload})))
    self.assertEqual(inspect(query_params={"cmd": payload}).action, ALLOW)


class TestCommandInjectionBlocked(unittest.TestCase):
    pass


class TestCommandInjectionBelowThreshold(unittest.TestCase):
    pass


class TestCommandInjectionIgnored(unittest.TestCase):
    pass


add_cases(TestCommandInjectionBlocked, "test_blocks", BLOCKED, _blocked)
add_cases(TestCommandInjectionBelowThreshold, "test_single_signal_scores_below_block", BELOW_THRESHOLD, _below_threshold)
add_cases(TestCommandInjectionIgnored, "test_ignored", IGNORED, _ignored)


class TestCommandInjectionCorroboration(unittest.TestCase):
    def test_metacharacter_plus_command_adds_bonus(self):
        result = command_injection.detect(make_request(query_params={"c": "; whoami"}))
        self.assertEqual(result["score"], 75)
        self.assertIn("metacharacter + command name", result["reason"])

    def test_command_names_without_metacharacter_do_not_corroborate(self):
        # CMD-008 (cat, 20) + CMD-009 (ping, 25): two rules, no CMD-001.
        self.assertIsNone(
            command_injection.detect(make_request(query_params={"c": "cat ping"}))
        )

    def test_scanner_user_agent_pushes_sub_threshold_command_over_the_line(self):
        d = inspect(query_params={"c": "$(id)"}, headers={"User-Agent": "curl/8.0.1"})
        self.assertEqual(d.action, BLOCK)  # 60 (CMD-001) + 25 (UA-014)


class TestCommandInjectionLocations(unittest.TestCase):
    def test_form_field(self):
        d = inspect(method="POST", form_data={"host": "example.com; whoami"})
        self.assertEqual(d.action, BLOCK)

    def test_json_body(self):
        d = inspect(
            method="POST",
            headers={"Content-Type": "application/json"},
            body='{"host": "example.com && whoami"}',
        )
        self.assertEqual(d.action, BLOCK)

    def test_header_value(self):
        d = inspect(headers={"X-Custom": "x; whoami"})
        self.assertEqual(d.action, BLOCK)


if __name__ == "__main__":
    unittest.main()
