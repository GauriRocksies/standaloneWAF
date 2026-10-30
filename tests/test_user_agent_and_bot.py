"""
test_user_agent_and_bot.py

user_agent_detector (UA-*) and bot_detector (BOT-*).

Block rule reminder: summed score >= 70, or any critical (>= 80)
detection. So scanner UAs scoring >= 70 block by themselves, while
generic HTTP-library UAs (python-requests, curl, ...) only add signal.
"""

import unittest
from unittest import mock

from waf_core.constants import ALLOW, BLOCK
from waf_core.detectors import bot_detector, user_agent

from tests.helpers import BROWSER_UA, add_cases, inspect, make_request, unique_ip

# (case_id, User-Agent, rule id, score)
KNOWN_TOOLS = [
    ("sqlmap", "sqlmap/1.7.2#stable (https://sqlmap.org)", "UA-001", 90),
    ("nikto", "Mozilla/5.00 (Nikto/2.1.6)", "UA-002", 90),
    ("acunetix", "Mozilla/5.0 Acunetix-Product", "UA-003", 90),
    ("burp", "Mozilla/5.0 BurpSuite/2023", "UA-004", 80),
    ("havij", "Havij scanner agent string", "UA-005", 90),
    ("nessus", "Nessus SOAP client agent", "UA-006", 85),
    ("zgrab", "Mozilla/5.0 zgrab/0.x", "UA-007", 75),
    ("masscan", "masscan/1.3 (https://github.com/robertdavidgraham/masscan)", "UA-008", 80),
    ("nmap", "Mozilla/5.0 (compatible; Nmap Scripting Engine)", "UA-009", 80),
    ("fimap", "fimap file inclusion scanner", "UA-010", 85),
    ("libwww", "libwww-perl/6.67", "UA-011", 60),
    ("python_requests", "python-requests/2.31.0", "UA-012", 40),
    ("go_http_client", "Go-http-client/1.1", "UA-013", 40),
    ("curl", "curl/8.4.0 (x86_64-pc-linux-gnu)", "UA-014", 25),
    ("wget", "Wget/1.21.3 (linux-gnu)", "UA-015", 30),
    ("case_insensitive", "SQLMAP/1.0 and padding text", "UA-001", 90),
]

# (case_id, User-Agent, rule id, score)
ODD_AGENTS = [
    ("empty", "", "UA-016", 35),
    ("whitespace_only", "   ", "UA-016", 35),
    ("too_short", "Mozilla", "UA-017", 25),
    ("random_alphanumeric", "a1b2c3d4e5f6g7h8i9j0k1", "UA-018", 20),
]

CLEAN_AGENTS = [
    ("chrome", BROWSER_UA),
    ("firefox", "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"),
    ("safari_ios", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Version/17.4 Mobile/15E148 Safari/604.1"),
    ("exactly_min_length", "A" * 14 + " "),  # 15 chars, contains a space
]


def _known_tool(self, ua, rule, score):
    result = user_agent.detect(make_request(headers={"User-Agent": ua}))
    self.assertEqual((result["rule"], result["score"]), (rule, score))
    expected = BLOCK if score >= 70 else ALLOW
    self.assertEqual(inspect(headers={"User-Agent": ua}).action, expected)


def _odd_agent(self, ua, rule, score):
    result = user_agent.detect(make_request(headers={"User-Agent": ua}))
    self.assertEqual((result["rule"], result["score"]), (rule, score))
    self.assertEqual(inspect(headers={"User-Agent": ua}).action, ALLOW)


def _clean_agent(self, ua):
    self.assertIsNone(user_agent.detect(make_request(headers={"User-Agent": ua})))


class TestKnownToolAgents(unittest.TestCase):
    pass


class TestOddAgents(unittest.TestCase):
    pass


class TestCleanAgents(unittest.TestCase):
    pass


add_cases(TestKnownToolAgents, "test_tool", KNOWN_TOOLS, _known_tool)
add_cases(TestOddAgents, "test_flags", ODD_AGENTS, _odd_agent)
add_cases(TestCleanAgents, "test_accepts", CLEAN_AGENTS, _clean_agent)


class TestUserAgentMissing(unittest.TestCase):
    def test_missing_header_is_treated_as_empty(self):
        from waf_core import WAFRequest

        result = user_agent.detect(WAFRequest(path="/"))
        self.assertEqual(result["rule"], "UA-016")

    def test_missing_user_agent_does_not_block_by_itself(self):
        from waf_core import WAFEngine, WAFRequest

        d = WAFEngine().inspect(WAFRequest(path="/", meta={"REMOTE_ADDR": unique_ip()}))
        self.assertEqual(d.action, ALLOW)
        self.assertEqual(d.rules, ["UA-016"])

    def test_python_requests_ua_plus_tautology_blocks(self):
        d = inspect(
            query_params={"id": "' OR 1=1 --"},
            headers={"User-Agent": "python-requests/2.31.0"},
        )
        self.assertEqual(d.action, BLOCK)  # 45 + 40


# ----------------------------------------------------------------------- bot
AUTOMATION_MARKERS = [
    ("headlesschrome", "Mozilla/5.0 HeadlessChrome/124.0 Safari/537.36"),
    ("phantomjs", "Mozilla/5.0 (Unknown; Linux x86_64) PhantomJS/2.1.1"),
    ("selenium", "Mozilla/5.0 Selenium/4.1 browser automation agent"),
    ("playwright", "Mozilla/5.0 Playwright/1.40 test agent string"),
    ("puppeteer", "Mozilla/5.0 Puppeteer/21 test agent string"),
]


def _automation_marker(self, ua):
    result = bot_detector.detect(make_request(headers={"User-Agent": ua}))
    self.assertEqual((result["rule"], result["score"]), ("BOT-001", 55))


class TestBotAutomationMarkers(unittest.TestCase):
    pass


add_cases(TestBotAutomationMarkers, "test_flags", AUTOMATION_MARKERS, _automation_marker)


class TestBotDetector(unittest.TestCase):
    def test_webdriver_header(self):
        result = bot_detector.detect(make_request(headers={"X-Webdriver": "1"}))
        self.assertEqual((result["rule"], result["score"]), ("BOT-002", 60))

    def test_alternate_webdriver_header(self):
        result = bot_detector.detect(make_request(headers={"Webdriver": "true"}))
        self.assertEqual(result["rule"], "BOT-002")

    def test_ordinary_browser_is_not_flagged(self):
        self.assertIsNone(bot_detector.detect(make_request()))

    def test_automation_alone_is_allowed(self):
        d = inspect(headers={"User-Agent": "Mozilla/5.0 HeadlessChrome/124.0 Safari"})
        self.assertEqual(d.action, ALLOW)

    def test_only_first_bot_finding_is_reported(self):
        d = inspect(
            headers={"User-Agent": "Mozilla/5.0 HeadlessChrome/124.0 Safari", "X-Webdriver": "1"}
        )
        # bot_detector returns one result per request: the UA marker
        # (BOT-001, 55) wins and the webdriver header (BOT-002) is not
        # added on top, so the total stays under the block threshold.
        self.assertEqual(d.action, ALLOW)
        self.assertEqual(d.rules, ["BOT-001"])

    def test_missing_remote_addr_skips_rapid_request_check(self):
        request = make_request(meta={"REMOTE_ADDR": ""})
        self.assertIsNone(bot_detector.detect(request))


class TestBotRapidRequests(unittest.TestCase):
    """BOT-003 counts requests per IP per 10-second bucket in a shared
    cache. Time is frozen so a bucket boundary can't split a test."""

    def _fire(self, ip, count):
        result = None
        for _ in range(count):
            result = bot_detector.detect(make_request(meta={"REMOTE_ADDR": ip}))
        return result

    def test_thirty_requests_are_fine_thirty_first_is_flagged(self):
        ip = unique_ip()
        with mock.patch.object(bot_detector, "time") as fake_time:
            fake_time.time.return_value = 1_000_000.0
            self.assertIsNone(self._fire(ip, 30))
            result = self._fire(ip, 1)
        self.assertEqual((result["rule"], result["score"]), ("BOT-003", 30))

    def test_counter_resets_in_the_next_window(self):
        ip = unique_ip()
        with mock.patch.object(bot_detector, "time") as fake_time:
            fake_time.time.return_value = 2_000_000.0
            self.assertIsNotNone(self._fire(ip, 31))
            fake_time.time.return_value = 2_000_010.0
            self.assertIsNone(self._fire(ip, 1))

    def test_ips_are_counted_independently(self):
        ip_a, ip_b = unique_ip(), unique_ip()
        with mock.patch.object(bot_detector, "time") as fake_time:
            fake_time.time.return_value = 3_000_000.0
            self.assertIsNotNone(self._fire(ip_a, 31))
            self.assertIsNone(self._fire(ip_b, 1))

    def test_rapid_requests_alone_never_block(self):
        ip = unique_ip()
        with mock.patch.object(bot_detector, "time") as fake_time:
            fake_time.time.return_value = 4_000_000.0
            self._fire(ip, 40)
            d = inspect(meta={"REMOTE_ADDR": ip})
        self.assertEqual(d.action, ALLOW)
        self.assertEqual(d.risk_score, 30)

    def test_broken_cache_backend_is_tolerated(self):
        with mock.patch.object(bot_detector.cache, "get", side_effect=RuntimeError("down")):
            self.assertIsNone(bot_detector.detect(make_request()))


if __name__ == "__main__":
    unittest.main()
