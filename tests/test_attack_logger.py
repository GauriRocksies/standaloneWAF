

from django.test import TestCase

from waf.logging.attack_logger import log_attack, log_access
from waf.models import AttackLog, BlockedIP, RuleStats, DetectorStats


def make_event(**overrides):
    """A minimal, valid log_attack() event dict, with any fields
    the caller wants to override."""
    event = {
        "ip_address": "203.0.113.10",
        "url": "/search",
        "method": "GET",
        "attack_type": "xss",
        "payload": {"q": "<script>alert(1)</script>"},
        "headers": {"User-Agent": "test-agent"},
        "severity": "high",
        "risk_score": 80,
        "rule_triggered": "XSS-001",
        "detector_name": "xss_detector",
        "user_agent": "test-agent",
        "blocked": True,
        "response_code": 403,
    }
    event.update(overrides)
    return event


class TestRequiredFields(TestCase):
    """log_attack() must refuse to write a row missing any of the
    documented required fields, and must never raise while doing so."""

    def test_missing_ip_address_returns_none(self):
        event = make_event()
        del event["ip_address"]
        result = log_attack(event)
        self.assertIsNone(result)
        self.assertEqual(AttackLog.objects.count(), 0)

    def test_missing_url_returns_none(self):
        event = make_event()
        del event["url"]
        result = log_attack(event)
        self.assertIsNone(result)
        self.assertEqual(AttackLog.objects.count(), 0)

    def test_missing_method_returns_none(self):
        event = make_event()
        del event["method"]
        result = log_attack(event)
        self.assertIsNone(result)
        self.assertEqual(AttackLog.objects.count(), 0)

    def test_missing_attack_type_returns_none(self):
        event = make_event()
        del event["attack_type"]
        result = log_attack(event)
        self.assertIsNone(result)
        self.assertEqual(AttackLog.objects.count(), 0)

    def test_all_required_fields_present_succeeds(self):
        result = log_attack(make_event())
        self.assertIsNotNone(result)
        self.assertEqual(AttackLog.objects.count(), 1)


class TestFieldPersistence(TestCase):
    """A successful call must persist exactly the data it was given,
    with documented defaults applied where a field is omitted."""

    def test_full_event_persists_all_fields_correctly(self):
        event = make_event()
        attack = log_attack(event)

        self.assertEqual(attack.ip_address, event["ip_address"])
        self.assertEqual(attack.url, event["url"])
        self.assertEqual(attack.method, event["method"])
        self.assertEqual(attack.attack_type, event["attack_type"])
        self.assertEqual(attack.payload, event["payload"])
        self.assertEqual(attack.headers, event["headers"])
        self.assertEqual(attack.severity, event["severity"])
        self.assertEqual(attack.risk_score, event["risk_score"])
        self.assertEqual(attack.rule_triggered, event["rule_triggered"])
        self.assertEqual(attack.detector_name, event["detector_name"])
        self.assertEqual(attack.user_agent, event["user_agent"])
        self.assertTrue(attack.blocked)
        self.assertEqual(attack.response_code, 403)

    def test_optional_fields_default_correctly_when_omitted(self):
        """Only the four required fields are given; everything else
        should fall back to log_attack()'s documented defaults."""
        minimal_event = {
            "ip_address": "203.0.113.20",
            "url": "/login",
            "method": "POST",
            "attack_type": "sql_injection",
        }
        attack = log_attack(minimal_event)

        self.assertIsNotNone(attack)
        self.assertEqual(attack.severity, "low")
        self.assertEqual(attack.risk_score, 0)
        self.assertEqual(attack.rule_triggered, "")
        self.assertEqual(attack.detector_name, "")
        self.assertEqual(attack.user_agent, "")
        self.assertFalse(attack.blocked)
        self.assertIsNone(attack.response_code)
        self.assertIsNone(attack.payload)
        self.assertIsNone(attack.headers)


class TestStatsUpdates(TestCase):
    """RuleStats/DetectorStats counters must increment whenever the
    corresponding field is present on a logged attack."""

    def test_rule_stats_created_and_incremented(self):
        log_attack(make_event(rule_triggered="XSS-001"))
        log_attack(make_event(rule_triggered="XSS-001", ip_address="203.0.113.11"))

        rule_stat = RuleStats.objects.get(rule_name="XSS-001")
        self.assertEqual(rule_stat.trigger_count, 2)

    def test_detector_stats_created_and_incremented(self):
        log_attack(make_event(detector_name="xss_detector"))
        log_attack(make_event(detector_name="xss_detector", ip_address="203.0.113.12"))

        detector_stat = DetectorStats.objects.get(detector_name="xss_detector")
        self.assertEqual(detector_stat.detection_count, 2)

    def test_no_rule_or_detector_name_skips_stats(self):
        log_attack(make_event(rule_triggered="", detector_name=""))
        self.assertEqual(RuleStats.objects.count(), 0)
        self.assertEqual(DetectorStats.objects.count(), 0)


class TestAutoBlock(TestCase):
    """The existing auto-block policy: an IP is blocked once it has
    AUTO_BLOCK_THRESHOLD (3) blocked attacks logged against it."""

    def test_ip_not_blocked_before_threshold(self):
        ip = "203.0.113.30"
        log_attack(make_event(ip_address=ip, blocked=True))
        log_attack(make_event(ip_address=ip, blocked=True))

        self.assertFalse(BlockedIP.is_blocked(ip))
        self.assertEqual(BlockedIP.objects.count(), 0)

    def test_ip_blocked_at_threshold(self):
        ip = "203.0.113.31"
        log_attack(make_event(ip_address=ip, blocked=True))
        log_attack(make_event(ip_address=ip, blocked=True))
        log_attack(make_event(ip_address=ip, blocked=True))

        self.assertTrue(BlockedIP.is_blocked(ip))
        blocked = BlockedIP.objects.get(ip_address=ip)
        self.assertEqual(blocked.attack_count, 1)

    def test_non_blocked_attacks_do_not_count_toward_threshold(self):
        ip = "203.0.113.32"
        log_attack(make_event(ip_address=ip, blocked=False))
        log_attack(make_event(ip_address=ip, blocked=False))
        log_attack(make_event(ip_address=ip, blocked=False))

        self.assertFalse(BlockedIP.is_blocked(ip))
        self.assertEqual(BlockedIP.objects.count(), 0)

    def test_auto_block_false_suppresses_blocking(self):
        ip = "203.0.113.33"
        for _ in range(5):
            log_attack(make_event(ip_address=ip, blocked=True, auto_block=False))

        self.assertFalse(BlockedIP.is_blocked(ip))
        self.assertEqual(BlockedIP.objects.count(), 0)

    def test_different_ips_tracked_independently(self):
        ip_a = "203.0.113.40"
        ip_b = "203.0.113.41"
        log_attack(make_event(ip_address=ip_a, blocked=True))
        log_attack(make_event(ip_address=ip_a, blocked=True))
        log_attack(make_event(ip_address=ip_b, blocked=True))

        self.assertFalse(BlockedIP.is_blocked(ip_a))
        self.assertFalse(BlockedIP.is_blocked(ip_b))


class TestLogAccess(TestCase):
    """log_access() is a lightweight helper with no DB writes of its
    own — it should simply never raise."""

    def test_log_access_does_not_raise(self):
        try:
            log_access(ip_address="203.0.113.50", url="/", method="GET", status_code=200)
        except Exception as exc:  # pragma: no cover - failure path
            self.fail(f"log_access raised unexpectedly: {exc}")