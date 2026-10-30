"""
test_engine_behavior.py

WAFEngine orchestration beyond the basics in test_waf_engine.py:
detector isolation, aggregation across detectors, hook contract,
determinism and score capping.
"""

import unittest
from unittest import mock

from waf_core import WAFEngine, WAFRequest, engine as engine_module
from waf_core.constants import ALLOW, BLOCK
from waf_core.decision_engine import Decision

from tests.helpers import inspect, make_request, unique_ip


def fake_detector(score, severity="medium", rule="FAKE-1", name="fake_detector"):
    def detect(request):
        return {
            "attack": "other",
            "score": score,
            "severity": severity,
            "reason": "fake",
            "rule": rule,
            "detector": name,
        }

    return detect


def crashing_detector(request):
    raise RuntimeError("detector bug")


def silent_detector(request):
    return None


class TestDetectorIsolation(unittest.TestCase):
    def test_crashing_detector_is_skipped_and_others_still_count(self):
        registry = [crashing_detector, fake_detector(80, "critical")]
        with mock.patch.object(engine_module, "DETECTOR_REGISTRY", registry):
            d = WAFEngine().inspect(make_request())
        self.assertEqual(d.action, BLOCK)
        self.assertEqual(d.rules, ["FAKE-1"])

    def test_only_crashing_detectors_means_allow(self):
        with mock.patch.object(engine_module, "DETECTOR_REGISTRY", [crashing_detector]):
            d = WAFEngine().inspect(make_request())
        self.assertEqual(d.action, ALLOW)
        self.assertEqual(d.risk_score, 0)

    def test_none_results_are_ignored(self):
        with mock.patch.object(engine_module, "DETECTOR_REGISTRY", [silent_detector, silent_detector]):
            d = WAFEngine().inspect(make_request())
        self.assertEqual(d.detections, [])

    def test_every_registered_detector_runs(self):
        calls = []

        def make(i):
            def detect(request):
                calls.append(i)

            return detect

        with mock.patch.object(engine_module, "DETECTOR_REGISTRY", [make(1), make(2), make(3)]):
            WAFEngine().inspect(make_request())
        self.assertEqual(calls, [1, 2, 3])

    def test_empty_registry_allows_everything(self):
        with mock.patch.object(engine_module, "DETECTOR_REGISTRY", []):
            d = WAFEngine().inspect(make_request(query_params={"q": "<script>"}))
        self.assertEqual(d.action, ALLOW)


class TestAggregation(unittest.TestCase):
    def test_two_sub_threshold_detectors_sum_to_a_block(self):
        registry = [fake_detector(40, rule="A", name="a"), fake_detector(35, rule="B", name="b")]
        with mock.patch.object(engine_module, "DETECTOR_REGISTRY", registry):
            d = WAFEngine().inspect(make_request())
        self.assertEqual((d.action, d.risk_score), (BLOCK, 75))
        self.assertEqual(d.detectors, ["a", "b"])

    def test_attacks_in_different_fields_hit_different_detectors(self):
        d = inspect(
            query_params={"q": "<script>alert(1)</script>"},
            form_data={"id": "1 UNION SELECT 1,2"},
            method="POST",
        )
        self.assertEqual(d.action, BLOCK)
        self.assertIn("xss_detector", d.detectors)
        self.assertIn("sqli_detector", d.detectors)

    def test_risk_score_never_exceeds_100(self):
        d = inspect(
            query_params={"a": "<script>document.cookie</script>", "b": "1 UNION SELECT 1; DROP TABLE t"},
            cookies={"c": "../../etc/passwd"},
            headers={"User-Agent": "sqlmap/1.0"},
        )
        self.assertEqual(d.risk_score, 100)

    def test_clean_request_has_no_rules_and_zero_score(self):
        d = inspect(path="/about")
        self.assertEqual((d.action, d.risk_score, d.rules, d.detections), (ALLOW, 0, [], []))

    def test_missing_user_agent_adds_only_ua_016(self):
        d = WAFEngine().inspect(WAFRequest(path="/", meta={"REMOTE_ADDR": unique_ip()}))
        self.assertEqual((d.action, d.rules, d.risk_score), (ALLOW, ["UA-016"], 35))


class TestDeterminismAndIsolation(unittest.TestCase):
    def test_same_request_gives_same_decision_every_time(self):
        req = dict(query_params={"q": "1 UNION SELECT 1"})
        results = {(inspect(**req).action, inspect(**req).risk_score) for _ in range(5)}
        self.assertEqual(results, {(BLOCK, 80)})

    def test_engine_instances_are_independent(self):
        seen_a, seen_b = [], []
        a = WAFEngine(on_detection=lambda *x: seen_a.append(x))
        b = WAFEngine(on_detection=lambda *x: seen_b.append(x))
        a.inspect(make_request(query_params={"q": "<script>x</script>"}))
        self.assertEqual((len(seen_a), len(seen_b)), (1, 0))

    def test_inspect_returns_a_decision(self):
        self.assertIsInstance(inspect(), Decision)


class TestOnDetectionHookContract(unittest.TestCase):
    def test_hook_receives_the_same_request_object(self):
        captured = []
        engine = WAFEngine(on_detection=lambda req, res, dec: captured.append(req))
        req = make_request(query_params={"q": "<script>x</script>"})
        engine.inspect(req)
        self.assertIs(captured[0], req)

    def test_hook_sees_every_raw_detection_and_the_final_decision(self):
        captured = []
        engine = WAFEngine(on_detection=lambda req, res, dec: captured.append((res, dec)))
        engine.inspect(
            make_request(
                query_params={"q": "<script>x</script>"},
                form_data={"id": "1 UNION SELECT 1"},
                method="POST",
            )
        )
        results, decision = captured[0]
        self.assertEqual(decision.detections, results)
        self.assertGreaterEqual(len(results), 2)

    def test_hook_is_called_for_sub_threshold_detections_too(self):
        calls = []
        engine = WAFEngine(on_detection=lambda *a: calls.append(a))
        d = engine.inspect(make_request(method="TRACE"))  # METHOD-001, allowed
        self.assertEqual(d.action, ALLOW)
        self.assertEqual(len(calls), 1)

    def test_hook_exception_does_not_change_the_decision(self):
        def broken(*args):
            raise RuntimeError("db down")

        d = WAFEngine(on_detection=broken).inspect(
            make_request(query_params={"q": "<script>x</script>"})
        )
        self.assertEqual(d.action, BLOCK)

    def test_hook_is_not_called_when_a_detector_crashes_and_nothing_else_fires(self):
        calls = []
        with mock.patch.object(engine_module, "DETECTOR_REGISTRY", [crashing_detector]):
            WAFEngine(on_detection=lambda *a: calls.append(a)).inspect(make_request())
        self.assertEqual(calls, [])


class TestEdgeCaseInputs(unittest.TestCase):
    def test_very_long_value_is_handled(self):
        d = inspect(query_params={"q": "a" * 200_000})
        self.assertEqual(d.action, ALLOW)

    def test_payload_inside_inspection_limit_is_caught(self):
        d = inspect(query_params={"q": "a" * 8000 + "<script>x</script>"})
        self.assertEqual(d.action, BLOCK)

    def test_unicode_values_do_not_crash(self):
        d = inspect(query_params={"q": "\u65e5\u672c\u8a9e \U0001F600 \u0645\u0631\u062d\u0628\u0627"})
        self.assertEqual(d.action, ALLOW)

    def test_empty_everything(self):
        d = inspect(query_params={}, form_data={}, cookies={}, body=b"")
        self.assertEqual(d.action, ALLOW)

    def test_binary_body_does_not_crash(self):
        d = inspect(method="POST", body=bytes(range(256)))
        self.assertIn(d.action, (ALLOW, BLOCK))


class TestKnownGaps(unittest.TestCase):
    @unittest.expectedFailure
    def test_payload_past_inspection_limit_should_still_be_scanned(self):
        """KNOWN GAP: values are truncated to 8192 characters before
        matching, so an attacker can pad a payload past the limit.
        Remove the decorator if the limit is lifted or the tail is
        also scanned."""
        d = inspect(query_params={"q": "a" * 9000 + "<script>x</script>"})
        self.assertEqual(d.action, BLOCK)


if __name__ == "__main__":
    unittest.main()
