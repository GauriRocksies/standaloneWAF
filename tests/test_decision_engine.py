"""
test_decision_engine.py

DecisionEngine in isolation: threshold, aggregation, the critical
override, capping and de-duplication, using hand-built detector results
so no detector behaviour is involved.
"""

import unittest

from waf_core.constants import ALLOW, BLOCK, DEFAULT_BLOCK_THRESHOLD
from waf_core.decision_engine import Decision, DecisionEngine

from tests.helpers import add_cases


def result(score, severity="medium", rule="R-1", detector="d1", reason="why"):
    return {
        "attack": "other",
        "score": score,
        "severity": severity,
        "reason": reason,
        "rule": rule,
        "detector": detector,
    }


# (case_id, list of scores, expected action, expected summed score)
THRESHOLD_CASES = [
    ("single_69_allows", [69], ALLOW, 69),
    ("single_70_blocks", [70], BLOCK, 70),
    ("single_71_blocks", [71], BLOCK, 71),
    ("two_35s_block", [35, 35], BLOCK, 70),
    ("two_34s_allow", [34, 34], ALLOW, 68),
    ("three_small_scores_sum", [20, 25, 30], BLOCK, 75),
    ("zero_score_allows", [0], ALLOW, 0),
    ("sum_is_capped_at_100", [60, 60, 60], BLOCK, 100),
]


def _threshold(self, scores, action, total):
    results = [result(s, rule=f"R-{i}", detector=f"d{i}") for i, s in enumerate(scores)]
    decision = DecisionEngine().decide(results)
    self.assertEqual(decision.action, action)
    self.assertEqual(decision.risk_score, total)


class TestThreshold(unittest.TestCase):
    pass


add_cases(TestThreshold, "test", THRESHOLD_CASES, _threshold)


class TestDecisionEngine(unittest.TestCase):
    def test_default_threshold_is_70(self):
        self.assertEqual(DEFAULT_BLOCK_THRESHOLD, 70)
        self.assertEqual(DecisionEngine().threshold, 70)

    def test_no_results_means_allow_with_empty_fields(self):
        d = DecisionEngine().decide([])
        self.assertEqual(d.action, ALLOW)
        self.assertEqual(d.risk_score, 0)
        self.assertEqual((d.detections, d.reasons, d.rules, d.detectors), ([], [], [], []))

    def test_critical_severity_blocks_even_with_tiny_score(self):
        d = DecisionEngine().decide([result(5, severity="critical")])
        self.assertEqual(d.action, BLOCK)
        self.assertEqual(d.risk_score, 5)

    def test_high_severity_alone_does_not_force_a_block(self):
        d = DecisionEngine().decide([result(65, severity="high")])
        self.assertEqual(d.action, ALLOW)

    def test_custom_threshold_raises_the_bar(self):
        d = DecisionEngine(threshold=90).decide([result(80, severity="high")])
        self.assertEqual(d.action, ALLOW)

    def test_custom_threshold_lowers_the_bar(self):
        d = DecisionEngine(threshold=10).decide([result(15, severity="low")])
        self.assertEqual(d.action, BLOCK)

    def test_rules_reasons_and_detectors_are_deduplicated_in_order(self):
        d = DecisionEngine().decide(
            [
                result(30, rule="A", detector="x", reason="r1"),
                result(30, rule="B", detector="y", reason="r2"),
                result(30, rule="A", detector="x", reason="r1"),
            ]
        )
        self.assertEqual(d.rules, ["A", "B"])
        self.assertEqual(d.detectors, ["x", "y"])
        self.assertEqual(d.reasons, ["r1", "r2"])

    def test_detections_are_passed_through_unchanged(self):
        results = [result(10), result(20, rule="R-2")]
        d = DecisionEngine().decide(results)
        self.assertEqual(d.detections, results)

    def test_missing_score_counts_as_zero(self):
        d = DecisionEngine().decide([{"severity": "low", "rule": "X"}])
        self.assertEqual(d.risk_score, 0)
        self.assertEqual(d.action, ALLOW)
        self.assertEqual(d.rules, ["X"])

    def test_numeric_string_score_is_coerced(self):
        d = DecisionEngine().decide([result("75")])
        self.assertEqual(d.risk_score, 75)
        self.assertEqual(d.action, BLOCK)

    def test_missing_reason_rule_and_detector_are_skipped(self):
        d = DecisionEngine().decide([{"score": 10, "severity": "low"}])
        self.assertEqual((d.reasons, d.rules, d.detectors), ([], [], []))

    def test_decision_dataclass_defaults(self):
        d = Decision(action=ALLOW, risk_score=0)
        self.assertEqual((d.detections, d.reasons, d.rules, d.detectors), ([], [], [], []))


if __name__ == "__main__":
    unittest.main()
