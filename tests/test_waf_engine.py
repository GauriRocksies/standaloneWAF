"""
test_waf_engine.py

Covers the standalone WAFEngine API, normal (legitimate) traffic
(Section 17), and the explicit Django-independence checks required by
Section 20 of the extraction spec.
"""

import ast
import os
import subprocess
import sys
import unittest

from waf_core import WAFEngine, WAFRequest
from waf_core.constants import ALLOW, BLOCK
from waf_core.detectors import DETECTOR_REGISTRY


class TestWAFEngineNormalRequests(unittest.TestCase):
    """Ordinary traffic must not be blocked."""

    def setUp(self):
        self.engine = WAFEngine()
        self.browser_headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
            )
        }

    def test_get_home(self):
        decision = self.engine.inspect(
            WAFRequest(path="/", headers=self.browser_headers)
        )
        self.assertEqual(decision.action, ALLOW)

    def test_get_products_with_id(self):
        decision = self.engine.inspect(
            WAFRequest(
                path="/products",
                query_params={"id": "123"},
                headers=self.browser_headers,
            )
        )
        self.assertEqual(decision.action, ALLOW)

    def test_post_login_normal_credentials(self):
        decision = self.engine.inspect(
            WAFRequest(
                path="/login",
                method="POST",
                form_data={"username": "alice", "password": "hunter2"},
                headers=self.browser_headers,
            )
        )
        self.assertEqual(decision.action, ALLOW)


class TestWAFEngineDecisionShape(unittest.TestCase):
    def test_decision_has_rich_fields(self):
        engine = WAFEngine()
        decision = engine.inspect(
            WAFRequest(path="/search", query_params={"q": "<script>alert(1)</script>"})
        )
        self.assertEqual(decision.action, BLOCK)
        self.assertIsInstance(decision.risk_score, int)
        self.assertIn("XSS-001", decision.rules)
        self.assertTrue(
            any(d.get("detector") == "xss_detector" for d in decision.detections)
        )

    def test_no_detections_is_zero_score_allow(self):
        engine = WAFEngine()
        decision = engine.inspect(
            WAFRequest(
                path="/",
                headers={"User-Agent": "Mozilla/5.0 (compatible)"},
            )
        )
        self.assertEqual(decision.action, ALLOW)
        self.assertEqual(decision.detections, [])


class TestOnDetectionHook(unittest.TestCase):
    """The persistence hook is optional and framework-agnostic: it's
    exactly how a Django (or any other) integration observes
    detections without waf_core depending on that integration."""

    def test_hook_called_once_with_final_decision(self):
        calls = []

        def hook(request, detector_results, decision):
            calls.append((request, list(detector_results), decision))

        engine = WAFEngine(on_detection=hook)
        engine.inspect(
            WAFRequest(
                path="/search",
                query_params={"q": "<script>alert(1)</script>"},
            )
        )

        self.assertEqual(len(calls), 1)
        _, results, decision = calls[0]
        self.assertTrue(len(results) >= 1)
        self.assertEqual(decision.action, BLOCK)

    def test_hook_not_called_for_clean_request(self):
        calls = []
        engine = WAFEngine(on_detection=lambda *a: calls.append(a))
        engine.inspect(
            WAFRequest(
                path="/",
                headers={"User-Agent": "Mozilla/5.0 (compatible)"},
            )
        )
        self.assertEqual(calls, [])

    def test_broken_hook_does_not_crash_inspect(self):
        def broken_hook(*args):
            raise RuntimeError("persistence backend down")

        engine = WAFEngine(on_detection=broken_hook)
        decision = engine.inspect(
            WAFRequest(
                path="/search",
                query_params={"q": "<script>alert(1)</script>"},
            )
        )
        self.assertEqual(decision.action, BLOCK)


class TestAllElevenDetectorsRegistered(unittest.TestCase):
    def test_registry_has_all_eleven(self):
        self.assertEqual(len(DETECTOR_REGISTRY), 11)

    def test_registry_entries_are_callable(self):
        for detector in DETECTOR_REGISTRY:
            self.assertTrue(callable(detector))


class TestDjangoIndependence(unittest.TestCase):
    """Section 20: waf_core must import and run with zero Django
    dependency, and this must be provable, not just claimed."""

    def test_import_does_not_require_django(self):
        import importlib
        import waf_core

        importlib.reload(waf_core)

    def test_engine_runs_without_importing_django(self):
        """
        Run the standalone engine in a fresh Python subprocess.

        The full unittest suite contains Django tests, so checking
        sys.modules in this process is unreliable: another test may
        already have imported Django. A subprocess gives this test a
        genuinely clean interpreter.
        """
        project_root = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..")
        )

        script = """
import sys

from waf_core import WAFEngine, WAFRequest

if "django" in sys.modules:
    raise SystemExit("Django was imported before waf_core was tested")

engine = WAFEngine()
decision = engine.inspect(WAFRequest(path="/"))

if "django" in sys.modules:
    raise SystemExit("waf_core.engine.inspect() imported Django")

print("standalone waf_core execution: OK")
"""

        env = os.environ.copy()
        env.pop("DJANGO_SETTINGS_MODULE", None)

        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=project_root,
            env=env,
            capture_output=True,
            text=True,
        )

        self.assertEqual(
            result.returncode,
            0,
            msg=(
                "Standalone waf_core subprocess failed.\n"
                f"stdout:\n{result.stdout}\n"
                f"stderr:\n{result.stderr}"
            ),
        )

        self.assertIn(
            "standalone waf_core execution: OK",
            result.stdout,
        )

    def test_no_django_imports_in_waf_core_source(self):
        """Static AST scan: no waf_core module may contain an `import
        django` or `from django...` statement anywhere in its source,
        regardless of whether that branch is reachable at runtime."""
        waf_core_dir = os.path.join(
            os.path.dirname(__file__),
            "..",
            "waf_core",
        )
        offenders = []

        for root, _dirs, files in os.walk(waf_core_dir):
            for filename in files:
                if not filename.endswith(".py"):
                    continue

                filepath = os.path.join(root, filename)

                with open(filepath, "r", encoding="utf-8") as fh:
                    tree = ast.parse(fh.read(), filename=filepath)

                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            if (
                                alias.name == "django"
                                or alias.name.startswith("django.")
                            ):
                                offenders.append(filepath)

                    elif isinstance(node, ast.ImportFrom):
                        if node.module and (
                            node.module == "django"
                            or node.module.startswith("django.")
                        ):
                            offenders.append(filepath)

        self.assertEqual(
            offenders,
            [],
            f"Django imports found in: {offenders}",
        )


if __name__ == "__main__":
    unittest.main()