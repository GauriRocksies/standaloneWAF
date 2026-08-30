"""
test_html_injection.py

HTML injection, using the existing detection surface exactly as it
behaves in the baseline project.

IMPORTANT — read before "fixing" this file:

The original project's AttackLog model lists "html_injection" as an
available attack-type choice, but there is no dedicated HTML-injection
detector or pattern group in waf/detectors/patterns.py — only specific
dangerous constructs (a <script> tag, an <iframe>, an inline event
handler like onerror=, a javascript: URI, etc.) are matched, all under
attack_type="xss". A verified check against the real (pre-extraction)
engine confirms this: a bare, otherwise inert tag like

    <h1>Injected</h1>

is NOT blocked by the baseline engine — nothing in the shared registry
matches a plain, non-dangerous tag, and per the extraction spec this
core is required to preserve existing detection behavior rather than
invent new patterns to make a test pass. See the extraction report for
this finding.

What the baseline DOES catch — and what this file tests — is HTML
injection that carries an actual payload (an event handler, a script
tag, an iframe with a javascript: URI), which is the realistic
HTML-injection threat model anyway: markup with no executable content
isn't a security-relevant "injection" in the same sense.
"""

import unittest

from waf_core import WAFEngine, WAFRequest
from waf_core.constants import ALLOW, BLOCK


class TestHTMLInjection(unittest.TestCase):
    def setUp(self):
        self.engine = WAFEngine()

    def test_dangerous_html_injection_is_blocked(self):
        decision = self.engine.inspect(
            WAFRequest(
                path="/comment",
                method="POST",
                form_data={"body": "<img src=x onerror=alert(document.cookie)>"},
            )
        )
        self.assertEqual(decision.action, BLOCK)

    def test_iframe_html_injection_is_blocked(self):
        decision = self.engine.inspect(
            WAFRequest(
                path="/comment",
                method="POST",
                form_data={"body": '<iframe src="javascript:alert(1)"></iframe>'},
            )
        )
        self.assertEqual(decision.action, BLOCK)

    def test_inert_html_tag_matches_baseline_behavior(self):
        """Documents (does not "fix") the baseline gap described above:
        a tag with no dangerous content is allowed through, both
        before and after extraction."""
        decision = self.engine.inspect(
            WAFRequest(
                path="/comment",
                method="POST",
                form_data={"body": "<h1>Injected</h1>"},
                headers={"User-Agent": "Mozilla/5.0 (compatible)"},
            )
        )
        self.assertEqual(decision.action, ALLOW)


if __name__ == "__main__":
    unittest.main()
