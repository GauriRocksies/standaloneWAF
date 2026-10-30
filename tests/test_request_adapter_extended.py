"""
test_request_adapter_extended.py

WAFRequest / CaseInsensitiveDict / WAFUploadedFile edge cases, plus the
Django-to-WAFRequest bridge exercised with a duck-typed request (no
Django install or settings needed).
"""

import unittest
from types import SimpleNamespace

from waf_core.request_adapter import CaseInsensitiveDict, WAFRequest, WAFUploadedFile
from waf_integration.django_adapter import to_waf_request


class TestCaseInsensitiveDict(unittest.TestCase):
    def setUp(self):
        self.d = CaseInsensitiveDict({"Content-Type": "text/html", "X-Test": "1"})

    def test_lookup_ignores_case(self):
        self.assertEqual(self.d["content-type"], "text/html")
        self.assertEqual(self.d["CONTENT-TYPE"], "text/html")

    def test_iteration_preserves_original_casing(self):
        self.assertEqual(list(self.d), ["Content-Type", "X-Test"])

    def test_len(self):
        self.assertEqual(len(self.d), 2)

    def test_contains_ignores_case_and_rejects_non_strings(self):
        self.assertIn("x-test", self.d)
        self.assertNotIn("x-missing", self.d)
        self.assertNotIn(5, self.d)

    def test_missing_key_raises_keyerror(self):
        with self.assertRaises(KeyError):
            self.d["nope"]

    def test_get_with_default(self):
        self.assertEqual(self.d.get("nope", "fallback"), "fallback")
        self.assertIsNone(self.d.get("nope"))

    def test_none_input_gives_empty_mapping(self):
        self.assertEqual(len(CaseInsensitiveDict(None)), 0)

    def test_values_and_keys(self):
        self.assertEqual(self.d.values(), ["text/html", "1"])
        self.assertEqual(self.d.keys(), ["Content-Type", "X-Test"])

    def test_later_duplicate_with_different_case_replaces_earlier(self):
        d = CaseInsensitiveDict({"A": "1", "a": "2"})
        self.assertEqual(len(d), 1)
        self.assertEqual(d["A"], "2")


class TestWAFRequestConstruction(unittest.TestCase):
    def test_empty_path_becomes_root(self):
        self.assertEqual(WAFRequest(path="").path, "/")

    def test_none_method_becomes_get(self):
        self.assertEqual(WAFRequest(method=None).method, "GET")

    def test_input_dicts_are_copied(self):
        params = {"q": "1"}
        req = WAFRequest(query_params=params)
        params["q"] = "changed"
        self.assertEqual(req.GET["q"], "1")

    def test_unicode_str_body_is_utf8_encoded(self):
        self.assertEqual(WAFRequest(body="caf\u00e9").body, "caf\u00e9".encode("utf-8"))

    def test_none_body_becomes_empty_bytes(self):
        self.assertEqual(WAFRequest(body=None).body, b"")

    def test_unexpected_body_type_is_stringified_not_raised(self):
        self.assertEqual(WAFRequest(body=123).body, b"123")

    def test_repr_shows_method_and_path(self):
        self.assertEqual(repr(WAFRequest(path="/x", method="post")), "<WAFRequest POST /x>")


class TestWAFRequestMeta(unittest.TestCase):
    def test_content_length_is_derived_from_body(self):
        self.assertEqual(WAFRequest(body=b"12345").META["CONTENT_LENGTH"], "5")

    def test_content_length_header_wins_over_body_length(self):
        req = WAFRequest(headers={"Content-Length": "99"}, body=b"12345")
        self.assertEqual(req.META["CONTENT_LENGTH"], "99")

    def test_explicit_meta_wins_over_everything(self):
        req = WAFRequest(headers={"Content-Length": "99"}, meta={"CONTENT_LENGTH": "7"})
        self.assertEqual(req.META["CONTENT_LENGTH"], "7")

    def test_path_info_defaults_to_path(self):
        self.assertEqual(WAFRequest(path="/a/b").META["PATH_INFO"], "/a/b")

    def test_hyphenated_header_becomes_wsgi_key(self):
        req = WAFRequest(headers={"X-Forwarded-For": "1.2.3.4"})
        self.assertEqual(req.META["HTTP_X_FORWARDED_FOR"], "1.2.3.4")


class TestUploadedFiles(unittest.TestCase):
    def test_dict_entry_without_name_uses_field_name(self):
        req = WAFRequest(files={"avatar": {"content_type": "image/png"}})
        self.assertEqual(req.FILES["avatar"].name, "avatar")

    def test_non_mapping_entry_gets_blank_content_type(self):
        req = WAFRequest(files={"doc": "raw"})
        self.assertEqual(req.FILES["doc"].content_type, "")

    def test_duck_typed_object_is_passed_through_unchanged(self):
        upload = WAFUploadedFile(name="a.txt", content_type="text/plain")
        req = WAFRequest(files={"f": upload})
        self.assertIs(req.FILES["f"], upload)


def fake_django_request(**overrides):
    attrs = dict(
        path="/search",
        method="GET",
        GET={"q": "hello"},
        POST={},
        headers={"User-Agent": "Mozilla/5.0 test-browser"},
        COOKIES={"sid": "abc"},
        FILES={},
        META={"REMOTE_ADDR": "203.0.113.7", "HTTP_USER_AGENT": "Mozilla/5.0 test-browser"},
        body=b"payload",
    )
    attrs.update(overrides)
    return SimpleNamespace(**attrs)


class TestDjangoBridge(unittest.TestCase):
    def test_basic_fields_are_copied(self):
        req = to_waf_request(fake_django_request())
        self.assertEqual((req.path, req.method), ("/search", "GET"))
        self.assertEqual(req.GET, {"q": "hello"})
        self.assertEqual(req.COOKIES, {"sid": "abc"})
        self.assertEqual(req.body, b"payload")

    def test_django_meta_is_passed_through_not_rederived(self):
        req = to_waf_request(fake_django_request())
        self.assertEqual(req.META["REMOTE_ADDR"], "203.0.113.7")

    def test_unreadable_body_falls_back_to_empty(self):
        class Unreadable(SimpleNamespace):
            @property
            def body(self):
                raise OSError("stream already consumed")

        raw = fake_django_request()
        data = {k: v for k, v in vars(raw).items() if k != "body"}
        req = to_waf_request(Unreadable(**data))
        self.assertEqual(req.body, b"")

    def test_post_data_is_copied(self):
        req = to_waf_request(fake_django_request(method="POST", POST={"u": "alice"}))
        self.assertEqual(req.POST, {"u": "alice"})

    def test_bridged_request_is_inspectable(self):
        from waf_core import WAFEngine
        from waf_core.constants import BLOCK

        req = to_waf_request(fake_django_request(GET={"q": "<script>x</script>"}))
        self.assertEqual(WAFEngine().inspect(req).action, BLOCK)


if __name__ == "__main__":
    unittest.main()
