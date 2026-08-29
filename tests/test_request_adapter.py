"""
test_request_adapter.py

Verifies WAFRequest's framework-independent surface: every attribute
and operation the detector pipeline actually relies on (see
Section 19 of the extraction spec). No Django involved anywhere.
"""

import unittest

from waf_core.request_adapter import WAFRequest


class TestMinimalRequest(unittest.TestCase):
    def test_path_only_is_valid(self):
        request = WAFRequest(path="/")
        self.assertEqual(request.path, "/")
        self.assertEqual(request.method, "GET")

    def test_no_args_is_valid(self):
        request = WAFRequest()
        self.assertEqual(request.path, "/")
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.GET, {})
        self.assertEqual(request.POST, {})
        self.assertEqual(request.COOKIES, {})
        self.assertEqual(request.FILES, {})
        self.assertEqual(request.body, b"")


class TestGetRequest(unittest.TestCase):
    def test_path_method_get(self):
        request = WAFRequest(
            path="/search", method="get", query_params={"q": "hello"}
        )
        self.assertEqual(request.path, "/search")
        self.assertEqual(request.method, "GET")  # normalized to uppercase
        self.assertEqual(dict(request.GET.items()), {"q": "hello"})


class TestPostRequest(unittest.TestCase):
    def test_post_data(self):
        request = WAFRequest(
            path="/login", method="POST", form_data={"username": "alice"}
        )
        self.assertEqual(dict(request.POST.items()), {"username": "alice"})


class TestHeaders(unittest.TestCase):
    def test_headers_present_and_case_insensitive(self):
        request = WAFRequest(headers={"User-Agent": "TestBrowser/1.0"})
        self.assertEqual(request.headers.get("User-Agent"), "TestBrowser/1.0")
        # Case-insensitive lookup, matching Django's HttpHeaders behavior.
        self.assertEqual(request.headers.get("user-agent"), "TestBrowser/1.0")
        self.assertIn(("User-Agent", "TestBrowser/1.0"), request.headers.items())

    def test_headers_populate_meta(self):
        request = WAFRequest(headers={"User-Agent": "TestBrowser/1.0"})
        self.assertEqual(request.META.get("HTTP_USER_AGENT"), "TestBrowser/1.0")

    def test_content_type_header_maps_unprefixed(self):
        request = WAFRequest(headers={"Content-Type": "application/json"})
        self.assertEqual(request.META.get("CONTENT_TYPE"), "application/json")
        self.assertNotIn("HTTP_CONTENT_TYPE", request.META)


class TestCookies(unittest.TestCase):
    def test_cookies_dict_like(self):
        request = WAFRequest(cookies={"session": "abc123"})
        self.assertEqual(dict(request.COOKIES), {"session": "abc123"})


class TestFiles(unittest.TestCase):
    def test_files_dict_and_upload_attrs(self):
        request = WAFRequest(
            files={"avatar": {"name": "shell.php", "content_type": "application/x-httpd-php"}}
        )
        self.assertIn("avatar", request.FILES.keys())
        uploaded = request.FILES["avatar"]
        self.assertEqual(uploaded.name, "shell.php")
        self.assertEqual(uploaded.content_type, "application/x-httpd-php")


class TestBody(unittest.TestCase):
    def test_bytes_body(self):
        request = WAFRequest(body=b"username=test")
        self.assertEqual(request.body, b"username=test")

    def test_str_body_is_coerced_to_bytes(self):
        request = WAFRequest(body="username=test")
        self.assertEqual(request.body, b"username=test")


class TestMeta(unittest.TestCase):
    def test_meta_explicit_wins_over_derived(self):
        request = WAFRequest(
            headers={"User-Agent": "header-value"},
            meta={"HTTP_USER_AGENT": "explicit-value", "REMOTE_ADDR": "1.2.3.4"},
        )
        self.assertEqual(request.META["HTTP_USER_AGENT"], "explicit-value")
        self.assertEqual(request.META["REMOTE_ADDR"], "1.2.3.4")

    def test_meta_default_remote_addr(self):
        request = WAFRequest()
        self.assertEqual(request.META.get("REMOTE_ADDR"), "unknown")


if __name__ == "__main__":
    unittest.main()
