"""Unit tests for normalizers/ - no Django request object needed for
the string-level decoders."""
import unittest

from normalizers.url_decoder import url_decode_repeated
from normalizers.unicode_decoder import decode_js_unicode_escapes, strip_zero_width, normalize_form
from normalizers.base64_decoder import looks_like_base64, try_decode_base64
from normalizers.decoder import normalize, normalize_with_base64


class TestUrlDecoder(unittest.TestCase):
    def test_single_encoding(self):
        self.assertEqual(url_decode_repeated("%3Cscript%3E"), "<script>")

    def test_double_encoding(self):
        self.assertEqual(url_decode_repeated("%253Cscript%253E"), "<script>")

    def test_non_string_passthrough(self):
        self.assertIsNone(url_decode_repeated(None))


class TestUnicodeDecoder(unittest.TestCase):
    def test_js_unicode_escape(self):
        self.assertEqual(decode_js_unicode_escapes("\\u003Cscript\\u003E"), "<script>")

    def test_strip_zero_width(self):
        self.assertEqual(strip_zero_width("sc\u200bript"), "script")

    def test_fullwidth_normalization(self):
        result = normalize_form("\uff1cscript\uff1e")
        self.assertEqual(result, "<script>")


class TestBase64Decoder(unittest.TestCase):
    def test_detects_valid_base64(self):
        self.assertTrue(looks_like_base64("PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="))

    def test_rejects_short_strings(self):
        self.assertFalse(looks_like_base64("abc"))

    def test_decodes_correctly(self):
        is_b64, decoded = try_decode_base64("PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==")
        self.assertTrue(is_b64)
        self.assertEqual(decoded, "<script>alert(1)</script>")

    def test_non_base64_returns_false(self):
        is_b64, decoded = try_decode_base64("hello world, not base64!")
        self.assertFalse(is_b64)
        self.assertIsNone(decoded)


class TestDecoderPipeline(unittest.TestCase):
    def test_combined_normalize(self):
        result = normalize("%3Cscript%3E")
        self.assertEqual(result, "<script>")

    def test_normalize_with_base64_includes_decoded_candidate(self):
        candidates = normalize_with_base64("PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==")
        self.assertIn("<script>alert(1)</script>", candidates)


if __name__ == "__main__":
    unittest.main()