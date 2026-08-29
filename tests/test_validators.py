"""Unit tests for validators/ - uses a minimal fake file object so
these run without Django's UploadedFile / test client."""
import io
import unittest

from validators.mime_validator import is_mime_allowed, validate_mime
from validators.magic_byte_validator import detect_file_type, is_dangerous_content, validate_magic_bytes
from validators.extension_validator import get_extension, has_double_extension, validate_extension


class FakeUploadedFile:
    """Minimal stand-in for django.core.files.uploadedfile.UploadedFile."""
    def __init__(self, content: bytes, content_type: str = ""):
        self._buf = io.BytesIO(content)
        self.content_type = content_type

    def seek(self, pos):
        self._buf.seek(pos)

    def read(self, n=-1):
        return self._buf.read(n)


class TestMimeValidator(unittest.TestCase):
    def test_allowed_mime(self):
        self.assertTrue(is_mime_allowed("image/png"))

    def test_dangerous_mime_rejected(self):
        self.assertFalse(is_mime_allowed("application/x-msdownload"))

    def test_validate_mime_result_shape(self):
        f = FakeUploadedFile(b"data", content_type="image/png")
        result = validate_mime(f)
        self.assertTrue(result["valid"])


class TestMagicByteValidator(unittest.TestCase):
    def test_detects_png_signature(self):
        png_header = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
        self.assertEqual(detect_file_type(png_header), "image/png")

    def test_detects_dangerous_php(self):
        self.assertEqual(is_dangerous_content(b"<?php system($_GET['c']); ?>"), "php script")

    def test_mismatched_declared_type_flagged(self):
        f = FakeUploadedFile(b"<?php echo 1; ?>", content_type="image/jpeg")
        result = validate_magic_bytes(f, declared_mime="image/jpeg")
        self.assertFalse(result["valid"])


class TestExtensionValidator(unittest.TestCase):
    def test_allowed_extension(self):
        result = validate_extension("photo.jpg")
        self.assertTrue(result["valid"])

    def test_dangerous_extension_rejected(self):
        result = validate_extension("shell.php")
        self.assertFalse(result["valid"])

    def test_double_extension_flagged(self):
        self.assertTrue(has_double_extension("shell.php.jpg"))

    def test_get_extension(self):
        self.assertEqual(get_extension("archive.tar.gz"), ".gz")


if __name__ == "__main__":
    unittest.main()
    