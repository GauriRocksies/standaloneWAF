"""
Validates a file's declared Content-Type / MIME type against an
allow-list. This checks only the *declared* type (what the browser/
client says the file is) - pair with magic_byte_validator.py to confirm
the file's actual content matches, since declared MIME type is
trivially spoofable.
"""
DEFAULT_ALLOWED_MIME_TYPES = {
    "image/jpeg", "image/png", "image/gif", "image/webp",
    "text/plain", "application/pdf",
}

# MIME types that should basically never be accepted from an upload form
DANGEROUS_MIME_TYPES = {
    "application/x-msdownload", "application/x-sh", "application/x-executable",
    "application/x-php", "text/x-php", "application/x-httpd-php",
    "application/java-archive", "application/x-msdos-program",
}


def is_mime_allowed(mime_type: str, allowed: set = None) -> bool:
    if not mime_type:
        return False
    mime_type = mime_type.lower().strip()
    if mime_type in DANGEROUS_MIME_TYPES:
        return False
    allowed = allowed if allowed is not None else DEFAULT_ALLOWED_MIME_TYPES
    return mime_type in allowed


def validate_mime(uploaded_file, allowed: set = None) -> dict:
    """
    uploaded_file: a Django UploadedFile (has .content_type)
    Returns a result dict, similar shape to Member 2's detector results,
    so it can be logged the same way if desired.
    """
    mime_type = getattr(uploaded_file, "content_type", "") or ""
    allowed_ok = is_mime_allowed(mime_type, allowed)
    return {
        "valid": allowed_ok,
        "declared_mime": mime_type,
        "reason": None if allowed_ok else f"disallowed or dangerous MIME type: {mime_type}",
    }