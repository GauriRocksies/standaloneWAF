"""
Validates a file's actual content by inspecting its magic bytes (file
signature) - catches files that lie about their extension/MIME type
(e.g. a .php file renamed to .jpg, or a polyglot file).
"""

# (signature bytes, offset, file type label)
MAGIC_SIGNATURES = [
    (b"\xff\xd8\xff", 0, "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", 0, "image/png"),
    (b"GIF87a", 0, "image/gif"),
    (b"GIF89a", 0, "image/gif"),
    (b"RIFF", 0, "image/webp"),  # note: needs WEBP at offset 8 too, checked separately
    (b"%PDF-", 0, "application/pdf"),
]

# Signatures that indicate something dangerous regardless of extension
DANGEROUS_SIGNATURES = [
    (b"MZ", 0, "windows executable"),        # .exe/.dll
    (b"\x7fELF", 0, "linux executable"),
    (b"#!/", 0, "shell script shebang"),
    (b"<?php", 0, "php script"),
]


def detect_file_type(file_bytes: bytes):
    if not file_bytes:
        return None
    if file_bytes[:4] == b"RIFF" and len(file_bytes) >= 12 and file_bytes[8:12] == b"WEBP":
        return "image/webp"
    for sig, offset, label in MAGIC_SIGNATURES:
        if file_bytes[offset:offset + len(sig)] == sig:
            return label
    return None


def is_dangerous_content(file_bytes: bytes):
    """Returns a description string if dangerous content is detected, else None."""
    if not file_bytes:
        return None
    head = file_bytes[:512]  # dangerous signatures live near the start
    for sig, offset, label in DANGEROUS_SIGNATURES:
        if head[offset:offset + len(sig)] == sig:
            return label
    return None


def validate_magic_bytes(uploaded_file, declared_mime: str = "") -> dict:
    """
    uploaded_file: Django UploadedFile - reads a small header chunk only
    (doesn't load the whole file into memory).
    """
    try:
        uploaded_file.seek(0)
        head = uploaded_file.read(512)
        uploaded_file.seek(0)
    except Exception:
        return {"valid": False, "reason": "could not read file for magic-byte inspection"}

    danger = is_dangerous_content(head)
    if danger:
        return {"valid": False, "reason": f"dangerous file signature detected: {danger}", "detected_type": None}

    detected_type = detect_file_type(head)
    if declared_mime and detected_type and declared_mime.lower() != detected_type.lower():
        return {
            "valid": False,
            "reason": f"declared MIME '{declared_mime}' does not match actual content '{detected_type}'",
            "detected_type": detected_type,
        }

    return {"valid": True, "reason": None, "detected_type": detected_type}