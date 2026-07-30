"""Validates file extension against an allow-list, and flags
double-extension tricks (e.g. "shell.php.jpg")."""
import os

DEFAULT_ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".pdf", ".txt"}

DANGEROUS_EXTENSIONS = {
    ".php", ".php3", ".php4", ".php5", ".phtml", ".asp", ".aspx", ".jsp",
    ".exe", ".sh", ".bat", ".cmd", ".dll", ".py", ".rb", ".pl", ".cgi", ".htaccess",
}


def get_extension(filename: str) -> str:
    return os.path.splitext(filename)[1].lower()


def has_double_extension(filename: str) -> bool:
    """Flags e.g. 'shell.php.jpg' - multiple dot-separated segments where
    any non-final segment is itself a recognized/dangerous extension."""
    parts = filename.lower().split(".")
    if len(parts) <= 2:
        return False
    for part in parts[1:-1]:
        if f".{part}" in DANGEROUS_EXTENSIONS:
            return True
    return False


def validate_extension(filename: str, allowed: set = None) -> dict:
    allowed = allowed if allowed is not None else DEFAULT_ALLOWED_EXTENSIONS
    ext = get_extension(filename)

    if ext in DANGEROUS_EXTENSIONS:
        return {"valid": False, "reason": f"dangerous extension: {ext}"}

    if has_double_extension(filename):
        return {"valid": False, "reason": f"suspicious double extension in filename: {filename}"}

    if ext not in allowed:
        return {"valid": False, "reason": f"extension not in allow-list: {ext}"}

    return {"valid": True, "reason": None}