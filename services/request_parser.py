"""
Extracts a clean, consistent dict of request data - this is likely what
Member 1's middleware calls right at the top of process_request, before
handing off to detectors/normalizers.
"""
from waf.logging.logger import get_logger

logger = get_logger(__name__)


def parse_request(request) -> dict:
    """Never raises - every field is wrapped so one bad field doesn't
    take down the whole parse."""

    def _safe(fn, default):
        try:
            return fn()
        except Exception:
            return default

    return {
        "ip": _safe(lambda: request.META.get("REMOTE_ADDR", ""), ""),
        "method": _safe(lambda: request.method, ""),
        "path": _safe(lambda: request.path, ""),
        "full_url": _safe(lambda: request.build_absolute_uri(), ""),
        "query_params": _safe(lambda: dict(request.GET), {}),
        "post_data": _safe(lambda: dict(request.POST), {}),
        "cookies": _safe(lambda: dict(request.COOKIES), {}),
        "headers": _safe(lambda: dict(request.headers), {}),
        "user_agent": _safe(lambda: request.META.get("HTTP_USER_AGENT", ""), ""),
        "content_type": _safe(lambda: request.content_type, ""),
        "content_length": _safe(lambda: int(request.META.get("CONTENT_LENGTH") or 0), 0),
        "files": _safe(lambda: list(request.FILES.keys()), []),
    }