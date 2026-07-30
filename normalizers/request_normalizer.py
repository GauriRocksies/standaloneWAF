"""
Takes a Django request and produces a normalized view of every
attacker-controlled input on it (query params, POST data, headers,
cookies, JSON body). This is what Member 1's middleware/engine should
call once per request and pass downstream, instead of every detector
re-deriving its own normalized data.
"""
from waf.logging.logger import get_logger
from normalizers.decoder import normalize_with_base64

logger = get_logger(__name__)


def _safe_json_body(request):
    try:
        import json
        if not request.body:
            return None
        return json.loads(request.body.decode("utf-8", errors="ignore"))
    except Exception:
        return None


def _flatten(value, out):
    if isinstance(value, dict):
        for v in value.values():
            _flatten(v, out)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _flatten(v, out)
    elif isinstance(value, str):
        out.append(value)


class NormalizedRequest:
    """Container for normalized request data. Attribute access mirrors
    the raw request's shape so detectors can be adapted easily."""

    def __init__(self, ip, path, method, query_params, post_data,
                 json_body, cookies, headers, raw_values, normalized_values):
        self.ip = ip
        self.path = path
        self.method = method
        self.query_params = query_params
        self.post_data = post_data
        self.json_body = json_body
        self.cookies = cookies
        self.headers = headers
        self.raw_values = raw_values          # list[str] - every raw string value found
        self.normalized_values = normalized_values  # list[str] - normalized (+base64-decoded) candidates


def normalize_request(request) -> NormalizedRequest:
    """
    Never raises - any per-field failure is logged and that field is
    left empty rather than aborting the whole request.
    """
    ip = request.META.get("REMOTE_ADDR", "")
    path = request.path
    method = request.method

    try:
        query_params = dict(request.GET)
    except Exception:
        logger.warning("failed to read GET params")
        query_params = {}

    try:
        post_data = dict(request.POST)
    except Exception:
        logger.warning("failed to read POST data")
        post_data = {}

    json_body = _safe_json_body(request)

    try:
        cookies = dict(request.COOKIES)
    except Exception:
        cookies = {}

    try:
        headers = dict(request.headers)
    except Exception:
        headers = {}

    raw_values = []
    for source in (query_params, post_data, cookies, headers):
        _flatten(source, raw_values)
    if json_body:
        _flatten(json_body, raw_values)

    normalized_values = []
    for v in raw_values:
        try:
            normalized_values.extend(normalize_with_base64(v))
        except Exception:
            continue

    return NormalizedRequest(
        ip=ip, path=path, method=method,
        query_params=query_params, post_data=post_data, json_body=json_body,
        cookies=cookies, headers=headers,
        raw_values=raw_values, normalized_values=normalized_values,
    )