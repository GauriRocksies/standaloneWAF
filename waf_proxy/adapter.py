"""
adapter.py

WHY THIS FILE EXISTS (read this before assuming it shouldn't):

The Phase 1 inspection of the repository found that Member 1's WAF
core does NOT expose a standalone `WAFRequest` type or a
`request_adapter.py`. `WAFEngine.inspect(request)` and every function
in `waf/detectors/base_detector.py` (get_query_params, get_post_data,
get_json_body, get_cookies, get_headers, get_files) call Django
`HttpRequest` attributes directly: `.GET`, `.POST`, `.META`,
`.COOKIES`, `.headers`, `.FILES`, `.body`, `.path`, `.method`.

So there is nothing "generic" to plug a FastAPI request into yet.
Rather than modify waf/engine.py or waf/detectors/* (explicitly out
of scope — see the project brief, section 3), this module builds a
small duck-typed object, `AdaptedRequest`, that exposes exactly the
attributes those functions already read. No detector, no engine
logic, and no decision logic is touched or reimplemented here — this
is pure request-shape translation, Member 2's actual job.

If Member 1 later publishes a real `WAFRequest`/adapter, this file
becomes a thin translation from Starlette -> that type instead, and
nothing else in waf_proxy/ needs to change.
"""

from typing import Any, Dict

from starlette.requests import Request


class AdaptedRequest:
    """
    Duck-types just enough of django.http.HttpRequest for
    waf.engine.WAFEngine.inspect() and the detectors in
    waf/detectors/base_detector.py to work unmodified.
    """

    __slots__ = ("method", "path", "GET", "POST", "COOKIES", "META", "headers", "FILES", "body")

    def __init__(self, method, path, GET, POST, COOKIES, META, headers, FILES, body):
        self.method = method
        self.path = path
        self.GET = GET
        self.POST = POST
        self.COOKIES = COOKIES
        self.META = META
        self.headers = headers
        self.FILES = FILES
        self.body = body


def _to_wsgi_meta_key(header_name: str) -> str:
    """
    Mirror WSGI/Django's header -> META key convention, since
    bot_detector.py, user_agent.py, path_validator.py, and
    payload_validator.py read headers via request.META (e.g.
    HTTP_USER_AGENT, HTTP_X_WEBDRIVER), not via request.headers.
    """
    upper = header_name.upper().replace("-", "_")
    if upper in ("CONTENT_TYPE", "CONTENT_LENGTH"):
        return upper
    return f"HTTP_{upper}"


async def build_adapted_request(request: Request, client_ip: str) -> AdaptedRequest:
    """
    Read a Starlette request (body included, once) and produce an
    AdaptedRequest carrying everything the existing detectors expect.
    """
    body: bytes = await request.body()

    raw_headers: Dict[str, str] = dict(request.headers)
    content_type = raw_headers.get("content-type", "")

    # GET params
    get_params: Dict[str, str] = dict(request.query_params)

    # POST params — only populated for form-encoded / multipart bodies,
    # exactly like Django's request.POST (JSON bodies stay empty here;
    # base_detector.get_json_body() reads request.body directly).
    post_params: Dict[str, str] = {}
    files: Dict[str, str] = {}  # dict, not list: get_files() calls request.FILES.keys()
    if body and (
        "application/x-www-form-urlencoded" in content_type
        or "multipart/form-data" in content_type
    ):
        try:
            form = await request.form()
            for key, value in form.multi_items():
                if hasattr(value, "filename"):  # UploadFile
                    files[key] = value.filename
                else:
                    post_params[key] = value
        except Exception:
            # Malformed multipart/form body — leave POST/FILES empty
            # rather than crash the adapter; detectors still get the
            # raw body via .body for payload_validator's size/content
            # checks.
            pass

    # META — WSGI-style, since several detectors read headers through
    # request.META rather than request.headers.
    meta: Dict[str, Any] = {
        "REMOTE_ADDR": client_ip,
        "PATH_INFO": request.url.path,
        "CONTENT_TYPE": content_type,
        "CONTENT_LENGTH": raw_headers.get("content-length", str(len(body))),
    }
    for name, value in raw_headers.items():
        meta[_to_wsgi_meta_key(name)] = value

    return AdaptedRequest(
        method=request.method,
        path=request.url.path,
        GET=get_params,
        POST=post_params,
        COOKIES=dict(request.cookies),
        META=meta,
        headers=raw_headers,
        FILES=files,
        body=body,
    )