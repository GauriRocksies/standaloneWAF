"""
request_adapter.py

Framework-independent request representation for the WAF core.

The original detectors were written against Django's HttpRequest and
consistently use only a handful of attributes/operations:

    request.path                    -> str
    request.method                  -> str
    request.GET.items() / .values() -> mapping-like
    request.POST.items() / .values()-> mapping-like
    request.headers.items()/.get()  -> case-insensitive mapping-like
    request.COOKIES (dict(...))     -> mapping-like
    request.FILES.keys()/.values()  -> mapping-like of upload-like objects
    request.body                    -> bytes
    request.META.get(...)           -> plain dict (WSGI-environ-shaped)

WAFRequest reproduces exactly that surface using nothing but the
standard library, so every existing detector keeps working against it
unmodified. It does not attempt to be a full HttpRequest replacement —
only what the detector pipeline actually touches (see
waf_core/detectors/*.py and waf_core/base_detector.py for the exact
operations relied upon).
"""

from collections.abc import Mapping
from typing import Any, Dict, Iterator, Optional, Union


class CaseInsensitiveDict(Mapping):
    """
    Minimal case-insensitive mapping, standing in for Django's
    HttpHeaders. Preserves the original casing of keys on iteration,
    but every lookup is case-insensitive — matching how HTTP header
    names are compared.
    """

    def __init__(self, data: Optional[Dict[str, str]] = None):
        self._store: Dict[str, tuple] = {}
        if data:
            for k, v in data.items():
                self._store[k.lower()] = (k, v)

    def __getitem__(self, key: str) -> str:
        return self._store[key.lower()][1]

    def __iter__(self) -> Iterator[str]:
        return (original for original, _ in self._store.values())

    def __len__(self) -> int:
        return len(self._store)

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and key.lower() in self._store

    def get(self, key: str, default: Any = None) -> Any:
        entry = self._store.get(key.lower())
        return entry[1] if entry is not None else default

    def items(self):
        return [(original, value) for original, value in self._store.values()]

    def values(self):
        return [value for _, value in self._store.values()]

    def keys(self):
        return [original for original, _ in self._store.values()]


class WAFUploadedFile:
    """
    Minimal stand-in for Django's UploadedFile, exposing only what
    payload_validator.py reads: .name and .content_type. If the
    caller already has an object with those attributes (e.g. a real
    Django UploadedFile, when this adapter is used from Django), it
    can be passed straight through instead — see _coerce_file below.
    """

    def __init__(self, name: str = "", content_type: str = ""):
        self.name = name
        self.content_type = content_type


def _coerce_file(name: str, value: Any) -> Any:
    """Accept a dict, a duck-typed object, or a raw value for one
    uploaded file entry, and normalize it to something exposing
    .name / .content_type — without discarding a caller-provided
    object that already has richer behavior (e.g. .read())."""
    if hasattr(value, "name") or hasattr(value, "content_type"):
        return value
    if isinstance(value, Mapping):
        return WAFUploadedFile(
            name=value.get("name", name),
            content_type=value.get("content_type", ""),
        )
    return WAFUploadedFile(name=name, content_type="")


def _normalize_body(body: Union[bytes, str, None]) -> bytes:
    """Body must always be bytes internally (matching HttpRequest.body),
    accepting str for caller convenience. Never raises: undecodable
    str input falls back to a replacement-safe encode rather than
    crashing request construction."""
    if body is None:
        return b""
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8", errors="replace")
    # Unexpected type: fail safe rather than crash construction.
    return str(body).encode("utf-8", errors="replace")


class WAFRequest:
    """
    Generic, framework-independent HTTP request representation.

    Example:

        request = WAFRequest(
            path="/search",
            method="GET",
            query_params={"q": "<script>alert(1)</script>"},
        )

    All fields are optional except `path`; sensible defaults are used
    for everything else so minimal construction (`WAFRequest(path="/")`)
    is valid.
    """

    def __init__(
        self,
        path: str = "/",
        method: str = "GET",
        query_params: Optional[Dict[str, str]] = None,
        form_data: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, Any]] = None,
        body: Union[bytes, str, None] = b"",
        meta: Optional[Dict[str, Any]] = None,
    ):
        self.path = path or "/"
        self.method = (method or "GET").upper()

        # query_params -> GET, form_data -> POST. Plain dicts are
        # sufficient: every detector only ever calls .items()/.values()
        # on these, never QueryDict-specific behavior like getlist().
        self.GET: Dict[str, str] = dict(query_params or {})
        self.POST: Dict[str, str] = dict(form_data or {})

        self.headers = CaseInsensitiveDict(headers or {})
        self.COOKIES: Dict[str, str] = dict(cookies or {})

        self.FILES: Dict[str, Any] = {
            name: _coerce_file(name, value) for name, value in (files or {}).items()
        }

        self.body: bytes = _normalize_body(body)

        # META mirrors a WSGI environ closely enough for the detector
        # pipeline: HTTP_<HEADER_NAME> for ordinary headers, plus the
        # couple of fields (CONTENT_TYPE, CONTENT_LENGTH, PATH_INFO,
        # REMOTE_ADDR) that WSGI/Django expose unprefixed. Any value
        # the caller supplies explicitly via `meta` always wins.
        self.META: Dict[str, Any] = self._build_meta(meta or {})

    def _build_meta(self, explicit_meta: Dict[str, Any]) -> Dict[str, Any]:
        derived: Dict[str, Any] = {}

        for name, value in self.headers.items():
            upper = name.upper().replace("-", "_")
            if upper in ("CONTENT_TYPE", "CONTENT_LENGTH"):
                derived.setdefault(upper, value)
            else:
                derived.setdefault(f"HTTP_{upper}", value)

        derived.setdefault("PATH_INFO", self.path)
        derived.setdefault("REMOTE_ADDR", "unknown")

        if "CONTENT_LENGTH" not in derived and "CONTENT_LENGTH" not in explicit_meta:
            derived["CONTENT_LENGTH"] = str(len(self.body))

        derived.update(explicit_meta)
        return derived

    def __repr__(self) -> str:
        return f"<WAFRequest {self.method} {self.path}>"
