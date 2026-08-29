"""
django_adapter.py

The ONLY place in this project that converts a Django HttpRequest
into a framework-independent waf_core.WAFRequest. This is the seam
Section 15 of the extraction spec calls for: waf_core knows nothing
about Django, and this module is the (small, isolated) piece that
knows about both sides.

Usage (see middleware.py):

    from waf_integration.django_adapter import to_waf_request

    waf_request = to_waf_request(django_request)
    decision = engine.inspect(waf_request)
"""

import logging

from waf_core.request_adapter import WAFRequest

logger = logging.getLogger("waf")


def to_waf_request(django_request) -> WAFRequest:
    """
    Build a WAFRequest from a Django HttpRequest, preserving exactly
    the data the detector pipeline used to read directly off the
    Django request.

    request.META is passed through as-is (not re-derived from
    headers) since it already has the exact WSGI-environ shape the
    detectors expect (HTTP_USER_AGENT, REMOTE_ADDR, CONTENT_TYPE,
    CONTENT_LENGTH, PATH_INFO, ...) straight from Django/WSGI — more
    reliable than reconstructing it from request.headers.
    """
    try:
        body = django_request.body
    except Exception:
        # Body already consumed by the multipart parser, or otherwise
        # unavailable — matches the original detectors' own
        # defensive handling of request.body access failures.
        logger.debug("could not read request.body for WAF inspection", exc_info=True)
        body = b""

    return WAFRequest(
        path=django_request.path,
        method=django_request.method,
        query_params={k: v for k, v in django_request.GET.items()},
        form_data={k: v for k, v in django_request.POST.items()},
        headers={k: v for k, v in django_request.headers.items()},
        cookies=dict(django_request.COOKIES),
        files={k: v for k, v in django_request.FILES.items()},
        body=body,
        meta=dict(django_request.META),
    )
