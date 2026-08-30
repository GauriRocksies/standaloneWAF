"""
verdict_service.py

Member 2's FastAPI service. Sits behind Nginx, in front of an
arbitrary origin (Flask, Django, anything). For every request:

    1. Adapt it into the Django-request shape waf.engine expects
       (waf_proxy/adapter.py).
    2. Call the EXISTING, unmodified WAFEngine.inspect().
    3. BLOCK  -> 403, request never reaches the origin.
       ALLOW  -> forward verbatim to UPSTREAM_HOST:UPSTREAM_PORT and
                 stream the origin's response back.

Origin is configured entirely through environment variables (see
_get_upstream_base_url) — nothing here references VulneraBlog/Django
by name.
"""

import logging
import os
import sys
from pathlib import Path

import django
import httpx
from asgiref.sync import sync_to_async
from fastapi import FastAPI, Request
from fastapi.responses import Response

# --------------------------------------------------------------------
# Bootstrap Django settings/ORM so the existing waf.engine +
# waf.logging.attack_logger (which write AttackLog/BlockedIP rows via
# the Django ORM) work exactly as they do inside the Django app. This
# is configuration, not a change to Member 1's code.
# --------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vulnerablog.settings")
django.setup()

from waf.engine import WAFEngine  # noqa: E402  (must follow django.setup())
from waf.constants import BLOCK, BLOCK_MESSAGE  # noqa: E402

from waf_proxy.adapter import build_adapted_request  # noqa: E402

logger = logging.getLogger("waf_proxy")

app = FastAPI(title="WAF Verdict Service")
engine = WAFEngine()

# engine.inspect() is synchronous and, via log_attack(), does Django
# ORM writes (AttackLog/BlockedIP/RuleStats). Django refuses sync ORM
# calls made directly on an async event loop thread ("You cannot call
# this from an async context"). thread_sensitive=True runs it on
# Django's single dedicated sync thread, matching how Django's own
# ASGI/async views call sync ORM code — not a change to Member 1's
# engine, just how Member 2's async handler invokes it.
inspect_async = sync_to_async(engine.inspect, thread_sensitive=True)

HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length",
}


def _get_upstream_base_url() -> str:
    host = os.environ.get("UPSTREAM_HOST", "localhost")
    port = os.environ.get("UPSTREAM_PORT", "5000")
    scheme = os.environ.get("UPSTREAM_SCHEME", "http")
    return f"{scheme}://{host}:{port}"


def _client_ip(request: Request) -> str:
    # Trust X-Real-IP / X-Forwarded-For from Nginx (set in nginx.conf);
    # fall back to the direct peer address.
    forwarded = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
async def gate(full_path: str, request: Request):
    client_ip = _client_ip(request)

    adapted = await build_adapted_request(request, client_ip)

    decision = await inspect_async(adapted)

    if decision.action == BLOCK:
        logger.warning(
            "BLOCKED %s %s from %s (risk=%d, rules=%s)",
            adapted.method, adapted.path, client_ip,
            decision.risk_score, decision.rules,
        )
        return Response(
            content=BLOCK_MESSAGE,
            status_code=403,
            media_type="text/plain",
        )

    # ALLOW -> forward to the configurable origin.
    upstream_url = f"{_get_upstream_base_url()}{request.url.path}"
    forward_headers = {
        k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP_HEADERS
    }
    forward_headers["X-Forwarded-For"] = client_ip
    forward_headers["X-Real-IP"] = client_ip
    forward_headers["X-Forwarded-Proto"] = request.headers.get("x-forwarded-proto", "http")

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            upstream_response = await client.request(
                method=request.method,
                url=upstream_url,
                params=request.query_params,
                headers=forward_headers,
                content=adapted.body,
            )
    except httpx.RequestError:
        logger.exception("Upstream origin unreachable: %s", upstream_url)
        return Response(
            content="Origin unavailable.",
            status_code=502,
            media_type="text/plain",
        )

    logger.info(
        "ALLOWED %s %s from %s -> origin %s",
        adapted.method, adapted.path, client_ip, upstream_response.status_code,
    )

    response_headers = {
        k: v for k, v in upstream_response.headers.items() if k.lower() not in HOP_BY_HOP_HEADERS
    }
    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=response_headers,
    )