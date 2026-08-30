"""
middleware.py

Main Web Application Firewall middleware — Django-facing, using the
standalone waf_core engine underneath.

Runs before every Django view: checks blocked IPs, converts the
Django request into a WAFRequest, passes it through WAFEngine, and
blocks malicious traffic. Functionally identical to the original
waf/middleware.py; the only change is that inspection now goes
through waf_core (framework-independent) instead of a Django-coupled
engine, via the adapter/persistence seam in this package.
"""

import logging

from django.http import HttpResponseForbidden

from waf.models import BlockedIP
from waf.constants import BLOCK, BLOCK_MESSAGE
from waf.logging.attack_logger import log_access
from waf_core.engine import WAFEngine
from waf_integration.django_adapter import to_waf_request
from waf_integration.persistence import make_log_attack_hook

logger = logging.getLogger(__name__)


class WAFMiddleware:
    """
    Main request interception middleware.

    AttackLog rows are written via WAFEngine's on_detection hook
    (see waf_integration/persistence.py), once per detection, after
    the decision engine has made its final call — so this middleware
    only needs to check the blocklist, run inspection, and respond.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.engine = WAFEngine(on_detection=make_log_attack_hook())

    def __call__(self, request):

        ip = request.META.get("REMOTE_ADDR", "unknown")

        # -------------------------------------------------
        # Reject requests from previously blocked IPs
        # -------------------------------------------------

        if BlockedIP.is_blocked(ip):

            logger.warning(
                "Blocked request from blacklisted IP %s",
                ip
            )

            log_access(
                ip_address=ip,
                url=request.path,
                method=request.method,
                status_code=403,
            )

            return HttpResponseForbidden(BLOCK_MESSAGE)

        # -------------------------------------------------
        # Run WAF inspection via the standalone core
        # -------------------------------------------------

        waf_request = to_waf_request(request)
        decision = self.engine.inspect(waf_request)

        if decision.action == BLOCK:

            logger.warning(
                "Blocked request from %s (risk=%d)",
                ip,
                decision.risk_score,
            )

            log_access(
                ip_address=ip,
                url=request.path,
                method=request.method,
                status_code=403,
            )

            return HttpResponseForbidden(BLOCK_MESSAGE)

        # -------------------------------------------------
        # Allow request
        # -------------------------------------------------

        response = self.get_response(request)

        log_access(
            ip_address=ip,
            url=request.path,
            method=request.method,
            status_code=response.status_code,
        )

        return response
