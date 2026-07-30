"""
middleware.py

Main Web Application Firewall middleware.

Runs before every Django view, checks blocked IPs,
passes the request through the WAF engine, and
blocks malicious traffic.
"""

import logging

from django.http import HttpResponseForbidden

from waf.engine import WAFEngine
from waf.models import BlockedIP, AttackLog
from waf.constants import BLOCK, BLOCK_MESSAGE
from waf.logging.attack_logger import log_access

logger = logging.getLogger(__name__)


class WAFMiddleware:
    """
    Main request interception middleware.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.engine = WAFEngine()

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

            # Update latest attack log if one exists
            latest = (
                AttackLog.objects
                .filter(
                    ip_address=ip,
                    url=request.path,
                    blocked=False,
                )
                .order_by("-timestamp")
                .first()
            )

            if latest:
                latest.blocked = True
                latest.response_code = 403
                latest.save(update_fields=["blocked", "response_code"])

            log_access(
                ip_address=ip,
                url=request.path,
                method=request.method,
                status_code=403,
            )

            return HttpResponseForbidden(BLOCK_MESSAGE)

        # -------------------------------------------------
        # Run WAF inspection
        # -------------------------------------------------

        decision = self.engine.inspect(request)

        if decision.action == BLOCK:

            logger.warning(
                "Blocked request from %s (risk=%d)",
                ip,
                decision.risk_score,
            )

            # Update the attack log created by the detector
            latest = (
                AttackLog.objects
                .filter(
                    ip_address=ip,
                    url=request.path,
                    blocked=False,
                )
                .order_by("-timestamp")
                .first()
            )

            if latest:
                latest.blocked = True
                latest.response_code = 403
                latest.save(update_fields=["blocked", "response_code"])

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