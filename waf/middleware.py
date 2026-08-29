"""
middleware.py

Backward-compatibility shim.

This module used to contain the WAF middleware implementation
directly, coupled to the old Django-only engine. The implementation
now lives in waf_integration/middleware.py, built on top of the
standalone waf_core engine (see that module's docstring for the
current architecture).

settings.py's MIDDLEWARE list still points at
'waf.middleware.WAFMiddleware', so this module re-exports the real
class from its new location rather than duplicating it -- there must
be exactly one WAF middleware implementation, not two.
"""

from waf_integration.middleware import WAFMiddleware

__all__ = ["WAFMiddleware"]
