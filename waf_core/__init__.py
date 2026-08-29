"""
waf_core

Standalone, framework-independent WAF detection engine, extracted
from the original Django `waf` app. Depends only on the Python
standard library — importing this package does NOT require Django to
be installed.

    from waf_core import WAFEngine, WAFRequest

    engine = WAFEngine()
    request = WAFRequest(path="/search", query_params={"q": "<script>alert(1)</script>"})
    decision = engine.inspect(request)
"""

from waf_core.engine import WAFEngine
from waf_core.request_adapter import WAFRequest

__all__ = ["WAFEngine", "WAFRequest"]
