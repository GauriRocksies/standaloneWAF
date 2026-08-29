"""
standalone_example.py

Demonstrates framework-independent usage of waf_core. Run directly:

    python examples/standalone_example.py

This file imports nothing but waf_core and the standard library —
no Django involved anywhere, proving the core works against any
Python web framework (or none at all).
"""

from waf_core import WAFEngine, WAFRequest


def main():
    engine = WAFEngine()

    # A malicious request: a reflected-XSS attempt in a query param.
    malicious_request = WAFRequest(
        path="/search",
        method="GET",
        query_params={"q": "<script>alert(1)</script>"},
    )
    decision = engine.inspect(malicious_request)
    print("Malicious request:")
    print(f"  action:     {decision.action}")
    print(f"  risk_score: {decision.risk_score}")
    print(f"  rules:      {decision.rules}")
    print(f"  reasons:    {decision.reasons}")
    print()

    # A normal, legitimate request.
    normal_request = WAFRequest(
        path="/products",
        method="GET",
        query_params={"id": "123"},
        headers={"User-Agent": "Mozilla/5.0 (compatible)"},
    )
    decision = engine.inspect(normal_request)
    print("Normal request:")
    print(f"  action:     {decision.action}")
    print(f"  risk_score: {decision.risk_score}")


if __name__ == "__main__":
    main()
