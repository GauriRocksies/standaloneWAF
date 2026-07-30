"""
Builds standard HTTP responses for the WAF's decisions - used by
Member 1's middleware to reject/block a request without duplicating
response-construction logic everywhere.
"""
from django.http import JsonResponse, HttpResponse


def blocked_response(reason: str = "Request blocked by WAF", status: int = 403) -> HttpResponse:
    return JsonResponse(
        {"error": "forbidden", "message": reason},
        status=status,
    )


def too_many_requests(retry_after: int = None) -> HttpResponse:
    resp = JsonResponse(
        {"error": "too_many_requests", "message": "Rate limit exceeded"},
        status=429,
    )
    if retry_after is not None:
        resp["Retry-After"] = str(retry_after)
    return resp


def malformed_request_response(reason: str = "Malformed request") -> HttpResponse:
    return JsonResponse(
        {"error": "bad_request", "message": reason},
        status=400,
    )