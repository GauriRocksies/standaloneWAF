"""
Lightweight GeoIP lookup service. Uses the free ip-api.com HTTP API by
default (no API key needed, rate-limited to 45 req/min - fine for a
university project, NOT for production). Swap in MaxMind GeoLite2 /
geoip2 for a real deployment; the interface (lookup(ip) -> dict) is
designed so that swap doesn't require changing callers.

Fails open: on any network/parsing error, returns a dict with
country=None rather than raising, so a GeoIP outage never blocks
request processing.
"""
import json
import urllib.request
import urllib.error

from waf.logging.logger import get_logger

logger = get_logger(__name__)

_PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "172.16.", "172.17.", "172.18.",
                      "172.19.", "172.2", "172.3", "0.")


def _is_private_ip(ip: str) -> bool:
    return ip.startswith(_PRIVATE_PREFIXES) or ip == "localhost"


def lookup(ip: str, timeout: float = 2.0) -> dict:
    """
    Returns: {"ip": ..., "country": ..., "country_code": ..., "city": ...,
              "is_private": bool}
    """
    empty = {"ip": ip, "country": None, "country_code": None, "city": None, "is_private": False}

    if not ip:
        return empty

    if _is_private_ip(ip):
        return {**empty, "is_private": True}

    url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if data.get("status") != "success":
            return empty
        return {
            "ip": ip,
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "city": data.get("city"),
            "is_private": False,
        }
    except Exception:
        logger.warning("geoip lookup failed for ip=%s, failing open", ip)
        return empty