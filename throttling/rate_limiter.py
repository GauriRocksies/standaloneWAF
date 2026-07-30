"""
Public interface for rate limiting - this is what Member 1's middleware
should call directly.

Combines TokenBucket (smooth, burst-tolerant limiting - good default) or
SlidingWindow (stricter, precise-window limiting) with CacheManager for
shared cross-process storage keyed by IP.
"""
from waf.logging.logger import get_logger
from throttling.token_bucket import TokenBucket
from throttling.sliding_window import SlidingWindow
from throttling.cache_manager import CacheManager

logger = get_logger(__name__)


class RateLimiter:
    def __init__(
        self,
        strategy: str = "token_bucket",
        capacity: int = 30,
        refill_rate: float = 5.0,
        window_seconds: float = 10.0,
        max_requests: int = 30,
        cache_manager: CacheManager = None,
    ):
        """
        strategy: "token_bucket" or "sliding_window"
        Token bucket params (capacity, refill_rate) used when strategy == "token_bucket"
        Sliding window params (window_seconds, max_requests) used otherwise
        """
        if strategy not in ("token_bucket", "sliding_window"):
            raise ValueError("strategy must be 'token_bucket' or 'sliding_window'")
        self.strategy = strategy
        default_ttl = int(window_seconds * 2) if strategy == "sliding_window" else 60
        self.cache = cache_manager or CacheManager(prefix="ratelimit", default_timeout=default_ttl)

        if strategy == "token_bucket":
            self._algo = TokenBucket(capacity=capacity, refill_rate=refill_rate)
        else:
            self._algo = SlidingWindow(max_requests=max_requests, window_seconds=window_seconds)

    def is_allowed(self, ip: str) -> bool:
        """
        The one function Member 1's middleware needs:
            if not rate_limiter.is_allowed(ip):
                return response_builder.too_many_requests()
        Fails open (returns True) if the cache backend is unavailable -
        rate limiting degrading gracefully is preferable to blocking all
        traffic when infra hiccups.
        """
        if not ip:
            return True

        try:
            if self.strategy == "token_bucket":
                state = self.cache.get(ip)
                allowed, new_state = self._algo.consume(state)
                self.cache.set(ip, new_state)
                return allowed
            else:
                timestamps = self.cache.get(ip)
                allowed, new_timestamps = self._algo.allow(timestamps)
                self.cache.set(ip, new_timestamps)
                return allowed
        except Exception:
            logger.warning("rate limiter failed for ip=%s, failing open", ip)
            return True

    def reset(self, ip: str) -> None:
        """Manually clear an IP's rate-limit state (e.g. after unblocking)."""
        self.cache.delete(ip)


# Sensible default instance modules can import directly, e.g.:
#   from throttling.rate_limiter import default_limiter
#   default_limiter.is_allowed(ip)
default_limiter = RateLimiter(strategy="token_bucket", capacity=30, refill_rate=5.0)