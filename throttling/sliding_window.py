"""
Sliding window counter rate limiting.

Tracks request timestamps in a window of `window_seconds`; allows up to
`max_requests` within that rolling window. More precise than a fixed
window (no burst-at-boundary problem) at the cost of storing a timestamp
list per key instead of a single counter.
"""
import time


class SlidingWindow:
    def __init__(self, max_requests: int, window_seconds: float):
        if max_requests <= 0:
            raise ValueError("max_requests must be > 0")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        self.max_requests = max_requests
        self.window_seconds = window_seconds

    def allow(self, timestamps: list = None, now: float = None):
        """
        timestamps: previous list of request times (epoch seconds) or None
        Returns (allowed, new_timestamps) - caller persists new_timestamps.
        """
        now = now if now is not None else time.time()
        timestamps = timestamps or []

        cutoff = now - self.window_seconds
        timestamps = [t for t in timestamps if t > cutoff]

        if len(timestamps) < self.max_requests:
            timestamps.append(now)
            return True, timestamps
        return False, timestamps
    