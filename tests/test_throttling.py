"""Unit tests for throttling/ - pure-algorithm tests, no Django cache
backend required (TokenBucket/SlidingWindow take state as plain data)."""
import unittest

from throttling.token_bucket import TokenBucket
from throttling.sliding_window import SlidingWindow


class TestTokenBucket(unittest.TestCase):
    def test_allows_burst_up_to_capacity(self):
        bucket = TokenBucket(capacity=5, refill_rate=1.0)
        state = None
        now = 1000.0
        for _ in range(5):
            allowed, state = bucket.consume(state, now=now)
            self.assertTrue(allowed)
        allowed, state = bucket.consume(state, now=now)
        self.assertFalse(allowed)

    def test_refills_over_time(self):
        bucket = TokenBucket(capacity=2, refill_rate=1.0)
        state = None
        allowed, state = bucket.consume(state, now=0.0)
        allowed, state = bucket.consume(state, now=0.0)
        allowed, state = bucket.consume(state, now=0.0)
        self.assertFalse(allowed)
        allowed, state = bucket.consume(state, now=3.0)
        self.assertTrue(allowed)

    def test_invalid_params_raise(self):
        with self.assertRaises(ValueError):
            TokenBucket(capacity=0, refill_rate=1.0)
        with self.assertRaises(ValueError):
            TokenBucket(capacity=5, refill_rate=0)


class TestSlidingWindow(unittest.TestCase):
    def test_allows_up_to_max_requests(self):
        window = SlidingWindow(max_requests=3, window_seconds=10.0)
        timestamps = None
        for _ in range(3):
            allowed, timestamps = window.allow(timestamps, now=100.0)
            self.assertTrue(allowed)
        allowed, timestamps = window.allow(timestamps, now=100.0)
        self.assertFalse(allowed)

    def test_old_requests_expire_out_of_window(self):
        window = SlidingWindow(max_requests=2, window_seconds=5.0)
        timestamps = None
        allowed, timestamps = window.allow(timestamps, now=0.0)
        allowed, timestamps = window.allow(timestamps, now=1.0)
        allowed, timestamps = window.allow(timestamps, now=2.0)
        self.assertFalse(allowed)
        allowed, timestamps = window.allow(timestamps, now=10.0)
        self.assertTrue(allowed)


if __name__ == "__main__":
    unittest.main()