"""
Token Bucket rate limiting algorithm.

Allows bursts up to `capacity` tokens, refilling at `refill_rate` tokens/sec.
Each IP (or key) gets its own bucket, stored via an injected cache backend
(see cache_manager.py) so state is shared across worker processes.
"""
import time


class TokenBucket:
    def __init__(self, capacity: int, refill_rate: float):
        """
        capacity: max tokens the bucket can hold (max burst size)
        refill_rate: tokens added per second
        """
        if capacity <= 0:
            raise ValueError("capacity must be > 0")
        if refill_rate <= 0:
            raise ValueError("refill_rate must be > 0")
        self.capacity = capacity
        self.refill_rate = refill_rate

    def _refill(self, state: dict, now: float) -> dict:
        elapsed = max(0.0, now - state["last_refill"])
        new_tokens = elapsed * self.refill_rate
        tokens = min(self.capacity, state["tokens"] + new_tokens)
        return {"tokens": tokens, "last_refill": now}

    def consume(self, state: dict = None, now: float = None, cost: int = 1):
        """
        state: previous {"tokens": float, "last_refill": float} or None for a fresh bucket
        Returns (allowed: bool, new_state: dict) - caller is responsible for
        persisting new_state (e.g. via cache_manager).
        """
        now = now if now is not None else time.time()
        if state is None:
            state = {"tokens": float(self.capacity), "last_refill": now}

        state = self._refill(state, now)

        if state["tokens"] >= cost:
            state["tokens"] -= cost
            return True, state
        return False, state