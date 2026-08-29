"""
cache.py

Tiny in-process, thread-safe, TTL-based cache used only by
bot_detector.py's rapid-request heuristic.

The original detector used Django's `django.core.cache.cache`, which
is a Django-only dependency (and, per Section 3 of the extraction
spec, anything that currently comes from Django must be replaced with
a framework-neutral implementation). This module exposes the same
minimal surface the detector actually calls — .get(key, default) and
.set(key, value, timeout) — backed by nothing but the standard
library, so the core keeps working identically with or without
Django installed.

This is intentionally NOT a general-purpose cache: no LRU eviction,
no size cap. It's a soft, heuristic signal (see bot_detector.py's own
docstring), and entries naturally stop being written once a time
bucket rolls over, so unbounded growth under sustained traffic isn't
a practical concern for its actual use.
"""

import threading
import time
from typing import Any, Dict, Optional, Tuple


class SimpleCache:
    """Minimal thread-safe TTL cache, API-compatible with the subset
    of Django's cache.get()/cache.set() that bot_detector.py uses."""

    def __init__(self):
        self._store: Dict[str, Tuple[Any, Optional[float]]] = {}
        self._lock = threading.Lock()

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return default
            value, expires_at = entry
            if expires_at is not None and expires_at < time.monotonic():
                del self._store[key]
                return default
            return value

    def set(self, key: str, value: Any, timeout: Optional[float] = None) -> None:
        expires_at = time.monotonic() + timeout if timeout is not None else None
        with self._lock:
            self._store[key] = (value, expires_at)


# Module-level singleton, matching django.core.cache's `cache` import
# convention so bot_detector.py's usage stays a one-line import swap.
cache = SimpleCache()
