"""
Thin wrapper around Django's cache framework used as shared state storage
for throttling (and reusable anywhere else a lightweight get/set/incr
with TTL is needed).

Fails open by design: if the cache backend is unavailable/misconfigured,
get() returns the provided default and set() silently no-ops, rather than
raising and taking down request handling. This mirrors the "never crash"
philosophy Member 2 used in their detectors.
"""
from waf.logging.logger import get_logger

logger = get_logger(__name__)

try:
    from django.core.cache import cache as django_cache
except Exception:  # pragma: no cover - Django not configured yet
    django_cache = None


class CacheManager:
    def __init__(self, prefix: str = "waf", default_timeout: int = 300, backend=None):
        """
        prefix: namespace prepended to every key, so different modules
                (throttling vs. bot_detector, etc.) don't collide.
        default_timeout: seconds before an entry expires if not overridden.
        backend: optional injected cache object (for testing without
                 Django configured); defaults to django.core.cache.cache.
        """
        self.prefix = prefix
        self.default_timeout = default_timeout
        self.backend = backend if backend is not None else django_cache

    def _key(self, key: str) -> str:
        return f"{self.prefix}:{key}"

    def get(self, key: str, default=None):
        if self.backend is None:
            return default
        try:
            value = self.backend.get(self._key(key))
            return value if value is not None else default
        except Exception:
            logger.warning("cache get failed for key=%s, failing open", key)
            return default

    def set(self, key: str, value, timeout: int = None) -> bool:
        if self.backend is None:
            return False
        try:
            self.backend.set(self._key(key), value, timeout if timeout is not None else self.default_timeout)
            return True
        except Exception:
            logger.warning("cache set failed for key=%s", key)
            return False

    def incr(self, key: str, delta: int = 1, timeout: int = None):
        """
        Atomic increment where the backend supports it (e.g. Memcached/Redis).
        Falls back to get+set (non-atomic) if incr() isn't supported, e.g.
        Django's local-memory cache in dev.
        """
        if self.backend is None:
            return None
        full_key = self._key(key)
        try:
            return self.backend.incr(full_key)
        except ValueError:
            # key doesn't exist yet
            self.set(key, delta, timeout)
            return delta
        except Exception:
            try:
                current = self.get(key, 0) or 0
                new_val = current + delta
                self.set(key, new_val, timeout)
                return new_val
            except Exception:
                logger.warning("cache incr failed for key=%s, failing open", key)
                return None

    def delete(self, key: str) -> bool:
        if self.backend is None:
            return False
        try:
            self.backend.delete(self._key(key))
            return True
        except Exception:
            return False