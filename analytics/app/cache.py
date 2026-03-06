# ═══════════════════════════════════════════════════════════════
# Redis Cache Layer for Analytics Engine
# ═══════════════════════════════════════════════════════════════
import os
import json
import logging
from datetime import datetime
from decimal import Decimal

logger = logging.getLogger("edars.analytics.cache")


class DecimalEncoder(json.JSONEncoder):
    """Handles Decimal and datetime serialisation for cache values."""
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


class RedisCache:
    """
    Simple Redis cache wrapper with TTL-based expiry.
    Falls back gracefully if Redis is unavailable (analytics
    still works, just without caching).
    """

    def __init__(self):
        self._redis = None
        try:
            import redis
            self._redis = redis.Redis(
                host=os.getenv("REDIS_HOST", "cache"),
                port=int(os.getenv("REDIS_PORT", "6379")),
                db=1,  # Separate DB from gateway rate limiting
                decode_responses=True,
                socket_connect_timeout=3,
                socket_timeout=3,
            )
            self._redis.ping()
            logger.info("Analytics Redis cache connected (db=1)")
        except Exception as e:
            logger.warning(f"Redis cache unavailable — running without cache: {e}")
            self._redis = None

    def get(self, key: str):
        """Retrieve cached value. Returns None on miss or error."""
        if not self._redis:
            return None
        try:
            val = self._redis.get(f"analytics:{key}")
            return json.loads(val) if val else None
        except Exception:
            return None

    def set(self, key: str, value, ttl_seconds: int = 300):
        """Cache value with TTL. Failures are non-fatal."""
        if not self._redis:
            return
        try:
            serialised = json.dumps(value, cls=DecimalEncoder)
            self._redis.setex(f"analytics:{key}", ttl_seconds, serialised)
        except Exception as e:
            logger.debug(f"Cache write failed (non-critical): {e}")

    def invalidate(self, pattern: str):
        """Invalidate all keys matching pattern."""
        if not self._redis:
            return
        try:
            keys = self._redis.keys(f"analytics:{pattern}")
            if keys:
                self._redis.delete(*keys)
                logger.info(f"Invalidated {len(keys)} cache keys matching '{pattern}'")
        except Exception:
            pass

    def ping(self):
        """Health check."""
        if self._redis:
            return self._redis.ping()
        raise ConnectionError("Redis not connected")

    def close(self):
        """Clean shutdown."""
        if self._redis:
            self._redis.close()
            logger.info("Analytics Redis cache closed")
