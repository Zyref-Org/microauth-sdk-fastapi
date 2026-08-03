"""Per-customer rate limiting.

Two interchangeable backends:

* ``MemoryLimiter`` — a token bucket per customer. Zero dependencies and
  zero I/O, but each worker process enforces the limit independently
  (N workers => up to N x the configured RPS across the fleet).

* ``RedisLimiter`` — a fixed one-second window counter in Redis
  (INCR + EXPIRE in one pipeline: a single round trip per request).
  Exact enforcement across any number of workers/machines.
"""

from __future__ import annotations

import time
from typing import Protocol


class Limiter(Protocol):
    async def allow(self, customer_id: str, rps: int) -> bool: ...

    async def aclose(self) -> None: ...


class _Bucket:
    __slots__ = ("tokens", "updated")

    def __init__(self, tokens: float, updated: float) -> None:
        self.tokens = tokens
        self.updated = updated


class MemoryLimiter:
    """Token bucket: capacity == rps, refill rate == rps/second.

    Runs entirely in the event loop (no awaits between read and write), so
    it needs no locking.
    """

    def __init__(self) -> None:
        self._buckets: dict[str, _Bucket] = {}
        self._last_gc = time.monotonic()

    async def allow(self, customer_id: str, rps: int) -> bool:
        if rps <= 0:
            return True
        now = time.monotonic()
        b = self._buckets.get(customer_id)
        if b is None:
            b = self._buckets[customer_id] = _Bucket(float(rps), now)
        else:
            b.tokens = min(float(rps), b.tokens + (now - b.updated) * rps)
            b.updated = now
        if b.tokens < 1.0:
            return False
        b.tokens -= 1.0
        self._maybe_gc(now)
        return True

    def _maybe_gc(self, now: float) -> None:
        # Drop buckets idle for 10+ minutes so long-running processes with
        # many one-off customers don't grow unboundedly.
        if now - self._last_gc < 600:
            return
        self._last_gc = now
        stale = [cid for cid, b in self._buckets.items() if now - b.updated > 600]
        for cid in stale:
            del self._buckets[cid]

    async def aclose(self) -> None:  # pragma: no cover - nothing to close
        return None


class RedisLimiter:
    """Fixed 1-second window in Redis, shared across workers.

    ``INCR ma:rps:{customer}:{second}`` + ``EXPIRE .. 3`` in one pipeline.
    Allows at most ``rps`` requests per wall-clock second per customer.
    If Redis is unreachable the limiter fails open (requests pass) —
    availability of your API beats strict throttling.
    """

    def __init__(self, url: str, key_prefix: str = "ma:rps") -> None:
        try:
            import redis.asyncio as aioredis
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "redis_url was configured but the redis package is not installed. "
                "Install with: pip install 'microauth-fastapi[redis]'"
            ) from exc
        self._redis = aioredis.from_url(url, socket_timeout=1.0, socket_connect_timeout=1.0)
        self._prefix = key_prefix
        self._down_until = 0.0

    async def allow(self, customer_id: str, rps: int) -> bool:
        if rps <= 0:
            return True
        now = time.monotonic()
        if now < self._down_until:
            return True  # circuit open: Redis recently failed
        key = f"{self._prefix}:{customer_id}:{int(time.time())}"
        try:
            async with self._redis.pipeline(transaction=False) as pipe:
                pipe.incr(key)
                pipe.expire(key, 3)
                count, _ = await pipe.execute()
        except Exception:
            # Fail open, and back off from Redis for a couple of seconds so a
            # dead Redis doesn't add latency to every request.
            self._down_until = now + 2.0
            return True
        return int(count) <= rps

    async def aclose(self) -> None:
        try:
            await self._redis.aclose()
        except Exception:  # pragma: no cover
            pass
