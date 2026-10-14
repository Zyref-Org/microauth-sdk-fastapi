"""Limits for API key callers, in memory or in Redis.

Two limits share one algorithm, GCRA (the generic cell rate algorithm):

- requests per minute for each person, which MicroAuth sends with every key
  check, so making more keys doesn't raise anyone's limit;
- unknown keys per client address, so an API can't be used to test stolen or
  guessed keys.

GCRA keeps one number per counter, the time the counter drains back to
empty. It admits ``limit`` requests in a burst and then one every
``60 / limit`` seconds, which is what a 60 second sliding window allows. In
Redis the whole decision is one Lua script, so every worker sharing the Redis
shares the limit.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from typing import Any, Protocol

from .exceptions import LimitBackendUnavailable

logger = logging.getLogger("microauth")

PERIOD_SECONDS = 60.0
TAKE = "take"
PEEK = "peek"
ADD = "add"
# Floating point sums over epoch milliseconds drift by far less than this,
# and it keeps the last request of a full window from being refused by it.
_TOLERANCE_SECONDS = 0.001
_MAX_MEMORY_COUNTERS = 100_000

_SCRIPT = """
local marker = "microauth-key-limit-v1"
local now = tonumber(ARGV[1])
local interval = tonumber(ARGV[2])
local period = tonumber(ARGV[3])
local mode = ARGV[4]
local tat = tonumber(redis.call("GET", KEYS[1]) or "0")
if tat < now then
    tat = now
end
local wait = tat + interval - period - now
if mode == "peek" then
    if wait > 1 then
        return math.ceil(wait)
    end
    return 0
end
if mode == "take" and wait > 1 then
    return math.ceil(wait)
end
tat = tat + interval
redis.call("SET", KEYS[1], string.format("%.3f", tat), "PX", math.ceil(tat - now))
return 0
"""
SCRIPT_SHA = hashlib.sha1(_SCRIPT.encode("utf-8")).hexdigest()


class RequestThrottled(Exception):
    """A caller went over a limit. ``reason`` is safe to show to them."""

    def __init__(self, retry_after: float, reason: str) -> None:
        super().__init__(reason)
        self.retry_after = retry_after
        self.reason = reason


class Gcra(Protocol):
    async def hit(self, name: str, limit: int, mode: str, now: float) -> float:
        """Seconds the caller must wait, or 0.

        ``take`` counts the request only when it is allowed, ``peek`` only
        answers whether the next one would be, and ``add`` always counts.
        """
        ...

    async def aclose(self) -> None: ...


class MemoryGcra:
    """Counters in this process. Each worker counts on its own."""

    def __init__(self, *, max_counters: int = _MAX_MEMORY_COUNTERS) -> None:
        self._drained_at: dict[str, float] = {}
        self._max = max_counters
        self._swept_at = 0.0

    async def hit(self, name: str, limit: int, mode: str, now: float) -> float:
        interval = PERIOD_SECONDS / limit
        drained_at = max(self._drained_at.get(name, now), now)
        wait = drained_at + interval - PERIOD_SECONDS - now
        if mode == PEEK:
            return wait if wait > _TOLERANCE_SECONDS else 0.0
        if mode == TAKE and wait > _TOLERANCE_SECONDS:
            return wait
        self._drained_at[name] = drained_at + interval
        self._sweep(now)
        return 0.0

    def _sweep(self, now: float) -> None:
        if len(self._drained_at) <= self._max and now - self._swept_at < PERIOD_SECONDS:
            return
        self._swept_at = now
        self._drained_at = {
            name: drained_at for name, drained_at in self._drained_at.items() if drained_at > now
        }
        while len(self._drained_at) > self._max:
            del self._drained_at[next(iter(self._drained_at))]

    async def aclose(self) -> None:
        self._drained_at.clear()


def _missing_script(exc: Exception) -> bool:
    return type(exc).__name__ == "NoScriptError" or "NOSCRIPT" in str(exc)


class RedisGcra:
    """Counters in Redis, shared by every worker. One script call per decision."""

    def __init__(self, redis: Callable[[], Any]) -> None:
        self._redis = redis

    async def hit(self, name: str, limit: int, mode: str, now: float) -> float:
        args = (
            int(now * 1000),
            f"{PERIOD_SECONDS * 1000 / limit:.6f}",
            int(PERIOD_SECONDS * 1000),
            mode,
        )
        client = self._redis()
        try:
            try:
                result = await client.evalsha(SCRIPT_SHA, 1, name, *args)
            except Exception as exc:
                if not _missing_script(exc):
                    raise
                result = await client.eval(_SCRIPT, 1, name, *args)
            wait_ms = int(result)
        except Exception as exc:
            raise LimitBackendUnavailable(
                f"Redis is unavailable, so API key limits can't be checked ({type(exc).__name__})"
            ) from exc
        return wait_ms / 1000

    async def aclose(self) -> None:
        return None


def _hashed(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


class KeyLimits:
    """The per person limit and the unknown key throttle of one API."""

    def __init__(self, gcra: Gcra, namespace: str, *, unknown_key_limit: int) -> None:
        self._gcra = gcra
        self._namespace = namespace
        self.unknown_key_limit = unknown_key_limit

    def _name(self, kind: str, value: str) -> str:
        return f"{self._namespace}:{kind}:{_hashed(value)}"

    async def unknown_key_wait(self, address: str, now: float) -> float:
        """Seconds this address must wait before sending another key, or 0."""
        if self.unknown_key_limit == 0:
            return 0.0
        return await self._gcra.hit(
            self._name("unknown", address), self.unknown_key_limit, PEEK, now
        )

    async def count_unknown_key(self, address: str, now: float) -> None:
        if self.unknown_key_limit:
            await self._gcra.hit(self._name("unknown", address), self.unknown_key_limit, ADD, now)

    async def take_request(self, sub: str, requests_per_minute: int, now: float) -> float:
        """Count one request for ``sub``, or the seconds to wait when over the limit."""
        return await self._gcra.hit(self._name("rpm", sub), requests_per_minute, TAKE, now)

    async def aclose(self) -> None:
        await self._gcra.aclose()
