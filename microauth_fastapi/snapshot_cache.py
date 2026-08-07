"""Redis-backed snapshot sharing and refresh coordination."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import time
import uuid
from dataclasses import dataclass
from typing import Any

from .exceptions import MicroAuthResponseError, SnapshotCacheError

_CACHE_VERSION = 1
_RELEASE_LOCK_SCRIPT = """
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
end
return 0
"""
_STORE_IF_OWNER_SCRIPT = """
if redis.call("GET", KEYS[2]) == ARGV[1] then
    redis.call("SET", KEYS[1], ARGV[2], "EX", ARGV[3])
    return 1
end
return 0
"""
_EXTEND_LOCK_SCRIPT = """
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("PEXPIRE", KEYS[1], ARGV[2])
end
return 0
"""


@dataclass(frozen=True, slots=True)
class CachedSnapshot:
    payload: dict[str, Any]
    marker: str


class RedisSnapshotCache:
    """Share validated snapshot payloads and serialize control-plane refreshes."""

    def __init__(
        self,
        redis_client: Any,
        tenant_scope: str,
        *,
        ttl: float,
        lock_timeout: float = 10.0,
        key_prefix: str = "ma",
    ) -> None:
        if ttl <= 0:
            raise ValueError("ttl must be positive")
        if lock_timeout <= 0:
            raise ValueError("lock_timeout must be positive")
        scope = hashlib.sha256(tenant_scope.encode("utf-8")).hexdigest()[:32]
        root = f"{key_prefix.rstrip(':')}:{{{scope}}}:snapshot"
        self._redis = redis_client
        self._cache_key = f"{root}:data"
        self._lock_key = f"{root}:refresh-lock"
        self._ttl_seconds = max(1, math.ceil(ttl))
        self._lock_ms = max(1000, math.ceil(lock_timeout * 1000))
        self._lock_heartbeat = max(0.25, lock_timeout / 3.0)

    async def load(self) -> CachedSnapshot | None:
        try:
            raw = await self._redis.get(self._cache_key)
        except Exception as exc:
            raise SnapshotCacheError("could not read the shared snapshot cache") from exc
        if raw is None:
            return None
        if isinstance(raw, bytes):
            try:
                raw = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise MicroAuthResponseError(
                    "shared snapshot cache contains invalid UTF-8"
                ) from exc
        if not isinstance(raw, str):
            raise MicroAuthResponseError(
                "shared snapshot cache returned an unsupported value"
            )
        try:
            envelope = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise MicroAuthResponseError(
                "shared snapshot cache contains invalid JSON"
            ) from exc
        if not isinstance(envelope, dict) or envelope.get("version") != _CACHE_VERSION:
            raise MicroAuthResponseError(
                "shared snapshot cache has an unsupported format"
            )
        marker = envelope.get("marker")
        payload = envelope.get("payload")
        if not isinstance(marker, str) or not marker or not isinstance(payload, dict):
            raise MicroAuthResponseError("shared snapshot cache is malformed")
        return CachedSnapshot(payload=payload, marker=marker)

    async def store_if_owner(
        self,
        payload: dict[str, Any],
        token: str,
    ) -> CachedSnapshot | None:
        marker = f"{time.time_ns()}-{uuid.uuid4()}"
        envelope = {
            "version": _CACHE_VERSION,
            "marker": marker,
            "payload": payload,
        }
        try:
            encoded = json.dumps(
                envelope,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        except (TypeError, ValueError) as exc:
            raise MicroAuthResponseError(
                "snapshot payload cannot be stored as JSON"
            ) from exc
        try:
            stored = await self._redis.eval(
                _STORE_IF_OWNER_SCRIPT,
                2,
                self._cache_key,
                self._lock_key,
                token,
                encoded,
                self._ttl_seconds,
            )
        except Exception as exc:
            raise SnapshotCacheError("could not update the shared snapshot cache") from exc
        if not stored:
            return None
        return CachedSnapshot(payload=payload, marker=marker)

    async def acquire_refresh_lock(self) -> str | None:
        token = str(uuid.uuid4())
        try:
            acquired = await self._redis.set(
                self._lock_key,
                token,
                nx=True,
                px=self._lock_ms,
            )
        except Exception as exc:
            raise SnapshotCacheError(
                "could not acquire the shared snapshot refresh lock"
            ) from exc
        return token if acquired else None

    async def release_refresh_lock(self, token: str) -> None:
        try:
            await self._redis.eval(
                _RELEASE_LOCK_SCRIPT,
                1,
                self._lock_key,
                token,
            )
        except Exception as exc:
            raise SnapshotCacheError(
                "could not release the shared snapshot refresh lock"
            ) from exc

    async def maintain_refresh_lock(self, token: str) -> None:
        """Renew a held lease until cancelled or ownership is lost."""

        while True:
            await asyncio.sleep(self._lock_heartbeat)
            try:
                extended = await self._redis.eval(
                    _EXTEND_LOCK_SCRIPT,
                    1,
                    self._lock_key,
                    token,
                    self._lock_ms,
                )
            except Exception as exc:
                raise SnapshotCacheError(
                    "could not renew the shared snapshot refresh lock"
                ) from exc
            if not extended:
                return

    async def wait_for_update(
        self,
        previous_marker: str | None,
        *,
        timeout: float,
        poll_interval: float = 0.05,
    ) -> CachedSnapshot | None:
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            try:
                cached = await self.load()
            except MicroAuthResponseError:
                # The current lock owner may be replacing a corrupt entry.
                cached = None
            if cached is not None and cached.marker != previous_marker:
                return cached
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            await asyncio.sleep(min(poll_interval, remaining))
