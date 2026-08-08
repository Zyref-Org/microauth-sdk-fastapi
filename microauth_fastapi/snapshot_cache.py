"""Redis-backed snapshot sharing and refresh coordination.

Envelope v2 hardening:

* Cache keys and the envelope scope are credential-bound, so a revoked tenant
  secret can never inherit snapshots validated by a different credential.
* Publications carry a monotonic fencing token issued with the refresh lock;
  an expired leader cannot overwrite a newer owner's snapshot, and an older
  ``generated_at`` can never replace a newer one.
* The envelope preserves the origin leader's ``refresh_started_at`` so every
  hydrating worker reconciles monetary reservations against the moment the
  snapshot's balances were actually read, not its own cache-read time.
* Payloads are digest-checked and size-bounded before JSON decoding.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import random
import time
import uuid
from dataclasses import dataclass
from typing import Any

from .exceptions import MicroAuthResponseError, SnapshotCacheError

# One protocol version is shared by every Redis primitive in this SDK (the
# Lua script markers and this envelope). Bump them together; readers reject
# other versions and the refresh leader republishes, so no compatibility
# shims are carried.
_CACHE_VERSION = 3
_MAX_ENVELOPE_BYTES = 8 << 20  # 8 MiB guards decode cost, not correctness.

_RELEASE_LOCK_SCRIPT = """
local marker = "microauth-snapshot-release-v3"
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
end
return 0
"""

_ACQUIRE_LOCK_SCRIPT = """
local marker = "microauth-snapshot-acquire-v3"
if redis.call("SET", KEYS[1], ARGV[1], "NX", "PX", ARGV[2]) then
    return redis.call("INCR", KEYS[2])
end
return 0
"""

_STORE_IF_OWNER_SCRIPT = """
local marker = "microauth-snapshot-store-v3"
if redis.call("GET", KEYS[2]) ~= ARGV[1] then
    return 0
end
local stored_fence = tonumber(redis.call("HGET", KEYS[3], "fence") or "-1")
local stored_generated = tonumber(
    redis.call("HGET", KEYS[3], "generated") or "-1")
if tonumber(ARGV[4]) < stored_fence then
    return -1
end
if tonumber(ARGV[6]) == 0 and tonumber(ARGV[5]) < stored_generated then
    return -2
end
redis.call("SET", KEYS[1], ARGV[2], "EX", ARGV[3])
redis.call("HSET", KEYS[3], "fence", ARGV[4], "generated", ARGV[5])
redis.call("EXPIRE", KEYS[3], ARGV[3])
return 1
"""

_EXTEND_LOCK_SCRIPT = """
local marker = "microauth-snapshot-extend-v3"
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("PEXPIRE", KEYS[1], ARGV[2])
end
return 0
"""

_DISCARD_EXACT_SCRIPT = """
local marker = "microauth-snapshot-discard-v3"
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
end
return 0
"""


@dataclass(frozen=True, slots=True)
class CachedSnapshot:
    payload: dict[str, Any]
    marker: str
    refresh_started_at: float


@dataclass(frozen=True, slots=True)
class SnapshotLease:
    """Ownership of one coordinated refresh: lock token plus fencing value."""

    token: str
    fence: int


class RedisSnapshotCache:
    """Share validated snapshot payloads and serialize control-plane refreshes."""

    def __init__(
        self,
        redis_client: Any,
        cache_scope: str,
        *,
        ttl: float,
        lock_timeout: float = 10.0,
        key_prefix: str = "ma",
    ) -> None:
        if ttl <= 0:
            raise ValueError("ttl must be positive")
        if lock_timeout <= 0:
            raise ValueError("lock_timeout must be positive")
        scope = hashlib.sha256(cache_scope.encode("utf-8")).hexdigest()[:32]
        root = f"{key_prefix.rstrip(':')}:{{{scope}}}:snapshot"
        self._redis = redis_client
        self._scope = scope
        self._cache_key = f"{root}:data"
        self._lock_key = f"{root}:refresh-lock"
        self._fence_key = f"{root}:fence"
        self._meta_key = f"{root}:meta"
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
        return self._parse_envelope(raw)

    def _parse_envelope(self, raw: Any) -> CachedSnapshot:
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
        if len(raw) > _MAX_ENVELOPE_BYTES:
            raise MicroAuthResponseError(
                "shared snapshot cache entry exceeds the supported size"
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
        if envelope.get("scope") != self._scope:
            raise MicroAuthResponseError(
                "shared snapshot cache entry belongs to a different credential scope"
            )
        marker = envelope.get("marker")
        payload = envelope.get("payload")
        digest = envelope.get("digest")
        refresh_started_at = envelope.get("refresh_started_at")
        if (
            not isinstance(marker, str)
            or not marker
            or not isinstance(payload, dict)
            or not isinstance(digest, str)
            or isinstance(refresh_started_at, bool)
            or not isinstance(refresh_started_at, (int, float))
            or not math.isfinite(float(refresh_started_at))
            or float(refresh_started_at) <= 0
        ):
            raise MicroAuthResponseError("shared snapshot cache is malformed")
        if _payload_digest(payload) != digest:
            raise MicroAuthResponseError(
                "shared snapshot cache digest does not match its payload"
            )
        return CachedSnapshot(
            payload=payload,
            marker=marker,
            refresh_started_at=float(refresh_started_at),
        )

    async def store_if_owner(
        self,
        payload: dict[str, Any],
        lease: SnapshotLease,
        *,
        refresh_started_at: float,
        generated_at_ms: int,
        force: bool = False,
    ) -> CachedSnapshot | None:
        """Publish while holding the refresh lock.

        Publication is rejected for an expired leader (stale fence) or an
        older ``generated_at``. ``force`` bypasses only the generation check,
        for the lock owner replacing a semantically poisoned entry whose
        recorded generation blocks a valid snapshot.
        """
        marker = f"{time.time_ns()}-{uuid.uuid4()}"
        envelope = {
            "version": _CACHE_VERSION,
            "marker": marker,
            "scope": self._scope,
            "refresh_started_at": refresh_started_at,
            "digest": _payload_digest(payload),
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
            stored = int(
                await self._redis.eval(
                    _STORE_IF_OWNER_SCRIPT,
                    3,
                    self._cache_key,
                    self._lock_key,
                    self._meta_key,
                    lease.token,
                    encoded,
                    self._ttl_seconds,
                    lease.fence,
                    generated_at_ms,
                    int(force),
                )
            )
        except Exception as exc:
            raise SnapshotCacheError("could not update the shared snapshot cache") from exc
        if stored != 1:
            return None
        return CachedSnapshot(
            payload=payload,
            marker=marker,
            refresh_started_at=refresh_started_at,
        )

    async def acquire_refresh_lock(self) -> SnapshotLease | None:
        token = str(uuid.uuid4())
        try:
            fence = int(
                await self._redis.eval(
                    _ACQUIRE_LOCK_SCRIPT,
                    2,
                    self._lock_key,
                    self._fence_key,
                    token,
                    self._lock_ms,
                )
            )
        except Exception as exc:
            raise SnapshotCacheError(
                "could not acquire the shared snapshot refresh lock"
            ) from exc
        if fence <= 0:
            return None
        return SnapshotLease(token=token, fence=fence)

    async def release_refresh_lock(self, lease: SnapshotLease) -> None:
        try:
            await self._redis.eval(
                _RELEASE_LOCK_SCRIPT,
                1,
                self._lock_key,
                lease.token,
            )
        except Exception as exc:
            raise SnapshotCacheError(
                "could not release the shared snapshot refresh lock"
            ) from exc

    async def maintain_refresh_lock(self, lease: SnapshotLease) -> None:
        """Renew a held lease until cancelled or ownership is lost."""

        while True:
            await asyncio.sleep(self._lock_heartbeat)
            try:
                extended = await self._redis.eval(
                    _EXTEND_LOCK_SCRIPT,
                    1,
                    self._lock_key,
                    lease.token,
                    self._lock_ms,
                )
            except Exception as exc:
                raise SnapshotCacheError(
                    "could not renew the shared snapshot refresh lock"
                ) from exc
            if not extended:
                return

    async def discard_corrupt(self) -> bool:
        """Quarantine a malformed cache value with compare-and-delete.

        Returns True when a malformed entry was removed. A concurrently stored
        replacement value is never deleted.
        """

        try:
            raw = await self._redis.get(self._cache_key)
        except Exception as exc:
            raise SnapshotCacheError("could not read the shared snapshot cache") from exc
        if raw is None:
            return False
        try:
            self._parse_envelope(raw)
        except MicroAuthResponseError:
            pass
        else:
            return False
        compare = raw if isinstance(raw, (str, bytes)) else None
        if compare is None:
            return False
        try:
            removed = await self._redis.eval(
                _DISCARD_EXACT_SCRIPT,
                1,
                self._cache_key,
                compare,
            )
        except Exception as exc:
            raise SnapshotCacheError(
                "could not discard a corrupt shared snapshot"
            ) from exc
        return bool(int(removed))

    async def wait_for_update(
        self,
        previous_marker: str | None,
        *,
        timeout: float,
        poll_interval: float = 0.05,
    ) -> CachedSnapshot | None:
        deadline = time.monotonic() + max(0.0, timeout)
        delay = poll_interval
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
            # Jittered backoff keeps a large cold-start fleet from producing
            # tens of thousands of synchronized Redis reads per second.
            await asyncio.sleep(min(delay * random.uniform(0.8, 1.2), remaining))
            delay = min(delay * 1.6, 0.4)


def _payload_digest(payload: dict[str, Any]) -> str:
    try:
        canonical = json.dumps(
            payload,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise MicroAuthResponseError(
            "snapshot payload cannot be canonicalized for digesting"
        ) from exc
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
