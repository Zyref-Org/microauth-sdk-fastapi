"""Redis-backed durable usage queue with lease-based cross-worker delivery.

Every completed request's usage is durably recorded here *before* the final
response body is released, so a worker that disappears afterwards (serverless
instance replacement, OOM, deploy) cannot lose acknowledged-but-undelivered
usage. Events are claimed under an owner lease; a dead worker's lease expires
and any other worker sharing the queue recovers and delivers its events.

Requests aggregate into counted events: an event's static identity (API key,
policy, status, hour bucket) is written once, and each additional request is
an O(1) counter increment plus one appended limiter attachment, so the durable
handoff stays constant-time no matter how many requests share an event.

Durability is bounded by the Redis deployment's own persistence guarantees
(managed offerings such as Upstash persist by default; self-hosted Redis needs
AOF enabled).

Attachment lists are stored under per-event keys derived inside Lua from a
prefix that shares the queue's hash tag, so every touched key lives in the
same cluster slot.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from typing import Any

from .exceptions import UsageQueueFull, UsageStoreError

logger = logging.getLogger("microauth")

UPSERT_CREATED = "created"
UPSERT_MERGED = "merged"
UPSERT_FENCED = "fenced"
UPSERT_CAPPED = "capped"

# All scripts read the clock with redis.call("TIME") so ordering decisions are
# consistent across workers with skewed local clocks.

_UPSERT_SCRIPT = """
local marker = "microauth-usage-upsert-v3"
local time = redis.call("TIME")
local now_ms = time[1] * 1000 + math.floor(time[2] / 1000)
local id = ARGV[1]
local result
if redis.call("HEXISTS", KEYS[1], id) == 1 then
    if redis.call("HGET", KEYS[4], id) ~= ARGV[4] then
        return -1
    end
    -- The per-request token makes the merge idempotent: a retry after an
    -- ambiguous timeout (executed, reply lost) must not double-count.
    if redis.call("SADD", KEYS[7], ARGV[10]) == 0 then
        redis.call("PEXPIRE", KEYS[7], ARGV[7])
        return 2
    end
    local count = tonumber(redis.call("HGET", KEYS[5], id) or "1")
    if count >= tonumber(ARGV[8]) then
        redis.call("SREM", KEYS[7], ARGV[10])
        return -2
    end
    redis.call("HINCRBY", KEYS[5], id, 1)
    if ARGV[3] ~= "" then
        redis.call("RPUSH", KEYS[6], ARGV[3])
    end
    redis.call("ZADD", KEYS[3], now_ms + tonumber(ARGV[5]), id)
    result = 2
else
    if tonumber(ARGV[9]) == 0 then
        -- Merge-only mode: the event vanished (another worker recovered and
        -- delivered it). Recreating it under the same idempotency key would
        -- later conflict with the server's receipt.
        return -1
    end
    if redis.call("HLEN", KEYS[1]) >= tonumber(ARGV[6]) then
        return 0
    end
    redis.call("HSET", KEYS[1], id, ARGV[2])
    redis.call("HSET", KEYS[5], id, 1)
    redis.call("SADD", KEYS[7], ARGV[10])
    if ARGV[3] ~= "" then
        redis.call("RPUSH", KEYS[6], ARGV[3])
    end
    redis.call("ZREM", KEYS[2], id)
    redis.call("ZADD", KEYS[3], now_ms + tonumber(ARGV[5]), id)
    redis.call("HSET", KEYS[4], id, ARGV[4])
    result = 1
end
for index = 1, 7 do
    redis.call("PEXPIRE", KEYS[index], ARGV[7])
end
return result
"""

_CLAIM_SCRIPT = """
local marker = "microauth-usage-claim-v3"
local time = redis.call("TIME")
local now_ms = time[1] * 1000 + math.floor(time[2] / 1000)
local limit = tonumber(ARGV[2])
local expired = redis.call(
    "ZRANGEBYSCORE", KEYS[3], "-inf", now_ms, "LIMIT", 0, limit)
for _, id in ipairs(expired) do
    redis.call("ZREM", KEYS[3], id)
    redis.call("HDEL", KEYS[4], id)
    if redis.call("HEXISTS", KEYS[1], id) == 1 then
        redis.call("ZADD", KEYS[2], now_ms, id)
    end
end
local due = redis.call(
    "ZRANGEBYSCORE", KEYS[2], "-inf", now_ms, "LIMIT", 0, limit)
local claimed = {}
for _, id in ipairs(due) do
    local static = redis.call("HGET", KEYS[1], id)
    redis.call("ZREM", KEYS[2], id)
    if static then
        redis.call("ZADD", KEYS[3], now_ms + tonumber(ARGV[3]), id)
        redis.call("HSET", KEYS[4], id, ARGV[1])
        local count = redis.call("HGET", KEYS[5], id) or "1"
        local attachments = redis.call("LRANGE", ARGV[5] .. id, 0, -1)
        claimed[#claimed + 1] = id
        claimed[#claimed + 1] = static
        claimed[#claimed + 1] = count
        claimed[#claimed + 1] = table.concat(attachments, "\\n")
    end
end
for index = 1, 5 do
    redis.call("PEXPIRE", KEYS[index], ARGV[4])
end
return claimed
"""

_ACK_SCRIPT = """
local marker = "microauth-usage-ack-v3"
local removed = 0
for index = 5, #ARGV do
    local id = ARGV[index]
    if redis.call("HGET", KEYS[4], id) == ARGV[1] then
        redis.call("HDEL", KEYS[1], id)
        redis.call("HDEL", KEYS[4], id)
        redis.call("HDEL", KEYS[5], id)
        redis.call("ZREM", KEYS[2], id)
        redis.call("ZREM", KEYS[3], id)
        redis.call("DEL", ARGV[3] .. id)
        redis.call("DEL", ARGV[4] .. id)
        removed = removed + 1
    end
end
for index = 1, 5 do
    redis.call("PEXPIRE", KEYS[index], ARGV[2])
end
return removed
"""

_RELEASE_SCRIPT = """
local marker = "microauth-usage-release-v3"
local time = redis.call("TIME")
local now_ms = time[1] * 1000 + math.floor(time[2] / 1000)
local released = 0
for index = 4, #ARGV do
    local id = ARGV[index]
    if redis.call("HGET", KEYS[4], id) == ARGV[1] then
        redis.call("HDEL", KEYS[4], id)
        redis.call("ZREM", KEYS[3], id)
        if redis.call("HEXISTS", KEYS[1], id) == 1 then
            redis.call("ZADD", KEYS[2], now_ms + tonumber(ARGV[2]), id)
        end
        released = released + 1
    end
end
for index = 1, 4 do
    redis.call("PEXPIRE", KEYS[index], ARGV[3])
end
return released
"""

_EXTEND_SCRIPT = """
local marker = "microauth-usage-extend-v3"
local time = redis.call("TIME")
local now_ms = time[1] * 1000 + math.floor(time[2] / 1000)
local extended = 0
for index = 4, #ARGV do
    local id = ARGV[index]
    if redis.call("HGET", KEYS[2], id) == ARGV[1] then
        redis.call("ZADD", KEYS[1], now_ms + tonumber(ARGV[2]), id)
        extended = extended + 1
    end
end
redis.call("PEXPIRE", KEYS[1], ARGV[3])
redis.call("PEXPIRE", KEYS[2], ARGV[3])
return extended
"""

_DEAD_LETTER_SCRIPT = """
local marker = "microauth-usage-dead-letter-v3"
local id = ARGV[2]
if redis.call("HGET", KEYS[4], id) ~= ARGV[1] then
    return 0
end
if redis.call("HEXISTS", KEYS[1], id) == 1 then
    redis.call("HSET", KEYS[6], id, ARGV[3])
end
redis.call("HDEL", KEYS[1], id)
redis.call("HDEL", KEYS[4], id)
redis.call("HDEL", KEYS[5], id)
redis.call("ZREM", KEYS[2], id)
redis.call("ZREM", KEYS[3], id)
redis.call("DEL", ARGV[5] .. id)
redis.call("DEL", ARGV[6] .. id)
for index = 1, 6 do
    redis.call("PEXPIRE", KEYS[index], ARGV[4])
end
return 1
"""

# Events older than the API's 45-day usage-age limit are terminally rejected,
# so retaining queue state longer than 46 days only hides permanent failures.
_RETENTION_MS = 46 * 86_400 * 1000


def _decode(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8")
    if isinstance(value, str):
        return value
    raise UsageStoreError("usage queue returned an unsupported value type")


def _encode_json(value: Any, what: str) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise UsageStoreError(f"{what} cannot be stored as JSON") from exc


class RedisUsageStore:
    """Durable at-least-once usage event queue shared by autoscaling workers."""

    def __init__(
        self,
        redis_client: Any,
        tenant_scope: str,
        *,
        max_items: int,
        lease_ms: int = 60_000,
        key_prefix: str = "ma",
    ) -> None:
        if max_items <= 0:
            raise ValueError("max_items must be positive")
        if lease_ms < 1000:
            raise ValueError("lease_ms must be at least 1000")
        scope = hashlib.sha256(tenant_scope.encode("utf-8")).hexdigest()[:32]
        root = f"{key_prefix.rstrip(':')}:{{{scope}}}:usage"
        self._redis = redis_client
        self._events_key = f"{root}:events"
        self._ready_key = f"{root}:ready"
        self._leases_key = f"{root}:leases"
        self._owners_key = f"{root}:owners"
        self._counts_key = f"{root}:counts"
        self._dead_key = f"{root}:dead"
        self._att_prefix = f"{root}:att:"
        self._tok_prefix = f"{root}:tok:"
        self._max_items = max_items
        self._lease_ms = lease_ms
        self.owner = str(uuid.uuid4())

    @property
    def lease_ms(self) -> int:
        return self._lease_ms

    def _att_key(self, event_id: str) -> str:
        return f"{self._att_prefix}{event_id}"

    def _tok_key(self, event_id: str) -> str:
        return f"{self._tok_prefix}{event_id}"

    async def enqueue_claimed(
        self,
        event_id: str,
        static_payload: dict[str, Any],
        attachment: dict[str, Any] | None,
    ) -> str:
        """Durably create an event (already claimed by this worker)."""

        return await self._upsert(
            event_id,
            _encode_json(static_payload, "usage event"),
            attachment,
            max_count=1,
            allow_create=True,
        )

    async def merge_claimed(
        self,
        event_id: str,
        attachment: dict[str, Any] | None,
        *,
        max_count: int,
    ) -> str:
        """Merge one request into an owned open event as an O(1) update.

        The merge is a counter increment plus one appended attachment, so the
        pre-response durable handoff stays constant-time regardless of how
        many requests share the event. Merging is owner-fenced: once another
        worker recovers the event's lease (or has already delivered it), the
        caller must create a fresh event instead.
        """

        return await self._upsert(
            event_id,
            "",
            attachment,
            max_count=max_count,
            allow_create=False,
        )

    async def _upsert(
        self,
        event_id: str,
        encoded_static: str,
        attachment: dict[str, Any] | None,
        *,
        max_count: int,
        allow_create: bool,
    ) -> str:
        encoded_attachment = (
            _encode_json(attachment, "usage attachment") if attachment else ""
        )
        # A stable per-request token makes the whole operation idempotent: an
        # ambiguous failure (the server executed the script but the reply was
        # lost) is retried once and deduplicated instead of double-counting.
        raw_token = attachment.get("token") if attachment else None
        dedup_token = (
            raw_token
            if isinstance(raw_token, str) and raw_token
            else str(uuid.uuid4())
        )
        last_error: Exception | None = None
        result: int | None = None
        for attempt in range(2):
            try:
                result = int(
                    await self._redis.eval(
                        _UPSERT_SCRIPT,
                        7,
                        self._events_key,
                        self._ready_key,
                        self._leases_key,
                        self._owners_key,
                        self._counts_key,
                        self._att_key(event_id),
                        self._tok_key(event_id),
                        event_id,
                        encoded_static,
                        encoded_attachment,
                        self.owner,
                        self._lease_ms,
                        self._max_items,
                        _RETENTION_MS,
                        max_count,
                        int(allow_create),
                        dedup_token,
                    )
                )
                break
            except Exception as exc:  # noqa: BLE001 - transport boundary
                last_error = exc
                if attempt == 0:
                    continue
        if result is None:
            raise UsageStoreError(
                "the durable usage queue could not store an event"
            ) from last_error
        if result == 0:
            raise UsageQueueFull(self._max_items)
        if result == -1:
            return UPSERT_FENCED
        if result == -2:
            return UPSERT_CAPPED
        return UPSERT_CREATED if result == 1 else UPSERT_MERGED

    async def claim_due(self, limit: int) -> list[tuple[str, dict[str, Any]]]:
        """Recover expired leases and claim due events for this worker."""

        if limit <= 0:
            return []
        try:
            raw = await self._redis.eval(
                _CLAIM_SCRIPT,
                5,
                self._events_key,
                self._ready_key,
                self._leases_key,
                self._owners_key,
                self._counts_key,
                self.owner,
                limit,
                self._lease_ms,
                _RETENTION_MS,
                self._att_prefix,
            )
        except Exception as exc:
            raise UsageStoreError(
                "the durable usage queue could not claim events"
            ) from exc
        if not isinstance(raw, (list, tuple)) or len(raw) % 4 != 0:
            raise UsageStoreError("the durable usage queue returned invalid claims")
        claimed: list[tuple[str, dict[str, Any]]] = []
        for index in range(0, len(raw), 4):
            event_id = _decode(raw[index])
            claimed.append(
                (
                    event_id,
                    _reassemble_payload(
                        event_id,
                        _decode(raw[index + 1]),
                        _decode(raw[index + 2]),
                        _decode(raw[index + 3]),
                    ),
                )
            )
        return claimed

    async def ack(self, event_ids: list[str]) -> int:
        """Delete acknowledged events this worker still owns (fenced)."""

        if not event_ids:
            return 0
        try:
            removed = await self._redis.eval(
                _ACK_SCRIPT,
                5,
                self._events_key,
                self._ready_key,
                self._leases_key,
                self._owners_key,
                self._counts_key,
                self.owner,
                _RETENTION_MS,
                self._att_prefix,
                self._tok_prefix,
                *event_ids,
            )
        except Exception as exc:
            raise UsageStoreError(
                "the durable usage queue could not acknowledge events"
            ) from exc
        return int(removed)

    async def release(self, event_ids: list[str], *, delay_ms: int = 0) -> int:
        """Return owned events to the ready queue (fenced nack)."""

        if not event_ids:
            return 0
        try:
            released = await self._redis.eval(
                _RELEASE_SCRIPT,
                4,
                self._events_key,
                self._ready_key,
                self._leases_key,
                self._owners_key,
                self.owner,
                max(0, delay_ms),
                _RETENTION_MS,
                *event_ids,
            )
        except Exception as exc:
            raise UsageStoreError(
                "the durable usage queue could not release events"
            ) from exc
        return int(released)

    async def extend_leases(self, event_ids: list[str]) -> int:
        """Renew this worker's leases during long delivery retries."""

        if not event_ids:
            return 0
        try:
            extended = await self._redis.eval(
                _EXTEND_SCRIPT,
                2,
                self._leases_key,
                self._owners_key,
                self.owner,
                self._lease_ms,
                _RETENTION_MS,
                *event_ids,
            )
        except Exception as exc:
            raise UsageStoreError(
                "the durable usage queue could not extend delivery leases"
            ) from exc
        return int(extended)

    async def dead_letter(
        self,
        event_id: str,
        detail: str,
        payload: dict[str, Any] | None = None,
    ) -> bool:
        """Move a terminally rejected owned event to the dead-letter hash.

        The full payload is preserved alongside the rejection detail so
        dead-lettered usage remains reconcilable, matching the local
        journal's dead-letter file.
        """

        record_body: dict[str, Any] = {"detail": detail[:2000]}
        if payload is not None:
            record_body["event"] = payload
        record = _encode_json(record_body, "dead-letter record")
        try:
            moved = await self._redis.eval(
                _DEAD_LETTER_SCRIPT,
                6,
                self._events_key,
                self._ready_key,
                self._leases_key,
                self._owners_key,
                self._counts_key,
                self._dead_key,
                self.owner,
                event_id,
                record,
                _RETENTION_MS,
                self._att_prefix,
                self._tok_prefix,
            )
        except Exception as exc:
            raise UsageStoreError(
                "the durable usage queue could not dead-letter an event"
            ) from exc
        return bool(int(moved))

    async def pending_count(self) -> int:
        """Best-effort count of undelivered events across all workers."""

        try:
            return int(await self._redis.hlen(self._events_key))
        except Exception as exc:
            raise UsageStoreError(
                "the durable usage queue could not report its depth"
            ) from exc


def _reassemble_payload(
    event_id: str,
    static_json: str,
    count_raw: str,
    attachments_blob: str,
) -> dict[str, Any]:
    try:
        item = json.loads(static_json)
    except ValueError as exc:
        raise UsageStoreError(
            f"the durable usage queue holds invalid JSON for {event_id}"
        ) from exc
    if not isinstance(item, dict):
        raise UsageStoreError(
            f"the durable usage queue holds a non-object payload for {event_id}"
        )
    try:
        count = int(count_raw)
    except ValueError as exc:
        raise UsageStoreError(
            f"the durable usage queue holds an invalid count for {event_id}"
        ) from exc
    attachments: list[dict[str, Any]] = []
    for line in attachments_blob.split("\n"):
        if not line:
            continue
        try:
            attachment = json.loads(line)
        except ValueError as exc:
            raise UsageStoreError(
                f"the durable usage queue holds an invalid attachment for {event_id}"
            ) from exc
        if not isinstance(attachment, dict):
            raise UsageStoreError(
                f"the durable usage queue holds a non-object attachment for {event_id}"
            )
        attachments.append(attachment)
    return {"item": {**item, "count": count}, "attachments": attachments}
