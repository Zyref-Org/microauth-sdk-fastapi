"""The usage queue and snapshot cache Lua scripts against a real Redis.

The other tests emulate these scripts in Python; these run the real ones.
Set ``MICROAUTH_TEST_REDIS_URL`` (CI uses a Redis service container).
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import pytest
from support import POLICY_ID, Reporter
from test_reporter import ScriptedClient, acknowledge

from microauth_fastapi.snapshot_cache import RedisSnapshotCache
from microauth_fastapi.usage_store import (
    UPSERT_CREATED,
    UPSERT_FENCED,
    UPSERT_MERGED,
    RedisUsageStore,
)

REDIS_URL = os.environ.get("MICROAUTH_TEST_REDIS_URL")
pytestmark = pytest.mark.skipif(
    REDIS_URL is None,
    reason="set MICROAUTH_TEST_REDIS_URL to run the Lua scripts",
)

API_KEY_ID = "11111111-1111-4111-8111-111111111111"
CURRENT_HOUR = (
    datetime.now(timezone.utc)
    .replace(minute=0, second=0, microsecond=0)
    .isoformat()
    .replace("+00:00", "Z")
)


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


@asynccontextmanager
async def redis() -> AsyncIterator[tuple[Any, str]]:
    import redis.asyncio as aioredis

    assert REDIS_URL is not None
    client = aioredis.from_url(REDIS_URL)
    prefix = f"ma-test-{uuid.uuid4().hex[:12]}"
    try:
        yield client, prefix
    finally:
        keys = [key async for key in client.scan_iter(match=f"{prefix}:*")]
        if keys:
            await client.delete(*keys)
        await client.aclose()


def store(client: Any, prefix: str, *, lease_ms: int = 60_000) -> RedisUsageStore:
    return RedisUsageStore(client, "scope", max_items=100, lease_ms=lease_ms, key_prefix=prefix)


def static_item(event_id: str) -> dict[str, Any]:
    return {
        "idempotency_key": event_id,
        "api_key_id": API_KEY_ID,
        "usage_policy_id": POLICY_ID,
        "status_code": 200,
        "period_start": CURRENT_HOUR,
        "unit_charge_micro": 25,
        "queued_at": time.time(),
    }


def test_a_dead_workers_events_move_to_a_survivor_exactly_once() -> None:
    async def exercise() -> None:
        async with redis() as (client, prefix):
            recorder = store(client, prefix, lease_ms=1_000)
            survivor = store(client, prefix)
            assert (
                await recorder.enqueue_claimed("ev-1", static_item("ev-1"), {"token": "a"})
                == UPSERT_CREATED
            )
            assert (
                await recorder.merge_claimed("ev-1", {"token": "b"}, max_count=500) == UPSERT_MERGED
            )
            # A live lease is never stolen, and nobody else can merge into it.
            assert await survivor.claim_due(10) == []
            assert await survivor.merge_claimed("ev-1", None, max_count=500) == UPSERT_FENCED
            assert await recorder.pending_count() == 1

            await asyncio.sleep(1.2)  # the recorder dies; its lease expires
            ((event_id, payload),) = await survivor.claim_due(10)
            assert event_id == "ev-1"
            assert payload["item"]["count"] == 2
            assert payload["item"]["unit_charge_micro"] == 25
            assert [a["token"] for a in payload["attachments"]] == ["a", "b"]
            # The old owner is fenced out; only the new owner acknowledges.
            assert await recorder.ack(["ev-1"]) == 0
            assert await survivor.ack(["ev-1"]) == 1
            assert await survivor.pending_count() == 0

    run(exercise())


def test_released_events_are_claimable_at_once() -> None:
    async def exercise() -> None:
        async with redis() as (client, prefix):
            owner = store(client, prefix)
            other = store(client, prefix)
            await owner.enqueue_claimed("ev-1", static_item("ev-1"), None)
            assert await owner.extend_leases(["ev-1"]) == 1
            assert await owner.release(["ev-1"]) == 1
            ((event_id, _),) = await other.claim_due(10)
            assert event_id == "ev-1"
            assert await owner.release(["ev-1"]) == 0

    run(exercise())


def test_dead_letters_keep_the_full_record() -> None:
    async def exercise() -> None:
        async with redis() as (client, prefix):
            owner = store(client, prefix)
            await owner.enqueue_claimed("ev-1", static_item("ev-1"), {"token": "a"})
            payload = {"item": {**static_item("ev-1"), "count": 1}, "attachments": []}
            assert await owner.dead_letter(
                "ev-1",
                "period_start is outside the usage policy's validity",
                payload,
                http_status=422,
                rejected_at="2026-10-11T09:30:00Z",
            )
            assert await owner.pending_count() == 0
            assert await owner.dead_letter_count() == 1
            ((event_id, record),) = await owner.dead_letters()
            assert event_id == "ev-1"
            assert record == {
                "detail": "period_start is outside the usage policy's validity",
                "http_status": 422,
                "rejected_at": "2026-10-11T09:30:00Z",
                "event": payload,
            }
            assert await owner.dead_letters(limit=0) == []

    run(exercise())


def test_the_reporter_delivers_through_the_real_queue() -> None:
    async def exercise() -> None:
        async with redis() as (client, prefix):
            queue = store(client, prefix)
            delivered = ScriptedClient([acknowledge])
            reporter = Reporter(delivered, 60, store=queue)
            event_id = await reporter.record(API_KEY_ID, 200, unit_charge_micro=25)
            assert await reporter.record(API_KEY_ID, 200, unit_charge_micro=25) == event_id
            assert await queue.pending_count() == 1
            await reporter.flush()
            assert await queue.pending_count() == 0
            assert delivered.calls[0][0]["count"] == 2
            await reporter.aclose()

    run(exercise())


def test_the_snapshot_cache_serializes_refreshes_with_fencing() -> None:
    payload = {"tenant_id": "t", "generated_at": "2026-10-11T09:30:00Z"}

    async def exercise() -> None:
        async with redis() as (client, prefix):
            first = RedisSnapshotCache(client, "secret", ttl=30, lock_timeout=1, key_prefix=prefix)
            second = RedisSnapshotCache(client, "secret", ttl=30, lock_timeout=1, key_prefix=prefix)
            lease = await first.acquire_refresh_lock()
            assert lease is not None
            assert await second.acquire_refresh_lock() is None
            stored = await first.store_if_owner(
                payload,
                lease,
                refresh_started_at=time.time(),
                generated_at_ms=1_000,
            )
            assert stored is not None
            loaded = await second.load()
            assert loaded is not None and loaded.payload == payload
            await first.release_refresh_lock(lease)

            newer = await second.acquire_refresh_lock()
            assert newer is not None and newer.fence > lease.fence
            # The old leader can't publish over the new one.
            assert (
                await first.store_if_owner(
                    payload, lease, refresh_started_at=time.time(), generated_at_ms=2_000
                )
                is None
            )
            # Nor can anyone publish data older than what is cached.
            assert (
                await second.store_if_owner(
                    payload, newer, refresh_started_at=time.time(), generated_at_ms=500
                )
                is None
            )
            await second.release_refresh_lock(newer)

    run(exercise())
