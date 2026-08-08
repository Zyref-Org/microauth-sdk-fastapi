from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from test_reporter import ScriptedClient, acknowledge

from microauth_fastapi.exceptions import UsageQueueFull
from microauth_fastapi.reporter import UsageReporter
from microauth_fastapi.usage_store import RedisUsageStore

API_KEY_ID = "11111111-1111-4111-8111-111111111111"


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


class FakeUsageRedis:
    """In-memory emulation of the usage-store Lua scripts with a fake clock."""

    def __init__(self) -> None:
        self.hashes: dict[str, dict[str, str]] = {}
        self.zsets: dict[str, dict[str, float]] = {}
        self.lists: dict[str, list[str]] = {}
        self.now_ms = 1_000_000_000
        self.fail = False

    def advance(self, ms: int) -> None:
        self.now_ms += ms

    async def hlen(self, key: str) -> int:
        return len(self.hashes.get(key, {}))

    async def eval(self, script: str, number_of_keys: int, *values: Any) -> Any:
        if self.fail:
            raise OSError("redis down")
        keys = [str(value) for value in values[:number_of_keys]]
        args = list(values[number_of_keys:])
        if "microauth-usage-upsert-v3" in script:
            events, ready, leases, owners, counts, att = keys
            (
                event_id,
                static,
                attachment,
                owner,
                lease_ms,
                max_items,
                _ttl,
                max_count,
                allow_create,
            ) = args
            event_id = str(event_id)
            event_table = self.hashes.setdefault(events, {})
            count_table = self.hashes.setdefault(counts, {})
            owner_table = self.hashes.setdefault(owners, {})
            if event_id in event_table:
                if owner_table.get(event_id) != str(owner):
                    return -1
                count = int(count_table.get(event_id, "1"))
                if count >= int(max_count):
                    return -2
                count_table[event_id] = str(count + 1)
                if str(attachment):
                    self.lists.setdefault(att, []).append(str(attachment))
                self.zsets.setdefault(leases, {})[event_id] = (
                    self.now_ms + int(lease_ms)
                )
                return 2
            if not int(allow_create):
                return -1
            if len(event_table) >= int(max_items):
                return 0
            event_table[event_id] = str(static)
            count_table[event_id] = "1"
            if str(attachment):
                self.lists.setdefault(att, []).append(str(attachment))
            self.zsets.setdefault(ready, {}).pop(event_id, None)
            self.zsets.setdefault(leases, {})[event_id] = (
                self.now_ms + int(lease_ms)
            )
            owner_table[event_id] = str(owner)
            return 1
        if "microauth-usage-claim-v3" in script:
            events, ready, leases, owners, counts = keys
            owner, limit, lease_ms, _ttl, att_prefix = args
            lease_table = self.zsets.setdefault(leases, {})
            ready_table = self.zsets.setdefault(ready, {})
            owner_table = self.hashes.setdefault(owners, {})
            event_table = self.hashes.setdefault(events, {})
            count_table = self.hashes.setdefault(counts, {})
            expired = sorted(
                event_id
                for event_id, deadline in lease_table.items()
                if deadline <= self.now_ms
            )[: int(limit)]
            for event_id in expired:
                del lease_table[event_id]
                owner_table.pop(event_id, None)
                if event_id in event_table:
                    ready_table[event_id] = self.now_ms
            due = sorted(
                event_id
                for event_id, score in ready_table.items()
                if score <= self.now_ms
            )[: int(limit)]
            claimed: list[str] = []
            for event_id in due:
                static = event_table.get(event_id)
                del ready_table[event_id]
                if static is not None:
                    lease_table[event_id] = self.now_ms + int(lease_ms)
                    owner_table[event_id] = str(owner)
                    claimed.extend(
                        [
                            event_id,
                            static,
                            count_table.get(event_id, "1"),
                            "\n".join(
                                self.lists.get(str(att_prefix) + event_id, [])
                            ),
                        ]
                    )
            return claimed
        if "microauth-usage-ack-v3" in script:
            events, ready, leases, owners, counts = keys
            owner, _ttl, att_prefix, *event_ids = args
            removed = 0
            for event_id in map(str, event_ids):
                if self.hashes.get(owners, {}).get(event_id) == str(owner):
                    self.hashes.get(events, {}).pop(event_id, None)
                    self.hashes.get(owners, {}).pop(event_id, None)
                    self.hashes.get(counts, {}).pop(event_id, None)
                    self.zsets.get(leases, {}).pop(event_id, None)
                    self.zsets.get(ready, {}).pop(event_id, None)
                    self.lists.pop(str(att_prefix) + event_id, None)
                    removed += 1
            return removed
        if "microauth-usage-release-v3" in script:
            events, ready, leases, owners = keys
            owner, delay_ms, _ttl, *event_ids = args
            released = 0
            for event_id in map(str, event_ids):
                if self.hashes.get(owners, {}).get(event_id) == str(owner):
                    self.hashes.get(owners, {}).pop(event_id, None)
                    self.zsets.get(leases, {}).pop(event_id, None)
                    if event_id in self.hashes.get(events, {}):
                        self.zsets.setdefault(ready, {})[event_id] = (
                            self.now_ms + int(delay_ms)
                        )
                    released += 1
            return released
        if "microauth-usage-extend-v3" in script:
            leases, owners = keys
            owner, lease_ms, _ttl, *event_ids = args
            extended = 0
            for event_id in map(str, event_ids):
                if self.hashes.get(owners, {}).get(event_id) == str(owner):
                    self.zsets.setdefault(leases, {})[event_id] = (
                        self.now_ms + int(lease_ms)
                    )
                    extended += 1
            return extended
        if "microauth-usage-dead-letter-v3" in script:
            events, ready, leases, owners, counts, dead = keys
            owner, event_id, record, _ttl, att_prefix = args
            event_id = str(event_id)
            if self.hashes.get(owners, {}).get(event_id) != str(owner):
                return 0
            if event_id in self.hashes.get(events, {}):
                self.hashes.setdefault(dead, {})[event_id] = str(record)
            self.hashes.get(events, {}).pop(event_id, None)
            self.hashes.get(owners, {}).pop(event_id, None)
            self.hashes.get(counts, {}).pop(event_id, None)
            self.zsets.get(ready, {}).pop(event_id, None)
            self.zsets.get(leases, {}).pop(event_id, None)
            self.lists.pop(str(att_prefix) + event_id, None)
            return 1
        raise AssertionError("unexpected Lua script")


def make_store(
    redis: FakeUsageRedis,
    *,
    max_items: int = 100,
    lease_ms: int = 60_000,
) -> RedisUsageStore:
    return RedisUsageStore(
        redis,
        "tenant-scope",
        max_items=max_items,
        lease_ms=lease_ms,
    )


def static_payload(event_id: str) -> dict[str, Any]:
    return {
        "idempotency_key": event_id,
        "api_key_id": API_KEY_ID,
        "status_code": 200,
        "period_start": "2026-08-08T05:00:00Z",
    }


def attachment_for(event_id: str, index: int = 0) -> dict[str, Any]:
    return {"token": f"token-{event_id}-{index}"}


def test_enqueued_events_stay_leased_to_the_recording_worker() -> None:
    redis = FakeUsageRedis()
    recorder = make_store(redis)
    other = make_store(redis)

    async def exercise() -> None:
        await recorder.enqueue_claimed(
            "event-1",
            static_payload("event-1"),
            attachment_for("event-1"),
        )
        # The recorder owns delivery; another healthy worker must not steal
        # an active lease.
        assert await other.claim_due(10) == []
        assert await recorder.pending_count() == 1

    run(exercise())


def test_merges_are_o1_and_reassemble_into_one_counted_event() -> None:
    redis = FakeUsageRedis()
    recorder = make_store(redis, lease_ms=1_000)
    survivor = make_store(redis)

    async def exercise() -> None:
        await recorder.enqueue_claimed(
            "event-1",
            static_payload("event-1"),
            attachment_for("event-1", 0),
        )
        from microauth_fastapi.usage_store import UPSERT_MERGED

        for index in range(1, 4):
            result = await recorder.merge_claimed(
                "event-1",
                attachment_for("event-1", index),
                max_count=500,
            )
            assert result == UPSERT_MERGED
        redis.advance(2_000)
        claimed = await survivor.claim_due(10)
        assert len(claimed) == 1
        event_id, payload = claimed[0]
        assert event_id == "event-1"
        assert payload["item"]["count"] == 4
        assert payload["attachments"] == [
            attachment_for("event-1", index) for index in range(4)
        ]

    run(exercise())


def test_merge_is_fenced_after_lease_recovery_and_capped() -> None:
    redis = FakeUsageRedis()
    recorder = make_store(redis, lease_ms=1_000)
    thief = make_store(redis)

    async def exercise() -> None:
        from microauth_fastapi.usage_store import UPSERT_CAPPED, UPSERT_FENCED

        await recorder.enqueue_claimed(
            "event-1",
            static_payload("event-1"),
            attachment_for("event-1"),
        )
        # Cap reached: no further merges.
        assert (
            await recorder.merge_claimed(
                "event-1",
                attachment_for("event-1", 1),
                max_count=1,
            )
            == UPSERT_CAPPED
        )
        # Another worker recovers the lease; the recorder is fenced out.
        redis.advance(2_000)
        await thief.claim_due(10)
        assert (
            await recorder.merge_claimed(
                "event-1",
                attachment_for("event-1", 2),
                max_count=500,
            )
            == UPSERT_FENCED
        )
        # A merge can never recreate an event that was already delivered.
        await thief.ack(["event-1"])
        assert (
            await thief.merge_claimed(
                "event-1",
                attachment_for("event-1", 3),
                max_count=500,
            )
            == UPSERT_FENCED
        )
        assert await thief.pending_count() == 0

    run(exercise())


def test_expired_leases_are_recovered_by_another_worker() -> None:
    redis = FakeUsageRedis()
    dead_worker = make_store(redis, lease_ms=1_000)
    survivor = make_store(redis)

    async def exercise() -> None:
        await dead_worker.enqueue_claimed(
            "event-1",
            static_payload("event-1"),
            attachment_for("event-1"),
        )
        redis.advance(2_000)
        claimed = await survivor.claim_due(10)
        assert [event_id for event_id, _ in claimed] == ["event-1"]
        assert claimed[0][1] == {
            "item": {**static_payload("event-1"), "count": 1},
            "attachments": [attachment_for("event-1")],
        }
        # The survivor now holds the lease; the original owner's ack is
        # rejected by the fence.
        assert await dead_worker.ack(["event-1"]) == 0
        assert await survivor.pending_count() == 1
        assert await survivor.ack(["event-1"]) == 1
        assert await survivor.pending_count() == 0

    run(exercise())


def test_release_returns_events_to_the_ready_queue_with_backoff() -> None:
    redis = FakeUsageRedis()
    store = make_store(redis)

    async def exercise() -> None:
        await store.enqueue_claimed(
            "event-1",
            static_payload("event-1"),
            attachment_for("event-1"),
        )
        assert await store.release(["event-1"], delay_ms=5_000) == 1
        # Not due yet: the backoff defers redelivery.
        assert await store.claim_due(10) == []
        redis.advance(6_000)
        claimed = await store.claim_due(10)
        assert [event_id for event_id, _ in claimed] == ["event-1"]

    run(exercise())


def test_queue_capacity_is_enforced_atomically() -> None:
    redis = FakeUsageRedis()
    store = make_store(redis, max_items=1)

    async def exercise() -> None:
        await store.enqueue_claimed(
            "event-1",
            static_payload("event-1"),
            attachment_for("event-1"),
        )
        with pytest.raises(UsageQueueFull):
            await store.enqueue_claimed(
                "event-2",
                static_payload("event-2"),
                attachment_for("event-2"),
            )

    run(exercise())


def test_dead_letter_is_fenced_and_preserves_the_record() -> None:
    redis = FakeUsageRedis()
    owner = make_store(redis, lease_ms=1_000)
    thief = make_store(redis)

    async def exercise() -> None:
        await owner.enqueue_claimed(
            "event-1",
            static_payload("event-1"),
            attachment_for("event-1"),
        )
        redis.advance(2_000)
        await thief.claim_due(10)
        # The original owner lost its lease and cannot dead-letter.
        assert await owner.dead_letter("event-1", "boom") is False
        assert await thief.dead_letter("event-1", "boom") is True
        assert await thief.pending_count() == 0
        dead = redis.hashes[thief._dead_key]
        assert "event-1" in dead

    run(exercise())


def test_reporter_records_durably_and_acks_after_delivery() -> None:
    redis = FakeUsageRedis()
    store = make_store(redis)
    client = ScriptedClient([acknowledge])
    reporter = UsageReporter(client, 60, spool_path=None, store=store)

    async def exercise() -> None:
        event_id = await reporter.record(API_KEY_ID, 200)
        # Durable before delivery: the event exists in Redis while queued.
        assert await store.pending_count() == 1
        await reporter.flush()
        assert reporter.pending_items == 0
        assert await store.pending_count() == 0
        assert client.calls[0][0]["idempotency_key"] == event_id

    run(exercise())


def test_second_reporter_recovers_a_dead_workers_events() -> None:
    redis = FakeUsageRedis()
    dead_store = make_store(redis, lease_ms=1_000)
    dead_client = ScriptedClient([])
    dead_reporter = UsageReporter(
        dead_client,
        60,
        spool_path=None,
        store=dead_store,
    )

    survivor_store = make_store(redis)
    survivor_client = ScriptedClient([acknowledge])
    restored: list[dict[str, Any]] = []

    async def on_restored(attachments: list[dict[str, Any]]) -> None:
        restored.extend(attachments)

    survivor = UsageReporter(
        survivor_client,
        60,
        spool_path=None,
        store=survivor_store,
        on_restored=on_restored,
    )

    async def exercise() -> None:
        event_id = await dead_reporter.record(
            API_KEY_ID,
            200,
            attachment={"token": "reservation-1", "spend_micro": 25},
        )
        # The recording worker dies without flushing; its lease expires.
        redis.advance(2_000)
        await survivor.start()
        await survivor.flush()
        await survivor.aclose()
        assert survivor_client.calls[0][0]["idempotency_key"] == event_id
        assert await survivor_store.pending_count() == 0

    run(exercise())
    assert restored == [{"spend_micro": 25, "token": "reservation-1"}]


def test_shutdown_hands_undelivered_events_back_to_the_queue() -> None:
    redis = FakeUsageRedis()
    store = make_store(redis)
    from microauth_fastapi.exceptions import MicroAuthAPIError

    failing_client = ScriptedClient([MicroAuthAPIError(503, "down")])
    reporter = UsageReporter(
        failing_client,
        60,
        spool_path=None,
        store=store,
    )

    async def exercise() -> None:
        await reporter.record(API_KEY_ID, 200)
        # With a durable queue, shutdown releases the claim for another
        # worker instead of raising a drain error.
        await reporter.aclose()
        assert reporter.pending_items == 0
        assert await store.pending_count() == 1

        rescuer_client = ScriptedClient([acknowledge])
        rescuer = UsageReporter(
            rescuer_client,
            60,
            spool_path=None,
            store=make_store(redis),
        )
        await rescuer.start()
        await rescuer.flush()
        await rescuer.aclose()
        assert len(rescuer_client.calls) == 1

    run(exercise())


def test_events_past_the_45_day_age_limit_are_dead_lettered() -> None:
    redis = FakeUsageRedis()
    store = make_store(redis)
    client = ScriptedClient([])
    rejected: list[dict[str, Any]] = []

    async def on_rejected(attachments: list[dict[str, Any]]) -> None:
        rejected.extend(attachments)

    reporter = UsageReporter(
        client,
        60,
        spool_path=None,
        store=store,
        on_rejected=on_rejected,
    )

    async def exercise() -> None:
        stale_start = datetime.now(timezone.utc) - timedelta(days=46)
        await reporter.record(
            API_KEY_ID,
            200,
            occurred_at=stale_start,
            attachment={"token": "stale-reservation"},
        )
        await reporter.flush()
        assert reporter.pending_items == 0
        assert await store.pending_count() == 0
        # The API would terminally reject it; no delivery was attempted.
        assert client.calls == []

    run(exercise())
    assert rejected == [{"token": "stale-reservation"}]


def test_redis_outage_at_record_degrades_without_losing_the_request() -> None:
    redis = FakeUsageRedis()
    store = make_store(redis)
    client = ScriptedClient([acknowledge])
    reporter = UsageReporter(client, 60, spool_path=None, store=store)

    async def exercise() -> None:
        redis.fail = True
        event_id = await reporter.record(API_KEY_ID, 200)
        assert reporter.pending_items == 1
        redis.fail = False
        await reporter.flush()
        assert reporter.pending_items == 0
        assert client.calls[0][0]["idempotency_key"] == event_id

    run(exercise())
