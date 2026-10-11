"""Receipts, charge reconciliation, hooks and delivery stats."""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from support import POLICY_ID, Reporter
from test_reporter import ScriptedClient

from microauth_fastapi import UsageReceipt, UsageRejection
from microauth_fastapi._clock import ServerClock
from microauth_fastapi.exceptions import MicroAuthAPIError, UsageStoreError
from microauth_fastapi.journal import WalJournal
from microauth_fastapi.usage_store import RedisUsageStore

API_KEY_ID = "11111111-1111-4111-8111-111111111111"
OTHER_KEY_ID = "22222222-2222-4222-8222-222222222222"
CUSTOMER_ID = "2b7c1f8e-5d34-4a9b-8c21-6e0f3d9a7b55"
RECORDED_AT = "2026-10-11T09:30:05.25Z"


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


def charge(
    prices: dict[int, int],
    *,
    outcome: str = "accepted",
    with_receipt: bool = True,
) -> Callable[[list[dict[str, Any]]], dict[str, Any]]:
    """A usage response that charges count times the status's price."""

    def respond(items: list[dict[str, Any]]) -> dict[str, Any]:
        results = []
        for item in items:
            result: dict[str, Any] = {
                "idempotency_key": item["idempotency_key"],
                "status": outcome,
            }
            if with_receipt:
                result.update(
                    customer_id=CUSTOMER_ID,
                    charged_micro=item["count"] * prices.get(item["status_code"], 0),
                    recorded_at=RECORDED_AT,
                )
            results.append(result)
        return {"results": results}

    return respond


def test_every_delivered_item_gets_a_receipt_that_reconciles() -> None:
    receipts: list[UsageReceipt] = []
    reporter = Reporter(ScriptedClient([charge({200: 25})]), 60, on_receipts=receipts.extend)

    async def exercise() -> None:
        await reporter.record(API_KEY_ID, 200, unit_charge_micro=25)
        await reporter.record(API_KEY_ID, 200, unit_charge_micro=25)
        await reporter.record(API_KEY_ID, 404, unit_charge_micro=0)
        await reporter.flush()

    run(exercise())
    by_status = {receipt.status_code: receipt for receipt in receipts}
    billable = by_status[200]
    assert billable.outcome == "accepted"
    assert (billable.count, billable.charged_micro, billable.expected_charge_micro) == (2, 50, 50)
    assert billable.charge_matches is True
    assert billable.customer_id == CUSTOMER_ID
    assert billable.api_key_id == API_KEY_ID
    assert billable.usage_policy_id == POLICY_ID
    assert billable.recorded_at == datetime(2026, 10, 11, 9, 30, 5, 250_000, tzinfo=timezone.utc)
    assert billable.period_start.tzinfo is not None
    assert (billable.period_start.minute, billable.period_start.second) == (0, 0)
    assert billable.delivered_at.tzinfo is not None
    free = by_status[404]
    assert (free.charged_micro, free.expected_charge_micro, free.charge_matches) == (0, 0, True)

    stats = reporter.stats()
    assert (stats.delivered_items, stats.delivered_requests) == (2, 3)
    assert stats.charged_micro == 50
    assert stats.charge_mismatches == 0
    assert stats.duplicate_items == 0
    assert stats.last_delivery_at is not None
    assert (stats.queued_items, stats.queued_requests, stats.oldest_queued_at) == (0, 0, None)


def test_a_charge_that_differs_from_the_enforced_price_is_flagged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    receipts: list[UsageReceipt] = []
    reporter = Reporter(ScriptedClient([charge({200: 30})]), 60, on_receipts=receipts.extend)

    async def exercise() -> None:
        await reporter.record(API_KEY_ID, 200, unit_charge_micro=25)
        await reporter.flush()

    with caplog.at_level(logging.ERROR, logger="microauth"):
        run(exercise())
    (receipt,) = receipts
    assert receipt.charge_matches is False
    assert reporter.stats().charge_mismatches == 1
    assert "charged 30 micro-USD" in caplog.text
    assert "the SDK expected 25" in caplog.text


def test_items_priced_differently_are_never_merged() -> None:
    client = ScriptedClient([charge({200: 25})])
    reporter = Reporter(client, 60)

    async def exercise() -> None:
        first = await reporter.record(API_KEY_ID, 200, unit_charge_micro=25)
        # A price change between requests opens a new item, so each item's
        # expected charge is a single price times its count.
        repriced = await reporter.record(API_KEY_ID, 200, unit_charge_micro=40)
        assert first != repriced
        assert await reporter.record(API_KEY_ID, 200, unit_charge_micro=25) == first
        await reporter.flush()

    run(exercise())
    assert sorted(item["count"] for item in client.calls[0]) == [1, 2]


def test_unknown_amounts_are_not_reported_as_mismatches(
    caplog: pytest.LogCaptureFixture,
) -> None:
    receipts: list[UsageReceipt] = []
    reporter = Reporter(
        ScriptedClient(
            [
                charge({200: 25}),
                charge({200: 25}, with_receipt=False),
                charge({200: 25}, with_receipt=False),
            ]
        ),
        60,
        on_receipts=receipts.extend,
    )

    async def exercise() -> None:
        # Admitted elsewhere (no unit price known here): nothing to compare.
        await reporter.record(API_KEY_ID, 200)
        await reporter.flush()
        for _ in range(2):
            await reporter.record(API_KEY_ID, 200, unit_charge_micro=25)
            await reporter.flush()

    with caplog.at_level(logging.WARNING, logger="microauth"):
        run(exercise())
    assert [receipt.charge_matches for receipt in receipts] == [None, None, None]
    assert receipts[0].expected_charge_micro is None
    assert receipts[1].charged_micro is None
    assert reporter.stats().charge_mismatches == 0
    assert caplog.text.count("without saying what it charged") == 1


def test_duplicates_carry_the_original_receipt() -> None:
    receipts: list[UsageReceipt] = []
    reporter = Reporter(
        ScriptedClient([charge({200: 25}, outcome="duplicate")]),
        60,
        on_receipts=receipts.extend,
    )

    async def exercise() -> None:
        await reporter.record(API_KEY_ID, 200, unit_charge_micro=25)
        await reporter.flush()

    run(exercise())
    (receipt,) = receipts
    assert receipt.outcome == "duplicate"
    assert receipt.charged_micro == 25
    assert receipt.charge_matches is True
    assert reporter.stats().duplicate_items == 1


def test_async_hooks_are_awaited_and_sync_hooks_run_off_the_event_loop() -> None:
    seen_async: list[str] = []
    sync_threads: list[int] = []

    async def collect(receipts: list[UsageReceipt]) -> None:
        await asyncio.sleep(0)
        seen_async.extend(receipt.idempotency_key for receipt in receipts)

    def export(receipts: list[UsageReceipt]) -> None:
        sync_threads.append(threading.get_ident())

    async def exercise() -> tuple[str, int]:
        loop_thread = threading.get_ident()
        first = Reporter(ScriptedClient([charge({200: 25})]), 60, on_receipts=collect)
        event_id = await first.record(API_KEY_ID, 200)
        await first.flush()
        second = Reporter(ScriptedClient([charge({200: 25})]), 60, on_receipts=export)
        await second.record(API_KEY_ID, 200)
        await second.flush()
        return event_id, loop_thread

    event_id, loop_thread = run(exercise())
    assert seen_async == [event_id]
    assert len(sync_threads) == 1 and sync_threads[0] != loop_thread


def test_a_failing_or_slow_hook_never_blocks_delivery(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def broken(receipts: list[UsageReceipt]) -> None:
        raise RuntimeError("metrics exporter is down")

    async def stuck(receipts: list[UsageReceipt]) -> None:
        await asyncio.sleep(30)

    async def exercise(hook: Any) -> Reporter:
        reporter = Reporter(
            ScriptedClient([charge({200: 25})]),
            60,
            on_receipts=hook,
            hook_timeout=0.05,
        )
        await reporter.record(API_KEY_ID, 200)
        await reporter.flush()
        return reporter

    started = time.monotonic()
    with caplog.at_level(logging.ERROR, logger="microauth"):
        for hook in (broken, stuck):
            reporter = run(exercise(hook))
            assert reporter.pending_items == 0
            assert reporter.stats().hook_failures == 1
            assert reporter.stats().delivered_items == 1
    assert time.monotonic() - started < 5
    assert "the on_receipts hook raised" in caplog.text
    assert "did not finish within" in caplog.text


def test_receipts_are_delivered_at_least_once_across_a_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_seen: list[UsageReceipt] = []
    crashed = Reporter(
        ScriptedClient([charge({200: 25})]),
        60,
        journal_dir=tmp_path,
        on_receipts=first_seen.extend,
    )
    real_apply = WalJournal.apply

    def die_before_the_ack(self: WalJournal, ops: Any, pending: Any) -> bool:
        if any(op.op == "ack" for op in ops):
            raise OSError("power lost")
        return real_apply(self, ops, pending)

    monkeypatch.setattr(WalJournal, "apply", die_before_the_ack)
    run(crashed.record(API_KEY_ID, 200, unit_charge_micro=25))
    with pytest.raises(UsageStoreError):
        run(crashed.flush())
    monkeypatch.setattr(WalJournal, "apply", real_apply)
    (delivered,) = first_seen
    assert delivered.outcome == "accepted"

    # The process is gone; its journal still holds the delivered item.
    second_seen: list[UsageReceipt] = []
    survivor = Reporter(
        ScriptedClient([charge({200: 25}, outcome="duplicate")]),
        60,
        journal_dir=tmp_path,
        journal_claim_grace=0,
        on_receipts=second_seen.extend,
    )

    async def recover() -> None:
        await survivor.start()
        await survivor.flush()
        await survivor.aclose()

    run(recover())
    (again,) = second_seen
    assert again.idempotency_key == delivered.idempotency_key
    assert again.outcome == "duplicate"
    # The price enforced at admission survived the crash in the journal.
    assert (again.charged_micro, again.expected_charge_micro) == (25, 25)


def test_refused_items_reach_on_rejections_with_the_reason() -> None:
    rejections: list[UsageRejection] = []

    def refuse(items: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "results": [
                {
                    "idempotency_key": items[0]["idempotency_key"],
                    "status": "rejected",
                    "http_status": 422,
                    "detail": "api_key_id does not belong to this API",
                }
            ]
        }

    reporter = Reporter(ScriptedClient([refuse]), 60, on_rejections=rejections.extend)

    async def exercise() -> str:
        event_id = await reporter.record(API_KEY_ID, 201)
        await reporter.flush()
        return event_id

    event_id = run(exercise())
    (rejection,) = rejections
    assert rejection.idempotency_key == event_id
    assert (rejection.http_status, rejection.detail) == (
        422,
        "api_key_id does not belong to this API",
    )
    assert (rejection.status_code, rejection.count) == (201, 1)
    assert rejection.usage_policy_id == POLICY_ID
    assert rejection.rejected_at.tzinfo is not None
    stats = reporter.stats()
    assert (stats.rejected_items, stats.rejected_requests) == (1, 1)
    assert reporter.pending_items == 0


def test_a_poisoned_item_is_isolated_and_refused_with_its_status() -> None:
    rejections: list[UsageRejection] = []
    receipts: list[UsageReceipt] = []

    def strict(items: list[dict[str, Any]]) -> dict[str, Any]:
        if any(item["api_key_id"] == OTHER_KEY_ID for item in items):
            raise MicroAuthAPIError(422, "api_key_id is not a key of this API")
        return charge({200: 25})(items)

    reporter = Reporter(
        ScriptedClient([strict] * 3),
        60,
        on_receipts=receipts.extend,
        on_rejections=rejections.extend,
    )

    async def exercise() -> None:
        await reporter.record(API_KEY_ID, 200, unit_charge_micro=25)
        await reporter.record(OTHER_KEY_ID, 200, unit_charge_micro=25)
        await reporter.flush()

    run(exercise())
    assert [receipt.api_key_id for receipt in receipts] == [API_KEY_ID]
    (rejection,) = rejections
    assert rejection.api_key_id == OTHER_KEY_ID
    assert (rejection.http_status, rejection.detail) == (422, "api_key_id is not a key of this API")


def test_stats_track_failures_until_the_next_success() -> None:
    reporter = Reporter(
        ScriptedClient(
            [
                MicroAuthAPIError(503, "maintenance"),
                MicroAuthAPIError(503, "maintenance"),
                charge({200: 25}),
            ]
        ),
        60,
    )

    async def exercise() -> None:
        await reporter.record(API_KEY_ID, 200)
        for _ in range(2):
            with pytest.raises(MicroAuthAPIError):
                await reporter.flush()
        failing = reporter.stats()
        assert failing.consecutive_failures == 2
        assert failing.last_error is not None and "maintenance" in failing.last_error
        assert failing.last_error_at is not None
        assert (failing.queued_items, failing.queued_requests) == (1, 1)
        assert failing.oldest_queued_at is not None
        assert failing.durability == "memory"
        await reporter.flush()

    run(exercise())
    recovered = reporter.stats()
    assert recovered.consecutive_failures == 0
    assert recovered.delivered_items == 1
    assert recovered.queued_items == 0


def test_durability_names_where_queued_usage_survives(tmp_path: Path) -> None:
    class AnyRedis:
        pass

    store = RedisUsageStore(AnyRedis(), "scope", max_items=10)
    assert Reporter(ScriptedClient([]), 60).durability == "memory"
    assert Reporter(ScriptedClient([]), 60, journal_dir=tmp_path).durability == "journal"
    assert Reporter(ScriptedClient([]), 60, journal_dir=tmp_path, store=store).durability == "redis"
    assert Reporter(ScriptedClient([]), 60, journal_dir=tmp_path).stats().journal_dir == str(
        tmp_path
    )


def test_usage_hours_follow_microauth_time_not_the_host_clock() -> None:
    clock = ServerClock()
    instant = time.monotonic()
    clock.observe(time.time() + 7_200, instant, instant)  # MicroAuth is 2h ahead
    client = ScriptedClient([charge({200: 25})])
    reporter = Reporter(client, 60, clock=clock)

    def hour(epoch: float) -> str:
        start = datetime.fromtimestamp(epoch, timezone.utc).replace(
            minute=0, second=0, microsecond=0
        )
        return start.isoformat().replace("+00:00", "Z")

    async def exercise() -> None:
        await reporter.record(API_KEY_ID, 200)
        await reporter.flush()

    before = hour(time.time() + 7_200)
    run(exercise())
    after = hour(time.time() + 7_200)
    assert client.calls[0][0]["period_start"] in {before, after}
    assert reporter.stats().clock_offset_seconds == pytest.approx(7_200, abs=1)
