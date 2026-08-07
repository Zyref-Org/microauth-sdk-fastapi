from __future__ import annotations

import asyncio
import json
import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from microauth_fastapi.client import APIClient
from microauth_fastapi.exceptions import (
    MicroAuthAPIError,
    MicroAuthAuthorizationError,
    UsageAcknowledgementError,
    UsageDrainError,
    UsageQueueFull,
)
from microauth_fastapi.reporter import UsageReporter

Outcome = dict[str, Any] | Exception | Callable[[list[dict[str, Any]]], dict[str, Any]]


class ScriptedClient:
    def __init__(self, outcomes: list[Outcome]) -> None:
        self.outcomes = outcomes
        self.calls: list[list[dict[str, Any]]] = []

    async def report_usage(self, items: list[dict[str, Any]]) -> dict[str, Any]:
        copied = [dict(item) for item in items]
        self.calls.append(copied)
        if not self.outcomes:
            raise AssertionError("unexpected usage call")
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        if callable(outcome):
            return outcome(copied)
        return outcome


def acknowledge(
    items: list[dict[str, Any]],
    status: str = "accepted",
) -> dict[str, Any]:
    return {
        "results": [
            {
                "idempotency_key": item["idempotency_key"],
                "status": status,
            }
            for item in items
        ]
    }


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


def test_wire_payload_uses_canonical_names_and_stable_retry() -> None:
    client = ScriptedClient(
        [
            MicroAuthAPIError(503, "unavailable"),
            acknowledge,
        ]
    )
    reporter = UsageReporter(client, 60, spool_path=None)
    event_id = reporter.record(
        "11111111-1111-4111-8111-111111111111",
        207,
        usage_policy_id="22222222-2222-4222-8222-222222222222",
    )

    with pytest.raises(MicroAuthAPIError):
        run(reporter.flush())
    run(reporter.flush())

    assert client.calls[0] == client.calls[1]
    assert client.calls[0] == [
        {
            "idempotency_key": event_id,
            "api_key_id": "11111111-1111-4111-8111-111111111111",
            "usage_policy_id": "22222222-2222-4222-8222-222222222222",
            "status_code": 207,
            "count": 1,
            "period_start": client.calls[0][0]["period_start"],
        }
    ]
    assert "key_id" not in client.calls[0][0]
    assert "requests" not in client.calls[0][0]


def test_http_transport_retry_keeps_identical_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import microauth_fastapi.client as client_module

    monkeypatch.setattr(client_module, "_BACKOFF", 0)
    attempts: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        attempts.append(body)
        if len(attempts) == 1:
            raise httpx.ReadTimeout("timed out", request=request)
        return httpx.Response(200, json=acknowledge(body["items"]))

    async def exercise() -> None:
        external = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        api = APIClient(
            "https://api.microauth.test",
            "mas_test",
            1,
            http_client=external,
        )
        reporter = UsageReporter(api, 60, spool_path=None)
        reporter.record("11111111-1111-4111-8111-111111111111", 218)
        await reporter.flush()
        await external.aclose()

    run(exercise())
    assert attempts[0] == attempts[1]


def test_record_is_journaled_before_flush_and_restored(tmp_path: Path) -> None:
    spool = tmp_path / "usage.sqlite3"
    first = UsageReporter(ScriptedClient([]), 60, spool_path=spool)
    event_id = first.record(
        "11111111-1111-4111-8111-111111111111",
        201,
        attachment={"token": "reservation-1", "spend_micro": 10},
    )

    second_client = ScriptedClient([acknowledge])
    restored: list[dict[str, Any]] = []

    async def on_restored(attachments: list[dict[str, Any]]) -> None:
        restored.extend(attachments)

    second = UsageReporter(
        second_client,
        60,
        spool_path=spool,
        on_restored=on_restored,
    )

    async def restore_and_flush() -> None:
        await second.start()
        await second.flush()
        await second.aclose()

    run(restore_and_flush())
    assert second_client.calls[0][0]["idempotency_key"] == event_id
    assert restored == [{"spend_micro": 10, "token": "reservation-1"}]


def test_legacy_journal_is_migrated_to_canonical_payload(tmp_path: Path) -> None:
    spool = tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(spool)
    connection.execute(
        """
        CREATE TABLE usage_events (
            idempotency_key TEXT PRIMARY KEY,
            key_id TEXT NOT NULL,
            status_code INTEGER NOT NULL,
            requests INTEGER NOT NULL,
            period_start TEXT NOT NULL
        )
        """
    )
    connection.execute(
        "INSERT INTO usage_events VALUES (?, ?, ?, ?, ?)",
        (
            "legacy-event-123",
            "11111111-1111-4111-8111-111111111111",
            200,
            3,
            "2026-08-04T00:00:00Z",
        ),
    )
    connection.commit()
    connection.close()

    client = ScriptedClient([acknowledge])
    reporter = UsageReporter(client, 60, spool_path=spool)

    async def exercise() -> None:
        await reporter.start()
        await reporter.flush()
        await reporter.aclose()

    run(exercise())
    assert client.calls[0][0]["api_key_id"].startswith("11111111")
    assert client.calls[0][0]["count"] == 3


def test_per_item_rejection_is_dead_lettered_without_blocking(
    tmp_path: Path,
) -> None:
    def partial(items: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "results": [
                {
                    "idempotency_key": items[0]["idempotency_key"],
                    "status": "accepted",
                },
                {
                    "idempotency_key": items[1]["idempotency_key"],
                    "status": "rejected",
                    "detail": "unknown key",
                },
                {
                    "idempotency_key": items[2]["idempotency_key"],
                    "status": "duplicate",
                },
            ]
        }

    spool = tmp_path / "usage.sqlite3"
    client = ScriptedClient([partial])
    rejected_attachments: list[dict[str, Any]] = []

    async def rejected(items: list[dict[str, Any]]) -> None:
        rejected_attachments.extend(items)

    reporter = UsageReporter(
        client,
        60,
        spool_path=spool,
        on_rejected=rejected,
    )
    reporter.record("11111111-1111-4111-8111-111111111111", 200)
    rejected_id = reporter.record(
        "22222222-2222-4222-8222-222222222222",
        200,
        attachment={"token": "terminal"},
    )
    reporter.record("33333333-3333-4333-8333-333333333333", 200)

    run(reporter.flush())
    assert reporter.pending_items == 0
    assert rejected_attachments == [{"token": "terminal"}]
    connection = sqlite3.connect(spool)
    rows = connection.execute(
        "SELECT idempotency_key, detail FROM usage_dead_letters"
    ).fetchall()
    connection.close()
    assert rows == [(rejected_id, "unknown key")]


def test_batch_level_terminal_error_is_bisected_to_isolate_poison() -> None:
    poison_key = "22222222-2222-4222-8222-222222222222"

    def outcome(items: list[dict[str, Any]]) -> dict[str, Any]:
        if any(item["api_key_id"] == poison_key for item in items):
            raise MicroAuthAPIError(422, "invalid api_key_id")
        return acknowledge(items)

    client = ScriptedClient([outcome] * 5)
    reporter = UsageReporter(client, 60, spool_path=None)
    reporter.record("11111111-1111-4111-8111-111111111111", 200)
    reporter.record(poison_key, 200)
    reporter.record("33333333-3333-4333-8333-333333333333", 200)

    run(reporter.flush())
    assert reporter.pending_items == 0
    assert any(len(call) == 3 for call in client.calls)
    assert any(
        len(call) == 1 and call[0]["api_key_id"] == poison_key
        for call in client.calls
    )
    assert any(
        len(call) == 1
        and call[0]["api_key_id"].startswith("33333333")
        for call in client.calls
    )


@pytest.mark.parametrize("status", [429, 500, 503])
def test_transient_http_failures_remain_queued(status: int) -> None:
    client = ScriptedClient([MicroAuthAPIError(status, "retry"), acknowledge])
    reporter = UsageReporter(client, 60, spool_path=None)
    reporter.record("11111111-1111-4111-8111-111111111111", 200)
    with pytest.raises(MicroAuthAPIError):
        run(reporter.flush())
    assert reporter.pending_items == 1
    run(reporter.flush())
    assert reporter.pending_items == 0


@pytest.mark.parametrize("status", [401, 403])
def test_authoritative_auth_failure_is_signalled_and_retained(status: int) -> None:
    failures: list[int] = []

    async def invalid(error: MicroAuthAuthorizationError) -> None:
        failures.append(error.status_code)

    reporter = UsageReporter(
        ScriptedClient(
            [
                MicroAuthAuthorizationError(status, "denied"),
                acknowledge,
            ]
        ),
        60,
        spool_path=None,
        on_authorization_failure=invalid,
    )
    reporter.record("11111111-1111-4111-8111-111111111111", 200)
    with pytest.raises(MicroAuthAuthorizationError):
        run(reporter.flush())
    assert failures == [status]
    assert reporter.pending_items == 1
    run(reporter.flush())


def test_malformed_partial_ack_does_not_block_later_chunk() -> None:
    def omitted(items: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "results": [
                {
                    "idempotency_key": items[0]["idempotency_key"],
                    "status": "accepted",
                }
            ]
        }

    client = ScriptedClient([omitted, acknowledge, acknowledge])
    reporter = UsageReporter(client, 60, batch_size=2, spool_path=None)
    ids = [
        reporter.record(f"{index:08d}-1111-4111-8111-111111111111", 200)
        for index in range(3)
    ]

    with pytest.raises(UsageAcknowledgementError):
        run(reporter.flush())
    assert reporter.pending_items == 1
    assert client.calls[1][0]["idempotency_key"] == ids[2]
    run(reporter.flush())
    assert client.calls[2][0]["idempotency_key"] == ids[1]


def test_completed_requests_are_frozen_and_batched_consistently() -> None:
    client = ScriptedClient([acknowledge, acknowledge, acknowledge])
    reporter = UsageReporter(client, 60, batch_size=2, spool_path=None)
    for _ in range(5):
        reporter.record("11111111-1111-4111-8111-111111111111", 200)
    run(reporter.flush())
    assert [len(call) for call in client.calls] == [2, 2, 1]
    assert all(item["count"] == 1 for call in client.calls for item in call)
    assert len(
        {
            item["idempotency_key"]
            for call in client.calls
            for item in call
        }
    ) == 5


def test_queue_is_bounded_and_reserved_capacity_is_consumed() -> None:
    reporter = UsageReporter(
        ScriptedClient([]),
        60,
        max_items=1,
        spool_path=None,
    )
    reservation = reporter.reserve()
    with pytest.raises(UsageQueueFull):
        reporter.reserve()
    reporter.record(
        "11111111-1111-4111-8111-111111111111",
        299,
        reservation=reservation,
    )
    assert reporter.pending_items == 1


def test_graceful_shutdown_drains_or_raises_typed_error() -> None:
    success = UsageReporter(
        ScriptedClient([acknowledge]),
        60,
        spool_path=None,
    )
    success.record("11111111-1111-4111-8111-111111111111", 200)
    run(success.aclose())

    failure = UsageReporter(
        ScriptedClient([MicroAuthAPIError(503, "down")]),
        60,
        spool_path=None,
    )
    failure.record("11111111-1111-4111-8111-111111111111", 200)
    with pytest.raises(UsageDrainError) as caught:
        run(failure.aclose())
    assert caught.value.pending_items == 1


@pytest.mark.parametrize("status", [99, 600, True, "200"])
def test_status_code_validation(status: Any) -> None:
    reporter = UsageReporter(ScriptedClient([]), 60, spool_path=None)
    with pytest.raises((TypeError, ValueError)):
        reporter.record("11111111-1111-4111-8111-111111111111", status)


def test_interval_flushes_without_a_follow_up_record() -> None:
    client = ScriptedClient([acknowledge])
    reporter = UsageReporter(client, 0.02, spool_path=None)

    async def exercise() -> None:
        await reporter.start()
        reporter.record("11111111-1111-4111-8111-111111111111", 200)
        deadline = asyncio.get_running_loop().time() + 1.0
        while reporter.pending_items and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.01)
        assert reporter.pending_items == 0
        await reporter.aclose()

    run(exercise())
    assert len(client.calls) == 1


def test_response_flush_includes_an_event_recorded_during_delivery() -> None:
    first_started = asyncio.Event()
    release_first = asyncio.Event()

    class BlockingClient:
        def __init__(self) -> None:
            self.calls: list[list[dict[str, Any]]] = []

        async def report_usage(
            self,
            items: list[dict[str, Any]],
        ) -> dict[str, Any]:
            self.calls.append([dict(item) for item in items])
            if len(self.calls) == 1:
                first_started.set()
                await release_first.wait()
            return acknowledge(items)

    async def exercise() -> list[list[dict[str, Any]]]:
        client = BlockingClient()
        reporter = UsageReporter(client, 60, spool_path=None)
        reporter.record("11111111-1111-4111-8111-111111111111", 200)
        first = asyncio.create_task(reporter.flush_on_response())
        await first_started.wait()
        reporter.record("22222222-2222-4222-8222-222222222222", 201)
        second = asyncio.create_task(reporter.flush_on_response())
        release_first.set()
        await asyncio.gather(first, second)
        assert reporter.pending_items == 0
        return client.calls

    calls = run(exercise())
    assert [len(call) for call in calls] == [1, 1]


def test_explicit_drain_waits_for_an_already_inflight_event() -> None:
    async def exercise() -> None:
        started = asyncio.Event()
        release = asyncio.Event()

        class BlockingClient:
            async def report_usage(
                self,
                items: list[dict[str, Any]],
            ) -> dict[str, Any]:
                started.set()
                await release.wait()
                return acknowledge(items)

        reporter = UsageReporter(BlockingClient(), 60, spool_path=None)
        reporter.record("11111111-1111-4111-8111-111111111111", 200)
        delivery = asyncio.create_task(reporter.flush())
        await started.wait()
        drain = asyncio.create_task(reporter.flush_on_response())
        await asyncio.sleep(0)
        assert not drain.done()
        release.set()
        await asyncio.gather(delivery, drain)
        assert reporter.pending_items == 0

    run(exercise())


def test_shutdown_cancels_a_stuck_response_flush() -> None:
    async def exercise() -> None:
        started = asyncio.Event()

        class StuckClient:
            async def report_usage(
                self,
                items: list[dict[str, Any]],
            ) -> dict[str, Any]:
                del items
                started.set()
                await asyncio.Event().wait()
                raise AssertionError("unreachable")

        reporter = UsageReporter(
            StuckClient(),
            60,
            shutdown_timeout=0.02,
            spool_path=None,
        )
        reporter.record("11111111-1111-4111-8111-111111111111", 200)
        response_flush = asyncio.create_task(reporter.flush_on_response())
        await started.wait()
        with pytest.raises(UsageDrainError):
            await reporter.aclose()
        await asyncio.gather(response_flush, return_exceptions=True)
        assert response_flush.done()
        assert reporter._response_flush_task is None
        assert reporter.pending_items == 1

    run(exercise())
