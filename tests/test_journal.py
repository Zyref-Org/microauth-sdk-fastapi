"""Behavioral tests for the append-only WAL usage journal."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from test_reporter import ScriptedClient, acknowledge

from microauth_fastapi.journal import WalJournal
from microauth_fastapi.reporter import UsageReporter

API_KEY_ID = "11111111-1111-4111-8111-111111111111"


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


def wal_files(tmp_path: Path) -> list[Path]:
    return sorted(tmp_path.glob("*.wal"))


def test_merges_append_one_line_per_request_instead_of_rewriting(
    tmp_path: Path,
) -> None:
    """The p99 killer: journal cost per merged request must be O(1)."""

    spool = tmp_path / "usage.sqlite3"
    reporter = UsageReporter(ScriptedClient([]), 60, spool_path=spool)

    async def exercise() -> str:
        first = await reporter.record(API_KEY_ID, 200, attachment={"n": 0})
        for index in range(1, 50):
            merged = await reporter.record(
                API_KEY_ID,
                200,
                attachment={"n": index},
            )
            assert merged == first
        return first

    event_id = run(exercise())
    (journal_file,) = wal_files(tmp_path)
    lines = [line for line in journal_file.read_text().splitlines() if line]
    # One create plus one merge line per subsequent request; no rewrites.
    assert len(lines) == 50
    ops = [json.loads(line)["op"] for line in lines]
    assert ops == ["create"] + ["merge"] * 49

    journal = reporter._journal
    assert journal is not None
    replayed = journal.replay_own()
    assert replayed[event_id]["item"]["count"] == 50
    assert len(replayed[event_id]["attachments"]) == 50


def test_replay_tolerates_a_torn_tail_line_from_a_crash(tmp_path: Path) -> None:
    spool = tmp_path / "usage.sqlite3"
    reporter = UsageReporter(ScriptedClient([]), 60, spool_path=spool)
    run(reporter.record(API_KEY_ID, 200))
    run(reporter.record(API_KEY_ID, 201))
    (journal_file,) = wal_files(tmp_path)

    # A crash mid-append leaves a torn final line.
    with open(journal_file, "ab") as handle:
        handle.write(b'{"v":1,"op":"merge","id":"trunc')

    adopter = UsageReporter(
        ScriptedClient([acknowledge]),
        60,
        spool_path=spool,
        spool_claim_grace=0,
    )

    async def restore() -> int:
        await adopter.start()
        try:
            return adopter.pending_requests
        finally:
            await adopter.aclose()

    assert run(restore()) == 2


def test_graceful_shutdown_disowns_the_journal_for_instant_adoption(
    tmp_path: Path,
) -> None:
    spool = tmp_path / "usage.sqlite3"

    class FailingClient:
        async def report_usage(self, items: list[dict[str, Any]]) -> dict[str, Any]:
            raise OSError("network down at shutdown")

    first = UsageReporter(FailingClient(), 60, spool_path=spool, shutdown_timeout=0.2)
    event_id = run(first.record(API_KEY_ID, 200))
    # aclose cannot deliver (client fails) but must hand the journal back
    # without raising: the file is backdated for immediate adoption.
    run(first.aclose())

    second_client = ScriptedClient([acknowledge])
    # Default 120s grace: only the disowned backdating makes this adoptable.
    second = UsageReporter(second_client, 60, spool_path=spool)

    async def adopt_and_deliver() -> None:
        await second.start()
        await second.flush()
        await second.aclose()

    run(adopt_and_deliver())
    assert second_client.calls[0][0]["idempotency_key"] == event_id
    # The adopted file was consumed and the adopter drained cleanly.
    assert wal_files(tmp_path) == []


def test_compaction_drops_acknowledged_operations(tmp_path: Path) -> None:
    journal = WalJournal(tmp_path / "usage.sqlite3", max_items=100, grace_seconds=0)
    event = {
        "item": {
            "idempotency_key": "keep-1",
            "api_key_id": API_KEY_ID,
            "status_code": 200,
            "count": 2,
            "period_start": "2026-08-08T10:00:00Z",
        },
        "attachments": [],
    }
    from microauth_fastapi.journal import JournalOp

    journal.apply([JournalOp(op="create", event=event)], {})
    journal.apply(
        [JournalOp(op="ack", event_ids=["gone-1", "gone-2"])],
        {"keep-1": event},
    )
    assert journal.path.exists()
    before = journal.path.read_text()
    assert "gone-1" in before

    journal.compact({"keep-1": event})
    after = [line for line in journal.path.read_text().splitlines() if line]
    assert len(after) == 1
    record = json.loads(after[0])
    assert record["op"] == "create"
    assert record["event"]["item"]["idempotency_key"] == "keep-1"

    # Replay of the compacted file reproduces exactly the live state.
    assert set(journal.replay_own()) == {"keep-1"}


def test_adoption_rename_race_is_won_by_exactly_one_process(tmp_path: Path) -> None:
    base = tmp_path / "usage.sqlite3"
    dead = WalJournal(base, max_items=100, grace_seconds=0)
    from microauth_fastapi.journal import JournalOp

    event = {
        "item": {
            "idempotency_key": "orphan-1",
            "api_key_id": API_KEY_ID,
            "status_code": 200,
            "count": 1,
            "period_start": "2026-08-08T10:00:00Z",
        },
        "attachments": [],
    }
    dead.apply([JournalOp(op="create", event=event)], {})
    dead.disown()

    # A real grace keeps in-flight adoptions (fresh mtime) off-limits, so the
    # only claimable file is the disowned one, and its rename is atomic.
    adopter_a = WalJournal(base, max_items=100, grace_seconds=60)
    adopter_b = WalJournal(base, max_items=100, grace_seconds=60)
    state_a, claimed_a = adopter_a.adopt_orphans()
    state_b, claimed_b = adopter_b.adopt_orphans()

    # Exactly one adopter got the file; the other saw nothing.
    assert sorted([len(state_a), len(state_b)]) == [0, 1]
    winner_state = state_a or state_b
    assert winner_state["orphan-1"]["item"]["count"] == 1
    adopter_a.remove_adopted(claimed_a)
    adopter_b.remove_adopted(claimed_b)
    assert wal_files(tmp_path) == []
