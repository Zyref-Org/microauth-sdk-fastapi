"""Behavioral tests for the checksummed, append-only usage journal."""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from support import POLICY_ID, Reporter
from test_reporter import ScriptedClient, acknowledge

import microauth_fastapi.journal as journal_module
from microauth_fastapi.exceptions import UsageStoreError
from microauth_fastapi.journal import (
    JournalOp,
    WalJournal,
    decode_record,
    encode_record,
    inspect_directory,
    read_api_metadata,
    read_records,
    replay_file,
    write_api_metadata,
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


def wal_files(directory: Path) -> list[Path]:
    return sorted(directory.glob("usage-*.wal"))


def event(key: str = "ev-1", count: int = 1, **item: Any) -> dict[str, Any]:
    return {
        "item": {
            "idempotency_key": key,
            "api_key_id": API_KEY_ID,
            "usage_policy_id": POLICY_ID,
            "status_code": 200,
            "count": count,
            "period_start": CURRENT_HOUR,
            **item,
        },
        "attachments": [],
    }


def journal(directory: Path, *, grace: float = 60) -> WalJournal:
    return WalJournal(directory, max_items=100, grace_seconds=grace)


def ops_in(path: Path) -> list[str]:
    records, damaged, torn = read_records(path)
    assert (damaged, torn) == (0, False)
    return [record["op"] for record in records]


def test_records_carry_a_checksum_that_catches_any_damage() -> None:
    line = encode_record({"op": "create", "event": event()})
    assert line.endswith(b"\n")
    assert decode_record(line) == {"v": 2, "op": "create", "event": event()}
    assert decode_record(line[:-1]) == decode_record(line)

    body_start = line.index(b"{")
    for position in (0, body_start + 5, len(line) - 3):
        damaged = bytearray(line)
        damaged[position] ^= 0x01
        assert decode_record(bytes(damaged)) is None

    unversioned = line.replace(b'"v":2', b'"v":1')
    assert decode_record(unversioned) is None
    assert decode_record(b"") is None
    assert decode_record(b"not a record") is None


def test_merges_append_one_checksummed_line_per_request(tmp_path: Path) -> None:
    """Journal cost per merged request must be O(1), never a rewrite."""

    reporter = Reporter(ScriptedClient([]), 60, journal_dir=tmp_path)

    async def exercise() -> str:
        first = await reporter.record(API_KEY_ID, 200, attachment={"n": 0})
        for index in range(1, 50):
            merged = await reporter.record(API_KEY_ID, 200, attachment={"n": index})
            assert merged == first
        return first

    event_id = run(exercise())
    (journal_file,) = wal_files(tmp_path)
    assert ops_in(journal_file) == ["create"] + ["merge"] * 49

    owned = reporter._journal
    assert owned is not None
    replayed = owned.replay_own()
    assert replayed[event_id]["item"]["count"] == 50
    assert len(replayed[event_id]["attachments"]) == 50


def test_the_journal_keeps_the_expected_charge_but_the_wire_does_not(
    tmp_path: Path,
) -> None:
    client = ScriptedClient([acknowledge])
    reporter = Reporter(client, 60, journal_dir=tmp_path)

    async def exercise() -> None:
        await reporter.record(API_KEY_ID, 200, unit_charge_micro=25)
        await reporter.record(API_KEY_ID, 200, unit_charge_micro=25)
        (journal_file,) = wal_files(tmp_path)
        (created, _merged), _, _ = read_records(journal_file)
        item = created["event"]["item"]
        assert item["unit_charge_micro"] == 25
        assert item["queued_at"] > 1_700_000_000
        await reporter.flush()
        await reporter.aclose()

    run(exercise())
    (wire,) = client.calls[0]
    assert "unit_charge_micro" not in wire
    assert "queued_at" not in wire
    assert wire["count"] == 2


def test_a_torn_tail_is_dropped_without_a_corruption_report(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    writer = Reporter(ScriptedClient([]), 60, journal_dir=tmp_path)
    run(writer.record(API_KEY_ID, 200))
    run(writer.record(API_KEY_ID, 201))
    (journal_file,) = wal_files(tmp_path)

    # A crash mid-append leaves a partial final line behind.
    with open(journal_file, "ab") as handle:
        handle.write(encode_record({"op": "merge", "id": "x"})[:17])
    replay = replay_file(journal_file)
    assert (replay.torn_tail, replay.corrupt_records, len(replay.state)) == (True, 0, 2)

    adopter = Reporter(
        ScriptedClient([acknowledge]),
        60,
        journal_dir=tmp_path,
        journal_claim_grace=0,
    )

    async def restore() -> int:
        await adopter.start()
        try:
            return adopter.pending_requests
        finally:
            await adopter.flush()
            await adopter.aclose()

    with caplog.at_level(logging.WARNING, logger="microauth"):
        assert run(restore()) == 2
    assert "torn last append" in caplog.text
    assert inspect_directory(tmp_path).corrupt_copies == []


def test_mid_file_damage_is_reported_and_kept_for_inspection(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    dead = journal(tmp_path)
    for key in ("ev-1", "ev-2", "ev-3"):
        dead.apply([JournalOp(op="create", event=event(key))], None)
    raw = bytearray(dead.path.read_bytes())
    middle = raw.index(b"ev-2")
    raw[middle] ^= 0x01
    dead.path.write_bytes(bytes(raw))
    dead.disown()

    replay = replay_file(dead.path)
    assert (replay.torn_tail, replay.corrupt_records) == (False, 1)
    assert set(replay.state) == {"ev-1", "ev-3"}

    client = ScriptedClient([acknowledge])
    adopter = Reporter(client, 60, journal_dir=tmp_path)

    async def exercise() -> None:
        await adopter.start()
        await adopter.flush()
        await adopter.aclose()

    with caplog.at_level(logging.ERROR, logger="microauth"):
        run(exercise())
    assert {item["idempotency_key"] for item in client.calls[0]} == {"ev-1", "ev-3"}
    assert "1 damaged record(s)" in caplog.text
    (copy,) = inspect_directory(tmp_path).corrupt_copies
    assert copy.startswith("corrupt-usage-")
    # The copy is the damaged file byte for byte, for whoever investigates.
    assert (tmp_path / copy).read_bytes() == bytes(raw)
    assert wal_files(tmp_path) == []


def test_a_dead_letter_is_durable_before_the_journal_forgets_the_event(
    tmp_path: Path,
) -> None:
    owned = journal(tmp_path)
    owned.apply([JournalOp(op="create", event=event("ev-1"))], None)
    dead_path = tmp_path / f"dead-{owned.owner}.jsonl"
    dead_path.mkdir()  # the dead letter write now fails

    rejection = JournalOp(
        op="dead",
        event_id="ev-1",
        event=event("ev-1"),
        detail="unknown key",
        http_status=422,
        rejected_at=1_791_711_000.0,
    )
    with pytest.raises(UsageStoreError, match="dead letter"):
        owned.apply([rejection], None)
    # The journal still tracks the event, so it is retried, not lost.
    assert set(replay_file(owned.path).state) == {"ev-1"}

    dead_path.rmdir()
    assert owned.apply([rejection], None) is True
    assert replay_file(owned.path).state == {}
    (letter,) = inspect_directory(tmp_path).dead_letters
    assert letter["idempotency_key"] == "ev-1"
    assert letter["http_status"] == 422
    assert letter["detail"] == "unknown key"
    assert letter["rejected_at"] == "2026-10-11T09:30:00Z"
    assert letter["event"]["item"]["count"] == 1


def test_a_failed_append_leaves_no_partial_record_behind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owned = journal(tmp_path)
    owned.apply([JournalOp(op="create", event=event("ev-1"))], None)
    intact = owned.path.read_bytes()

    real_write = os.write
    calls = 0

    def short_write(fd: int, data: Any) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_write(fd, bytes(data)[:7])  # a partial write
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(journal_module.os, "write", short_write)
    with pytest.raises(UsageStoreError, match="No space left"):
        owned.apply([JournalOp(op="create", event=event("ev-2"))], None)
    monkeypatch.setattr(journal_module.os, "write", real_write)
    assert owned.path.read_bytes() == intact

    # The next append lands on a clean line and replays intact.
    owned.apply([JournalOp(op="create", event=event("ev-3"))], None)
    replay = replay_file(owned.path)
    assert (replay.corrupt_records, replay.torn_tail) == (0, False)
    assert set(replay.state) == {"ev-1", "ev-3"}


def test_unreadable_adopted_events_move_to_the_dead_letters(tmp_path: Path) -> None:
    dead = journal(tmp_path)
    broken = event("ev-broken")
    del broken["item"]["usage_policy_id"]
    dead.apply(
        [
            JournalOp(op="create", event=event("ev-good", count=2)),
            JournalOp(op="create", event=broken),
        ],
        None,
    )
    dead.disown()

    client = ScriptedClient([acknowledge])
    adopter = Reporter(client, 60, journal_dir=tmp_path)

    async def exercise() -> int:
        await adopter.start()
        pending = adopter.pending_requests
        await adopter.flush()
        await adopter.aclose()
        return pending

    assert run(exercise()) == 2
    assert [item["idempotency_key"] for item in client.calls[0]] == ["ev-good"]
    (letter,) = inspect_directory(tmp_path).dead_letters
    assert letter["idempotency_key"] == "ev-broken"
    assert "usage_policy_id" in letter["detail"]
    assert letter["event"] == broken


def test_graceful_shutdown_disowns_the_journal_for_instant_adoption(
    tmp_path: Path,
) -> None:
    class FailingClient:
        async def report_usage(self, items: list[dict[str, Any]]) -> dict[str, Any]:
            raise OSError("network down at shutdown")

    first = Reporter(FailingClient(), 60, journal_dir=tmp_path, shutdown_timeout=0.2)
    event_id = run(first.record(API_KEY_ID, 200))
    # aclose cannot deliver, but it hands the journal back without raising:
    # the file is backdated for immediate adoption.
    run(first.aclose())

    second_client = ScriptedClient([acknowledge])
    # The default 120s grace: only the backdating makes this adoptable now.
    second = Reporter(second_client, 60, journal_dir=tmp_path)

    async def adopt_and_deliver() -> None:
        await second.start()
        await second.flush()
        await second.aclose()

    run(adopt_and_deliver())
    assert second_client.calls[0][0]["idempotency_key"] == event_id
    assert wal_files(tmp_path) == []


def test_a_live_owner_keeps_its_journal_from_being_adopted(tmp_path: Path) -> None:
    class Unreachable:
        async def report_usage(self, items: list[dict[str, Any]]) -> dict[str, Any]:
            raise OSError("MicroAuth is unreachable")

    owner = Reporter(Unreachable(), 0.05, journal_dir=tmp_path, shutdown_timeout=0.2)

    async def outage() -> None:
        await owner.start()
        await owner.record(API_KEY_ID, 200)
        (journal_file,) = wal_files(tmp_path)
        # Nothing new to append for ten minutes, as in a long outage.
        stale = time.time() - 600
        os.utime(journal_file, (stale, stale))
        await asyncio.sleep(0.3)
        assert time.time() - journal_file.stat().st_mtime < 5
        assert journal(tmp_path, grace=120).adopt_orphans() == ({}, [])
        assert owner.pending_requests == 1
        await owner.aclose()

    run(outage())


def test_a_restart_after_a_clean_drain_starts_a_fresh_journal(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    client = ScriptedClient([acknowledge, acknowledge])
    reporter = Reporter(client, 60, journal_dir=tmp_path)

    async def serve_twice() -> None:
        for _ in range(2):
            await reporter.start()
            await reporter.record(API_KEY_ID, 200)
            await reporter.flush()
            await reporter.aclose()

    with caplog.at_level(logging.WARNING, logger="microauth"):
        run(serve_twice())
    assert len(client.calls) == 2
    assert "adopted or removed" not in caplog.text
    assert wal_files(tmp_path) == []


def test_compaction_drops_acknowledged_operations(tmp_path: Path) -> None:
    owned = journal(tmp_path, grace=0)
    keep = event("keep-1", count=2)
    owned.apply([JournalOp(op="create", event=keep)], {})
    owned.apply([JournalOp(op="ack", event_ids=["gone-1", "gone-2"])], {"keep-1": keep})
    assert b"gone-1" in owned.path.read_bytes()

    owned.compact({"keep-1": keep})
    records, _, _ = read_records(owned.path)
    assert [record["op"] for record in records] == ["create"]
    assert records[0]["event"]["item"]["idempotency_key"] == "keep-1"
    assert set(owned.replay_own()) == {"keep-1"}
    assert list(tmp_path.glob("*.tmp")) == []


def test_apply_fast_path_defers_live_state_until_actually_needed(
    tmp_path: Path,
) -> None:
    """The group-commit hot path stays O(batch) however large the backlog.

    The journal asks for live state (returns False without writing) only
    when its file was taken away or a compaction is due.
    """

    owned = journal(tmp_path)
    live = event("ev-1", count=2)
    assert owned.apply([JournalOp(op="create", event=live)], None) is True

    # Take the file away: the fast path refuses, writing nothing, so the
    # caller retries with live payloads for the rebuild.
    owned.path.rename(tmp_path / "stolen.wal")
    merge = JournalOp(op="merge", event_id="ev-1")
    assert owned.apply([merge], None) is False
    live["item"]["count"] = 3  # memory is incremented before submission
    assert owned.apply([merge], {"ev-1": live}) is True
    assert owned.replay_own()["ev-1"]["item"]["count"] == 3


def test_size_compaction_uses_garbage_ratio_not_absolute_size(
    tmp_path: Path,
) -> None:
    """A large live backlog must not trigger a full rewrite on every append."""

    owned = journal(tmp_path)
    big_live = event("live-1")
    # About 2MB of live attachments: more than the compaction floor.
    big_live["attachments"] = [{"token": "x" * 100} for _ in range(18_000)]
    owned.apply([JournalOp(op="create", event=big_live)], {"live-1": big_live})
    assert owned.path.stat().st_size > 1 << 20

    for index in range(50):
        op = JournalOp(op="merge", event_id="live-1")
        assert owned.apply([op], None) is True, f"batch {index} left the fast path"


def test_adoption_rename_race_is_won_by_exactly_one_process(tmp_path: Path) -> None:
    dead = journal(tmp_path, grace=0)
    dead.apply([JournalOp(op="create", event=event("orphan-1"))], {})
    dead.disown()

    # A real grace keeps in-flight adoptions (fresh mtime) off limits, so the
    # only claimable file is the disowned one, and its rename is atomic.
    adopter_a = journal(tmp_path)
    adopter_b = journal(tmp_path)
    state_a, claimed_a = adopter_a.adopt_orphans()
    state_b, claimed_b = adopter_b.adopt_orphans()

    assert sorted([len(state_a), len(state_b)]) == [0, 1]
    winner_state = state_a or state_b
    assert winner_state["orphan-1"]["item"]["count"] == 1
    adopter_a.remove_adopted(claimed_a)
    adopter_b.remove_adopted(claimed_b)
    assert wal_files(tmp_path) == []


def test_inspection_counts_each_event_once_and_reads_dead_letters(
    tmp_path: Path,
) -> None:
    first = journal(tmp_path)
    first.apply(
        [
            JournalOp(op="create", event=event("ev-1", count=3, queued_at=1_000.0)),
            JournalOp(op="create", event=event("ev-2", count=2, queued_at=2_000.0)),
        ],
        None,
    )
    # Mid-adoption, an event can sit in two files at once.
    second = journal(tmp_path)
    second.apply(
        [
            JournalOp(op="create", event=event("ev-1", count=3, queued_at=1_000.0)),
            JournalOp(
                op="dead",
                event_id="ev-9",
                event=event("ev-9"),
                detail="customer is not active",
                http_status=402,
                rejected_at=3_000.0,
            ),
        ],
        None,
    )
    dead_letters = tmp_path / f"dead-{second.owner}.jsonl"
    intact = dead_letters.read_bytes()
    dead_letters.write_bytes(b"00000000 {garbage}\n" + intact)

    report = inspect_directory(tmp_path)
    assert report.queued_items == 2
    assert report.queued_requests == 5
    assert report.oldest_queued_at == 1_000.0
    assert sorted(f.items for f in report.files) == [1, 2]
    assert [letter["idempotency_key"] for letter in report.dead_letters] == ["ev-9"]
    assert report.damaged_dead_letters == 1
    assert report.corrupt_copies == []


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_journal_files_are_private_to_the_process_user(tmp_path: Path) -> None:
    owned = journal(tmp_path)
    owned.apply(
        [
            JournalOp(op="create", event=event("ev-1")),
            JournalOp(op="dead", event_id="ev-1", event=event("ev-1"), detail="no"),
        ],
        None,
    )
    for path in (owned.path, tmp_path / f"dead-{owned.owner}.jsonl"):
        assert path.stat().st_mode & 0o777 == 0o600


def test_api_metadata_labels_a_directory_atomically(tmp_path: Path) -> None:
    directory = tmp_path / "scope"
    assert read_api_metadata(directory) == {}
    write_api_metadata(directory, {"tenant_id": "a", "tenant_name": "One"})
    write_api_metadata(directory, {"tenant_id": "a", "tenant_name": "Renamed"})
    assert read_api_metadata(directory) == {"tenant_id": "a", "tenant_name": "Renamed"}
    assert [path.name for path in directory.iterdir()] == ["api.json"]

    (directory / "api.json").write_text("[1, 2]")
    assert read_api_metadata(directory) == {}
