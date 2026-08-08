"""Append-only local usage journal (WAL) - the no-Redis durability fallback.

Each process owns one journal file and appends one compact JSON line per
operation: event creation, an O(1) merge increment, delivery acknowledgement,
or dead-lettering. Appends never rewrite existing state, so the pre-response
durable handoff stays constant-time no matter how many requests merge into an
event (the SQLite journal it replaces rewrote the full merged row - including
its growing attachments array - on every request).

Ownership and recovery mirror the Redis queue's lease semantics with files:

* One file per reporter instance (``<stem>-<owner>.wal``); a single writer
  per file means no cross-process locking at all.
* A crashed process leaves its file behind; once its modification time is
  older than the claim grace, any other process adopts it with an atomic
  rename (rename races resolve themselves: one adopter wins, the loser sees
  the file vanish) and absorbs its pending events.
* A graceful shutdown that could not deliver everything backdates its file's
  modification time so the next process adopts it immediately.
* Compaction rewrites only live state into a temporary file and atomically
  renames it into place once enough acknowledged bytes accumulate.

All functions here are synchronous and are called from the reporter's single
detached writer task (via a worker thread), which provides group commit: one
append plus one fsync covers every request that completed in the batch.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .exceptions import UsageQueueFull, UsageStoreError

# Compact after this many acknowledged (dead) operations accumulate, or when
# the file grows past this size with mostly-dead content. The size floor is
# deliberately small: fsync latency grows with the append file's size on
# some filesystems (notably APFS), so keeping the journal short keeps the
# group-commit cadence fast; compaction itself only rewrites live state.
_COMPACT_DEAD_OPS = 2_000
_COMPACT_MIN_BYTES = 1 << 20

_WAL_VERSION = 1


@dataclass(slots=True)
class JournalOp:
    """One durable journal operation."""

    op: str  # "create" | "merge" | "ack" | "dead"
    event: dict[str, Any] | None = None  # create: full event payload
    event_id: str | None = None  # merge/dead
    attachment: dict[str, Any] | None = None  # merge
    event_ids: list[str] = field(default_factory=list)  # ack
    detail: str | None = None  # dead


class WalJournal:
    """Single-writer append-only journal with adoption-based recovery."""

    def __init__(self, base_path: Path, *, max_items: int, grace_seconds: float) -> None:
        self.owner = uuid.uuid4().hex[:12]
        self._base = base_path
        stem = base_path.name
        for suffix in (".sqlite3", ".wal", ".jsonl"):
            stem = stem.removesuffix(suffix)
        self._stem = stem
        self._dir = base_path.parent
        self._path = self._dir / f"{stem}-{self.owner}.wal"
        self._dead_path = self._dir / f"{stem}-{self.owner}.dead.jsonl"
        self._max_items = max_items
        self._grace = grace_seconds
        self._inode: int | None = None
        self._dead_ops = 0
        self._adopt_counter = 0
        # Tracked instead of stat()ing: appended bytes since open/compact.
        self._approx_size = 0
        # Bytes the last compaction wrote, i.e. the size of pure live state.
        # Compaction triggers on the garbage RATIO (file at least twice the
        # live baseline), never on absolute size alone: a large live backlog
        # must not cause a full rewrite on every append batch.
        self._live_baseline = 0

    @property
    def path(self) -> Path:
        return self._path

    def legacy_sqlite_path(self) -> Path:
        """The pre-WAL shared SQLite file this journal supersedes."""

        if self._base.suffix == ".sqlite3":
            return self._base
        return self._dir / f"{self._stem}.sqlite3"

    # ------------------------------------------------------------- appends

    def apply(
        self,
        ops: list[JournalOp],
        pending: dict[str, dict[str, Any]] | None,
    ) -> bool:
        """Append a batch of operations with one write and one fsync.

        ``pending`` is the reporter's current in-memory event state (payload
        per event id). It is only needed in two rare situations: the file was
        adopted or removed out from under us (re-snapshot), or enough dead
        operations accumulated for a compaction. Building those payloads
        costs O(backlog), so the writer calls with ``pending=None`` first;
        when live state is actually required this method writes nothing and
        returns False, and the caller retries with the payloads. The common
        case therefore stays O(batch) no matter how large the backlog is.
        """

        needs_live_state = self._file_was_taken() or self._compaction_due()
        if pending is None and needs_live_state:
            return False

        self._dir.mkdir(parents=True, exist_ok=True)
        lines: list[str] = []
        resnapshotted = self._file_was_taken()
        if resnapshotted:
            assert pending is not None
            # Another process adopted (renamed) our file, or it was deleted.
            # Every already-journaled op left with it; rebuild the journal
            # from live state so our future appends have their base records.
            for payload in pending.values():
                lines.append(_encode_line({"v": _WAL_VERSION, "op": "create", "event": payload}))
        for op in ops:
            if resnapshotted and op.op == "merge" and pending is not None and op.event_id in pending:
                # The snapshot above already contains this increment (memory
                # is bumped before the merge op is submitted); appending it
                # again would double-count on replay.
                continue
            lines.append(_encode_op(op))
            if op.op in ("ack", "dead"):
                self._dead_ops += len(op.event_ids) if op.op == "ack" else 1
        data = "".join(lines).encode("utf-8")
        try:
            with open(self._path, "ab") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(self._path, 0o600)
            self._inode = os.stat(self._path).st_ino
        except UsageStoreError:
            raise
        except Exception as exc:
            raise UsageStoreError(f"could not append to the usage journal: {exc}") from exc
        if resnapshotted:
            self._approx_size = len(data)
            self._live_baseline = len(data)
        else:
            self._approx_size += len(data)
        for op in ops:
            if op.op == "dead" and op.event is not None:
                self._append_dead_letter(op)
        if pending is not None and self._compaction_due():
            self.compact(pending)
        return True

    def _file_was_taken(self) -> bool:
        try:
            return os.stat(self._path).st_ino != self._inode
        except FileNotFoundError:
            return self._inode is not None

    def _compaction_due(self) -> bool:
        if self._dead_ops >= _COMPACT_DEAD_OPS:
            return True
        # Ratio rule: rewrite only when appended garbage at least matches
        # the live state, keeping compaction cost amortized O(1) per byte.
        return self._approx_size >= _COMPACT_MIN_BYTES and self._approx_size >= 2 * max(
            self._live_baseline, _COMPACT_MIN_BYTES // 2
        )

    def _append_dead_letter(self, op: JournalOp) -> None:
        record = {
            "idempotency_key": op.event_id,
            "event": op.event,
            "detail": (op.detail or "")[:2000],
            "rejected_at": time.time(),
        }
        try:
            with open(self._dead_path, "a", encoding="utf-8") as handle:
                handle.write(_encode_line(record))
            os.chmod(self._dead_path, 0o600)
        except Exception as exc:
            raise UsageStoreError(
                f"could not record a usage dead letter: {exc}"
            ) from exc

    # ---------------------------------------------------------- compaction

    def compact(self, pending: dict[str, dict[str, Any]]) -> None:
        """Rewrite the journal with only live events, atomically."""

        temporary = self._path.with_suffix(".wal.tmp")
        try:
            written = 0
            with open(temporary, "wb") as handle:
                for payload in pending.values():
                    encoded = _encode_line(
                        {"v": _WAL_VERSION, "op": "create", "event": payload}
                    ).encode("utf-8")
                    handle.write(encoded)
                    written += len(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self._path)
            self._inode = os.stat(self._path).st_ino
            self._dead_ops = 0
            self._approx_size = written
            self._live_baseline = written
        except Exception as exc:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            raise UsageStoreError(f"could not compact the usage journal: {exc}") from exc

    # ------------------------------------------------------------- replay

    def replay_own(self) -> dict[str, dict[str, Any]]:
        """Fold this process's own journal into pending event payloads."""

        state = _replay_file(self._path)
        try:
            stat = os.stat(self._path)
            self._inode = stat.st_ino
            self._approx_size = stat.st_size
            self._live_baseline = stat.st_size
        except FileNotFoundError:
            self._inode = None
            self._approx_size = 0
            self._live_baseline = 0
        return state

    def adopt_orphans(self) -> tuple[dict[str, dict[str, Any]], list[Path]]:
        """Claim journal files whose owners stopped writing for the grace.

        Claiming is an atomic rename, so two sweeping processes can never
        absorb the same file: exactly one rename succeeds. The claimed files
        are returned and must be removed with :meth:`remove_adopted` only
        after their events are durably re-journaled by the adopter; until
        then they keep a regular ``.wal`` name and stay adoptable themselves,
        so an adopter crash cannot lose them.
        """

        adopted: dict[str, dict[str, Any]] = {}
        claimed_paths: list[Path] = []
        cutoff = time.time() - self._grace
        try:
            candidates = sorted(self._dir.glob(f"{self._stem}-*.wal"))
        except OSError:
            return adopted, claimed_paths
        for candidate in candidates:
            if self.owner in candidate.name:
                continue  # our own journal or our own in-flight adoption
            try:
                if os.stat(candidate).st_mtime > cutoff:
                    continue
            except FileNotFoundError:
                continue
            self._adopt_counter += 1
            claimed = (
                self._dir
                / f"{self._stem}-{self.owner}-adopt{self._adopt_counter}.wal"
            )
            try:
                os.rename(candidate, claimed)
            except FileNotFoundError:
                continue  # another process won the rename race
            except OSError as exc:
                raise UsageStoreError(
                    f"could not adopt an abandoned usage journal: {exc}"
                ) from exc
            try:
                # Rename preserves the stale mtime; refresh it so the claimed
                # file is not itself adoptable until a full grace elapses.
                os.utime(claimed)
            except OSError:
                pass
            claimed_paths.append(claimed)
            for event_id, payload in _replay_file(claimed).items():
                adopted.setdefault(event_id, payload)
        return adopted, claimed_paths

    def remove_adopted(self, claimed_paths: list[Path]) -> None:
        """Delete claimed files once their events are re-journaled."""

        for path in claimed_paths:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass

    # ------------------------------------------------------------ shutdown

    def disown(self) -> None:
        """Make this journal immediately adoptable by the next process."""

        try:
            if not self._path.exists():
                return
            # Backdate the modification time to the epoch so the file is
            # claimable under any adopter's grace, including one longer than
            # ours (grace settings can differ across a rolling deploy).
            os.utime(self._path, (1.0, 1.0))
        except OSError as exc:
            raise UsageStoreError(
                f"could not release the usage journal at shutdown: {exc}"
            ) from exc

    def remove_if_empty(self, pending: dict[str, dict[str, Any]]) -> None:
        """Delete the journal after a fully clean drain."""

        if pending:
            return
        try:
            self._path.unlink(missing_ok=True)
        except OSError:
            pass


def _encode_op(op: JournalOp) -> str:
    record: dict[str, Any] = {"v": _WAL_VERSION, "op": op.op}
    if op.op == "create":
        record["event"] = op.event
    elif op.op == "merge":
        record["id"] = op.event_id
        if op.attachment:
            record["attachment"] = op.attachment
    elif op.op == "ack":
        record["ids"] = op.event_ids
    elif op.op == "dead":
        record["id"] = op.event_id
    else:  # pragma: no cover - internal misuse
        raise UsageStoreError(f"unknown journal operation {op.op!r}")
    return _encode_line(record)


def _encode_line(record: dict[str, Any]) -> str:
    try:
        return (
            json.dumps(record, allow_nan=False, separators=(",", ":"), sort_keys=True)
            + "\n"
        )
    except (TypeError, ValueError) as exc:
        raise UsageStoreError("usage journal record cannot be encoded") from exc


def _replay_file(path: Path) -> dict[str, dict[str, Any]]:
    """Fold a journal file's operations into live event payloads.

    A torn final line (crash mid-append) is tolerated and dropped; every
    complete line before it is intact because appends are fsynced in order.
    Merge operations for unknown events are dropped: their base create was
    adopted by another process along with the rest of the file.
    """

    state: dict[str, dict[str, Any]] = {}
    try:
        with open(path, encoding="utf-8") as handle:
            raw = handle.read()
    except FileNotFoundError:
        return state
    except OSError as exc:
        raise UsageStoreError(f"could not read the usage journal: {exc}") from exc
    for line in raw.split("\n"):
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue  # torn tail line from a crash mid-append
        if not isinstance(record, dict):
            continue
        op = record.get("op")
        if op == "create":
            event = record.get("event")
            if not isinstance(event, dict):
                continue
            item = event.get("item")
            if not isinstance(item, dict):
                continue
            event_id = item.get("idempotency_key")
            if isinstance(event_id, str) and event_id:
                state[event_id] = event
        elif op == "merge":
            event_id = record.get("id")
            if not isinstance(event_id, str):
                continue
            event = state.get(event_id)
            if event is None:
                continue
            item = event.get("item")
            if not isinstance(item, dict):
                continue
            count = item.get("count")
            if isinstance(count, bool) or not isinstance(count, int):
                continue
            item["count"] = count + 1
            attachment = record.get("attachment")
            if isinstance(attachment, dict) and attachment:
                attachments = event.get("attachments")
                if isinstance(attachments, list):
                    attachments.append(attachment)
        elif op == "ack":
            ids = record.get("ids")
            if isinstance(ids, list):
                for event_id in ids:
                    if isinstance(event_id, str):
                        state.pop(event_id, None)
        elif op == "dead":
            event_id = record.get("id")
            if isinstance(event_id, str):
                state.pop(event_id, None)
    return state


def enforce_capacity(
    state: dict[str, dict[str, Any]],
    max_items: int,
) -> dict[str, dict[str, Any]]:
    if len(state) > max_items:
        raise UsageQueueFull(max_items)
    return state
