"""Append-only local usage journal: the durability layer without Redis.

Each process owns one journal file and appends one record per operation:
event creation, an O(1) merge increment, delivery acknowledgement, or
dead-lettering. Records are never rewritten in place, so the durable handoff
before each response stays constant-time however many requests merge into
an event.

Every record is one line, ``<crc32> <json>``. The checksum lets replay tell a
torn tail, which a crash during an append leaves behind and which is dropped,
from damage in the middle of the file, which is reported and preserved in a
``corrupt-*`` copy for inspection. Records are fsynced, and so is the
directory whenever a file is created or renamed.

Layout inside the journal directory (one directory per API):

* ``usage-<owner>.wal``: the live journal of one process.
* ``usage-<owner>-adopt<n>.wal``: a dead process's journal being adopted.
* ``dead-<owner>.jsonl``: items MicroAuth refused, written before the
  journal stops tracking them so a crash can't lose the record.
* ``corrupt-<name>-<time>.wal``: a damaged journal kept for inspection.

A crashed process leaves its file behind; once its modification time is
older than the claim grace, any other process adopts it with an atomic
rename (one adopter wins, the loser sees the file vanish). A graceful
shutdown that could not deliver everything backdates its file so the next
process adopts it at once.

All functions here are synchronous. The reporter calls them from a single
detached writer task through a worker thread, which gives group commit: one
append and one fsync cover every request that completed in the batch.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import time
import uuid
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .exceptions import UsageStoreError

logger = logging.getLogger("microauth")

# Compact after this many acknowledged (dead) operations accumulate, or when
# the file grows past this size with mostly-dead content. The size floor is
# deliberately small: fsync latency grows with the append file's size on
# some filesystems (notably APFS), so keeping the journal short keeps the
# group-commit cadence fast; compaction itself only rewrites live state.
_COMPACT_DEAD_OPS = 2_000
_COMPACT_MIN_BYTES = 1 << 20

JOURNAL_VERSION = 2
JOURNAL_PREFIX = "usage-"
DEAD_LETTER_PREFIX = "dead-"
CORRUPT_PREFIX = "corrupt-"
API_METADATA = "api.json"


@dataclass(slots=True)
class JournalOp:
    """One durable journal operation."""

    op: str  # "create" | "merge" | "ack" | "dead"
    event: dict[str, Any] | None = None  # create, dead: full event payload
    event_id: str | None = None  # merge, dead
    attachment: dict[str, Any] | None = None  # merge
    event_ids: list[str] = field(default_factory=list)  # ack
    detail: str | None = None  # dead
    http_status: int | None = None  # dead
    rejected_at: float | None = None  # dead, MicroAuth epoch seconds


@dataclass(slots=True)
class Replay:
    """Live state folded from one journal file."""

    state: dict[str, dict[str, Any]]
    corrupt_records: int = 0
    torn_tail: bool = False


class WalJournal:
    """Single-writer append-only journal with adoption-based recovery."""

    def __init__(self, directory: Path, *, max_items: int, grace_seconds: float) -> None:
        self.owner = uuid.uuid4().hex[:12]
        self._dir = directory
        self._path = directory / f"{JOURNAL_PREFIX}{self.owner}.wal"
        self._dead_path = directory / f"{DEAD_LETTER_PREFIX}{self.owner}.jsonl"
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

    @property
    def directory(self) -> Path:
        return self._dir

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

        self._ensure_directory()
        dead = [op for op in ops if op.op == "dead" and op.event is not None]
        if dead:
            # The dead letter must be durable before the journal stops
            # tracking the event, or a crash in between loses the record.
            self._append_dead_letters(dead)
        records: list[bytes] = []
        resnapshotted = self._file_was_taken()
        if resnapshotted:
            assert pending is not None
            if pending:
                logger.warning(
                    "microauth: another process adopted or removed this worker's usage "
                    "journal while it was running; rewriting %d queued item(s). The "
                    "event loop may have been blocked longer than the claim grace",
                    len(pending),
                )
            # Another process adopted (renamed) our file, or it was deleted.
            # Every already-journaled op left with it; rebuild the journal
            # from live state so our future appends have their base records.
            for payload in pending.values():
                records.append(encode_record({"op": "create", "event": payload}))
        for op in ops:
            if (
                resnapshotted
                and op.op == "merge"
                and pending is not None
                and op.event_id in pending
            ):
                # The snapshot above already contains this increment (memory
                # is bumped before the merge op is submitted); appending it
                # again would double-count on replay.
                continue
            records.append(_encode_op(op))
            if op.op in ("ack", "dead"):
                self._dead_ops += len(op.event_ids) if op.op == "ack" else 1
        data = b"".join(records)
        created = not self._path.exists()
        try:
            self._inode = _append_durably(self._path, data)
        except Exception as exc:
            raise UsageStoreError(f"could not append to the usage journal: {exc}") from exc
        if created:
            _fsync_directory(self._dir)
        if resnapshotted:
            self._approx_size = len(data)
            self._live_baseline = len(data)
        else:
            self._approx_size += len(data)
        if pending is not None and self._compaction_due():
            self.compact(pending)
        return True

    def _ensure_directory(self) -> None:
        try:
            if not self._dir.is_dir():
                self._dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                _fsync_directory(self._dir.parent)
        except OSError as exc:
            raise UsageStoreError(
                f"could not create the usage journal directory {self._dir}: {exc}"
            ) from exc

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

    def _append_dead_letters(self, ops: list[JournalOp]) -> None:
        data = b"".join(
            encode_record(
                {
                    "idempotency_key": op.event_id,
                    "event": op.event,
                    "detail": (op.detail or "")[:2000],
                    "http_status": op.http_status,
                    "rejected_at": _iso(
                        op.rejected_at if op.rejected_at is not None else time.time()
                    ),
                }
            )
            for op in ops
        )
        created = not self._dead_path.exists()
        try:
            _append_durably(self._dead_path, data)
        except Exception as exc:
            raise UsageStoreError(f"could not record a usage dead letter: {exc}") from exc
        if created:
            _fsync_directory(self._dir)

    # ---------------------------------------------------------- compaction

    def compact(self, pending: dict[str, dict[str, Any]]) -> None:
        """Rewrite the journal with only live events, atomically."""

        temporary = self._path.with_suffix(".wal.tmp")
        try:
            written = 0
            with open(temporary, "wb") as handle:
                for payload in pending.values():
                    encoded = encode_record({"op": "create", "event": payload})
                    handle.write(encoded)
                    written += len(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self._path)
            _fsync_directory(self._dir)
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

        state = _replay_and_quarantine(self._path, self.owner)
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
            candidates = sorted(self._dir.glob(f"{JOURNAL_PREFIX}*.wal"))
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
            claimed = self._dir / f"{JOURNAL_PREFIX}{self.owner}-adopt{self._adopt_counter}.wal"
            try:
                os.rename(candidate, claimed)
            except FileNotFoundError:
                continue  # another process won the rename race
            except OSError as exc:
                raise UsageStoreError(f"could not adopt an abandoned usage journal: {exc}") from exc
            _fsync_directory(self._dir)
            try:
                # Rename preserves the stale mtime; refresh it so the claimed
                # file is not itself adoptable until a full grace elapses.
                os.utime(claimed)
            except OSError:
                pass
            claimed_paths.append(claimed)
            for event_id, payload in _replay_and_quarantine(claimed, self.owner).items():
                adopted.setdefault(event_id, payload)
        return adopted, claimed_paths

    def remove_adopted(self, claimed_paths: list[Path]) -> None:
        """Delete claimed files once their events are re-journaled."""

        for path in claimed_paths:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        if claimed_paths:
            _fsync_directory(self._dir)

    def heartbeat(self) -> None:
        """Keep a live owner's journal from looking abandoned.

        Adoption goes by modification time, and an owner with nothing new to
        append (idle, or holding usage through an outage) would otherwise
        age past the grace while it still holds the events.
        """

        if self._inode is None:
            return
        try:
            os.utime(self._path)
        except FileNotFoundError:
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
            return
        self._inode = None
        self._approx_size = 0
        self._live_baseline = 0
        _fsync_directory(self._dir)


# ----------------------------------------------------------------- records


def encode_record(record: dict[str, Any]) -> bytes:
    """One checksummed journal line: ``<crc32 hex> <json>\\n``."""

    try:
        body = json.dumps(
            {"v": JOURNAL_VERSION, **record},
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise UsageStoreError("usage journal record cannot be encoded") from exc
    return b"%08x %s\n" % (zlib.crc32(body), body)


def decode_record(line: bytes) -> dict[str, Any] | None:
    """The record on one line, or None when the line fails its checksum."""

    line = line.rstrip(b"\r\n")
    if len(line) < 10 or line[8:9] != b" ":
        return None
    try:
        expected = int(line[:8], 16)
    except ValueError:
        return None
    body = line[9:]
    if zlib.crc32(body) != expected:
        return None
    try:
        record = json.loads(body)
    except ValueError:
        return None
    if not isinstance(record, dict) or record.get("v") != JOURNAL_VERSION:
        return None
    return record


def read_records(path: Path) -> tuple[list[dict[str, Any]], int, bool]:
    """Every intact record of a file, the damaged count and a torn tail flag.

    Damaged lines that only precede the end of the file are a torn tail: a
    crash interrupted the last append before its fsync returned, so nothing
    in them was ever acknowledged to a caller. Damage followed by intact
    records is real corruption and is counted.
    """

    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return [], 0, False
    except OSError as exc:
        raise UsageStoreError(f"could not read the usage journal {path}: {exc}") from exc
    records: list[dict[str, Any]] = []
    damaged = 0
    pending_damage = 0
    lines = raw.split(b"\n")
    tail = lines.pop()  # bytes after the final newline, normally empty
    for line in lines:
        if not line:
            continue
        record = decode_record(line)
        if record is None:
            pending_damage += 1
            continue
        damaged += pending_damage
        pending_damage = 0
        records.append(record)
    torn = pending_damage > 0 or bool(tail.strip(b"\x00"))
    return records, damaged, torn


def replay_file(path: Path) -> Replay:
    """Fold a journal file's operations into live event payloads.

    Merge operations for unknown events are dropped: their base create was
    adopted by another process along with the rest of the file.
    """

    records, damaged, torn = read_records(path)
    state: dict[str, dict[str, Any]] = {}
    for record in records:
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
    return Replay(state=state, corrupt_records=damaged, torn_tail=torn)


def _replay_and_quarantine(path: Path, owner: str) -> dict[str, dict[str, Any]]:
    replay = replay_file(path)
    if replay.torn_tail:
        logger.warning(
            "microauth: dropped the torn last append of usage journal %s; it "
            "was never confirmed to a caller",
            path.name,
        )
    if replay.corrupt_records:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        copy = path.with_name(f"{CORRUPT_PREFIX}{path.stem}-{owner}-{stamp}.wal")
        try:
            shutil.copy2(path, copy)
            os.chmod(copy, 0o600)
        except OSError:
            copy = path
        logger.error(
            "microauth: usage journal %s has %d damaged record(s) between intact "
            "ones. Recovered %d event(s) from the intact records; a copy of the "
            "file is kept at %s. Usage in the damaged records may be missing "
            "or charged again under a new key",
            path.name,
            replay.corrupt_records,
            len(replay.state),
            copy,
        )
    return replay.state


def _encode_op(op: JournalOp) -> bytes:
    record: dict[str, Any] = {"op": op.op}
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
    return encode_record(record)


# ------------------------------------------------------------- inspection


@dataclass(frozen=True, slots=True)
class JournalFile:
    name: str
    items: int
    requests: int
    oldest_queued_at: float | None
    modified_at: float
    damaged_records: int
    torn_tail: bool


@dataclass(frozen=True, slots=True)
class JournalReport:
    """A read-only view of one API's journal directory."""

    directory: Path
    files: list[JournalFile]
    queued_items: int
    queued_requests: int
    oldest_queued_at: float | None
    dead_letters: list[dict[str, Any]]
    damaged_dead_letters: int
    corrupt_copies: list[str]


def inspect_directory(directory: Path) -> JournalReport:
    """Summarize queued usage and dead letters without changing anything.

    An event can briefly sit in two files while another process adopts a
    journal, so totals count each idempotency key once.
    """

    files: list[JournalFile] = []
    seen: dict[str, dict[str, Any]] = {}
    for path in sorted(directory.glob(f"{JOURNAL_PREFIX}*.wal")):
        try:
            modified = path.stat().st_mtime
        except FileNotFoundError:
            continue
        replay = replay_file(path)
        counts = [_event_count(event) for event in replay.state.values()]
        queued = [_event_queued_at(event) for event in replay.state.values()]
        stamps = [stamp for stamp in queued if stamp is not None]
        files.append(
            JournalFile(
                name=path.name,
                items=len(replay.state),
                requests=sum(counts),
                oldest_queued_at=min(stamps) if stamps else None,
                modified_at=modified,
                damaged_records=replay.corrupt_records,
                torn_tail=replay.torn_tail,
            )
        )
        for event_id, event in replay.state.items():
            seen.setdefault(event_id, event)
    letters: list[dict[str, Any]] = []
    damaged = 0
    for path in sorted(directory.glob(f"{DEAD_LETTER_PREFIX}*.jsonl")):
        records, file_damage, _ = read_records(path)
        letters.extend(records)
        damaged += file_damage
    letters.sort(key=lambda record: str(record.get("rejected_at", "")))
    stamps = [stamp for event in seen.values() if (stamp := _event_queued_at(event)) is not None]
    return JournalReport(
        directory=directory,
        files=files,
        queued_items=len(seen),
        queued_requests=sum(_event_count(event) for event in seen.values()),
        oldest_queued_at=min(stamps) if stamps else None,
        dead_letters=letters,
        damaged_dead_letters=damaged,
        corrupt_copies=sorted(path.name for path in directory.glob(f"{CORRUPT_PREFIX}*")),
    )


def write_api_metadata(directory: Path, metadata: dict[str, Any]) -> None:
    """Label a journal directory with the API it belongs to, atomically."""

    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = directory / API_METADATA
    temporary = directory / f".{API_METADATA}.{uuid.uuid4().hex[:8]}"
    try:
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(metadata, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    _fsync_directory(directory)


def read_api_metadata(directory: Path) -> dict[str, Any]:
    try:
        data = json.loads((directory / API_METADATA).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _event_count(event: dict[str, Any]) -> int:
    item = event.get("item")
    count = item.get("count") if isinstance(item, dict) else None
    return count if isinstance(count, int) and not isinstance(count, bool) else 0


def _event_queued_at(event: dict[str, Any]) -> float | None:
    item = event.get("item")
    stamp = item.get("queued_at") if isinstance(item, dict) else None
    if isinstance(stamp, (int, float)) and not isinstance(stamp, bool) and stamp > 0:
        return float(stamp)
    return None


def _append_durably(path: Path, data: bytes) -> int:
    """Append ``data`` and fsync it, or leave the file exactly as it was.

    A failed write or fsync truncates back to the old end. Otherwise a
    partial record would stay in the file and the next append would land on
    the same line, so a record confirmed later would fail its checksum on
    replay. Returns the file's inode.
    """

    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    try:
        start = os.lseek(fd, 0, os.SEEK_END)
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
            os.fsync(fd)
        except BaseException:
            try:
                os.ftruncate(fd, start)
                os.fsync(fd)
            except OSError:
                pass
            raise
        return os.fstat(fd).st_ino
    finally:
        os.close(fd)


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")


def _fsync_directory(directory: Path) -> None:
    """Make a create, rename or unlink in ``directory`` survive power loss."""

    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return  # Windows and some network filesystems can't open directories
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)
