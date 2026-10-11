"""Durable, bounded, idempotent usage reporting with per-item receipts.

Every completed authenticated request is counted into a usage event, and the
event is made durable (in Redis or the local journal) before the response's
final frame goes out. Requests that share an API key, usage policy, status
code and UTC hour merge into one event, so a long outage queues counts
rather than rows.

Events are delivered in batches of up to 500 items. MicroAuth answers every
item: ``accepted`` or ``duplicate`` with a receipt saying what it charged and
when it recorded the item, or ``rejected`` with the reason. The reporter
checks each receipt against the charge it expected from the price the
requests were admitted at, hands receipts to ``on_receipts`` and refusals to
``on_rejections``, and only then removes the items from the queue. A crash in
between replays the batch, and MicroAuth answers the replay as duplicates
that carry the original receipts.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import math
import os
import sys
import time
import uuid
from collections import deque
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ._clock import ServerClock
from ._time import parse_iso8601
from .client import APIClient
from .exceptions import (
    MicroAuthAPIError,
    MicroAuthAuthorizationError,
    MicroAuthError,
    UsageAcknowledgementError,
    UsageDrainError,
    UsageQueueFull,
    UsageStoreError,
)
from .journal import JournalOp, WalJournal
from .models import (
    MAX_SAFE_INTEGER,
    MAX_USAGE_COUNT,
    CustomerBalance,
    UsageReceipt,
    UsageRejection,
    UsageStats,
)
from .usage_store import UPSERT_MERGED, RedisUsageStore

logger = logging.getLogger("microauth")

_DEFAULT_MAX_ITEMS = 10_000
# Deliveries batch up to this many events; reaching it triggers an immediate
# flush instead of waiting for the interval deadline.
_DEFAULT_BATCH_SIZE = 500
_RESPONSE_BATCH_WINDOW = 0.01
_SUCCESS_STATUSES = frozenset({"accepted", "duplicate"})
_TERMINAL_ITEM_HTTP_STATUSES = frozenset({400, 402, 409, 422})
_UNIQUE_ATTACHMENT_FIELDS = frozenset({"token"})

# The API terminally rejects usage older than 45 days; retrying past that only
# converts a delayed delivery into a guaranteed rejection.
_MAX_EVENT_AGE_SECONDS = 45 * 86_400

# After a journal failure the reporter fails fast for this long, then probes
# the journal again. A transient disk blip must not poison the process into
# permanent 503s.
_STORE_ERROR_COOLDOWN_SECONDS = 5.0

# Requests sharing one identity merge into a single counted event up to this
# many requests. The cap is deliberately much larger than the delivery batch
# size: while the control plane is unreachable, open events keep absorbing
# traffic instead of fragmenting, so the bounded queue holds hours of an
# outage (max_items x merge cap requests) rather than minutes. The API
# accepts counts up to MAX_USAGE_COUNT (10M) per item.
_MERGE_CAP = 10_000

# Hooks run before the queue forgets a batch, so they see every receipt at
# least once. The time box keeps a slow hook from stalling delivery.
_HOOK_TIMEOUT_SECONDS = 5.0

# Failed deliveries are warnings until this many happen in a row.
_FAILURES_BEFORE_ERROR = 5

BACKEND_REDIS = "redis"
BACKEND_JOURNAL = "journal"
BACKEND_MEMORY = "memory"


UsageCallback = Callable[[list[dict[str, Any]]], Awaitable[None] | None]
AcknowledgementCallback = Callable[
    [list[dict[str, Any]], list[CustomerBalance]],
    Awaitable[None] | None,
]
AuthorizationCallback = Callable[
    [MicroAuthAuthorizationError],
    Awaitable[None] | None,
]
ReceiptCallback = Callable[[list[UsageReceipt]], Awaitable[None] | None]
RejectionCallback = Callable[[list[UsageRejection]], Awaitable[None] | None]

_MergeKey = tuple[str, str, int, str, int | None]


@dataclass(slots=True)
class _UsageEvent:
    idempotency_key: str
    api_key_id: str
    usage_policy_id: str
    status_code: int
    count: int
    period_start: str
    # MicroAuth's charge per request for this status under the event's usage
    # policy, as the SDK computed it when admitting the requests.
    unit_charge_micro: int | None = None
    # MicroAuth-aligned epoch seconds when the first request was queued.
    queued_at: float = 0.0
    attachments: list[dict[str, Any]] = field(default_factory=list)
    # Where the event is durable: Redis, the local journal, or nowhere.
    backend: str = BACKEND_MEMORY
    # Once an event has been selected for delivery (or recovered, where a
    # previous attempt may have happened), its payload is immutable: the
    # server's receipt is keyed by idempotency_key and a retry with a
    # different count would be a 409 conflict.
    frozen: bool = False
    # Number of merges currently persisting into this event. Flush selection
    # waits for them so a delivery can never freeze a payload halfway
    # through a durable count increment.
    merging: int = 0
    # Cached epoch seconds of period_start (filled lazily).
    period_ts: float = 0.0

    def as_payload(self) -> dict[str, Any]:
        """The item exactly as ``POST /sdk/v1/usage`` accepts it."""

        return {
            "idempotency_key": self.idempotency_key,
            "api_key_id": self.api_key_id,
            "usage_policy_id": self.usage_policy_id,
            "status_code": self.status_code,
            "count": self.count,
            "period_start": self.period_start,
        }

    def durable_item(self) -> dict[str, Any]:
        """The wire item plus the bookkeeping that must survive a restart."""

        item = self.as_payload()
        if self.unit_charge_micro is not None:
            item["unit_charge_micro"] = self.unit_charge_micro
        if self.queued_at:
            item["queued_at"] = self.queued_at
        return item

    def as_static_payload(self) -> dict[str, Any]:
        item = self.durable_item()
        del item["count"]
        return item

    def merge_key(self) -> _MergeKey:
        return (
            self.api_key_id,
            self.usage_policy_id,
            self.status_code,
            self.period_start,
            self.unit_charge_micro,
        )

    def expected_charge(self) -> int | None:
        if self.unit_charge_micro is None:
            return None
        return self.unit_charge_micro * self.count

    def period_epoch(self) -> float:
        if self.period_ts == 0.0:
            # Parsed once per event lifetime, not once per flush.
            self.period_ts = parse_iso8601(self.period_start).timestamp()
        return self.period_ts


@dataclass(frozen=True, slots=True)
class UsageReservation:
    token: str


@dataclass(frozen=True, slots=True)
class _ItemReceipt:
    outcome: str
    customer_id: str | None
    charged_micro: int | None
    recorded_at: datetime | None


@dataclass(frozen=True, slots=True)
class _ItemRejection:
    http_status: int | None
    detail: str


@dataclass(frozen=True, slots=True)
class _Acknowledgements:
    accepted: list[str]
    rejected: dict[str, _ItemRejection]
    retry: list[str]
    error: UsageAcknowledgementError | None
    receipts: dict[str, _ItemReceipt] = field(default_factory=dict)
    balances: list[CustomerBalance] = field(default_factory=list)


@dataclass(slots=True)
class _Counters:
    delivered_items: int = 0
    delivered_requests: int = 0
    duplicate_items: int = 0
    rejected_items: int = 0
    rejected_requests: int = 0
    charged_micro: int = 0
    charge_mismatches: int = 0
    last_delivery_at: float | None = None
    consecutive_failures: int = 0
    last_error: str | None = None
    last_error_at: float | None = None
    hook_failures: int = 0


def _hour_bucket(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("usage period timestamp must include a UTC offset")
    value = value.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
    return value.isoformat().replace("+00:00", "Z")


class UsageReporter:
    """Journal request outcomes and deliver stable, acknowledged batches."""

    def __init__(
        self,
        client: APIClient,
        interval: float,
        *,
        clock: ServerClock | None = None,
        max_items: int = _DEFAULT_MAX_ITEMS,
        batch_size: int = _DEFAULT_BATCH_SIZE,
        shutdown_timeout: float = 10.0,
        journal_dir: str | os.PathLike[str] | None = None,
        journal_claim_grace: float = 120.0,
        store: RedisUsageStore | None = None,
        on_acknowledged: AcknowledgementCallback | None = None,
        on_rejected: UsageCallback | None = None,
        on_restored: UsageCallback | None = None,
        on_authorization_failure: AuthorizationCallback | None = None,
        on_receipts: ReceiptCallback | None = None,
        on_rejections: RejectionCallback | None = None,
        hook_timeout: float = _HOOK_TIMEOUT_SECONDS,
    ) -> None:
        if interval <= 0:
            raise ValueError("interval must be positive")
        if max_items <= 0:
            raise ValueError("max_items must be positive")
        if batch_size <= 0 or batch_size > 1000:
            raise ValueError("batch_size must be between 1 and 1000")
        if shutdown_timeout <= 0:
            raise ValueError("shutdown_timeout must be positive")
        if journal_claim_grace < 0:
            raise ValueError("journal_claim_grace must not be negative")
        if hook_timeout <= 0:
            raise ValueError("hook_timeout must be positive")
        self._client = client
        self._clock = clock or ServerClock()
        self._interval = interval
        self._max_items = max_items
        self._batch_size = batch_size
        self._shutdown_timeout = shutdown_timeout
        self._journal_dir = Path(journal_dir).expanduser() if journal_dir is not None else None
        self._journal_grace = journal_claim_grace
        self._on_acknowledged = on_acknowledged
        self._on_rejected = on_rejected
        self._on_restored = on_restored
        self._on_authorization_failure = on_authorization_failure
        self._on_receipts = on_receipts
        self._on_rejections = on_rejections
        self._hook_timeout = hook_timeout

        self._store = store
        self._events: dict[str, _UsageEvent] = {}
        # Open (unfrozen, pending) events by identity, so requests sharing an
        # API key, policy, status and hour merge into one counted event
        # instead of one row per request.
        self._open_events: dict[_MergeKey, str] = {}
        # In-flight event creations by identity: followers in a cold burst
        # wait for the first creation instead of opening one event each.
        self._creating: dict[_MergeKey, asyncio.Future[None]] = {}
        self._merge_limit = min(_MERGE_CAP, MAX_USAGE_COUNT)
        self._pending: deque[str] = deque()
        self._reservations: set[str] = set()
        self._task: asyncio.Task[None] | None = None
        self._restore_task: asyncio.Task[None] | None = None
        self._response_flush_task: asyncio.Task[None] | None = None
        self._trailing_flush_task: asyncio.Task[None] | None = None
        self._flush_lock = asyncio.Lock()
        self._start_lock = asyncio.Lock()
        self._wake = asyncio.Event()
        self._flush_deadline: float | None = None
        self._restored = False
        self._store_error: UsageStoreError | None = None
        self._store_error_until = 0.0
        self._last_sweep = 0.0
        # Anchor the "seconds since the last flush" batching rule so the
        # first request batches instead of flushing instantly.
        self._last_flush = time.monotonic()
        # After a failed delivery, no flush may start before this time. This
        # must hold against every trigger (background deadline, full-batch
        # fast path, response-bound flushes): without it, a full backlog
        # forces an immediate retry on every new request, and each rapid
        # failed flush freezes the open event at a tiny count, fragmenting
        # the queue to its item bound in minutes during an outage.
        self._backoff_until = 0.0
        self._journal_writes: list[tuple[list[JournalOp], asyncio.Future[None]]] = []
        self._journal_writer_task: asyncio.Task[None] | None = None
        # Each process appends to its own WAL file (single writer, O(1)
        # appends). Files whose owner stopped writing for the claim grace
        # are adopted by any other process via an atomic rename.
        self._journal: WalJournal | None = None
        # Requests awaiting delivery (an O(1) counter for the batch trigger);
        # merged events contribute their full counts.
        self._pending_requests = 0
        self._counters = _Counters()
        self._warned_missing_receipt = False

    # ------------------------------------------------------------ properties

    @property
    def pending_items(self) -> int:
        return len(self._events)

    @property
    def pending_requests(self) -> int:
        return sum(event.count for event in self._events.values())

    @property
    def journal_dir(self) -> Path | None:
        return self._journal_dir

    @property
    def durability(self) -> str:
        if self._store is not None:
            return BACKEND_REDIS
        if self._journal_dir is not None:
            return BACKEND_JOURNAL
        return BACKEND_MEMORY

    def bind(
        self,
        *,
        journal_dir: str | os.PathLike[str] | None,
        store: RedisUsageStore | None,
    ) -> None:
        """Attach the durable backends of one API before the first restore.

        The SDK learns which API its secret belongs to from the first
        snapshot, and only then knows where that API's queued usage lives.
        """

        if self._restored or self._events or self._restore_task is not None:
            raise RuntimeError("the usage reporter is already running and cannot be rebound")
        self._journal_dir = Path(journal_dir).expanduser() if journal_dir is not None else None
        self._journal = None
        self._store = store

    def stats(self) -> UsageStats:
        """A point-in-time view of this process's usage delivery."""

        counters = self._counters
        events = list(self._events.values())
        oldest = min((event.queued_at for event in events if event.queued_at), default=None)
        return UsageStats(
            durability=self.durability,
            journal_dir=str(self._journal_dir) if self._journal_dir is not None else None,
            queued_items=len(events),
            queued_requests=sum(event.count for event in events),
            oldest_queued_at=_datetime(oldest),
            delivered_items=counters.delivered_items,
            delivered_requests=counters.delivered_requests,
            duplicate_items=counters.duplicate_items,
            rejected_items=counters.rejected_items,
            rejected_requests=counters.rejected_requests,
            charged_micro=counters.charged_micro,
            charge_mismatches=counters.charge_mismatches,
            last_delivery_at=_datetime(counters.last_delivery_at),
            consecutive_failures=counters.consecutive_failures,
            last_error=counters.last_error,
            last_error_at=_datetime(counters.last_error_at),
            clock_offset_seconds=self._clock.offset,
            hook_failures=counters.hook_failures,
        )

    # ------------------------------------------------------------ admission

    def reserve(self) -> UsageReservation:
        """Reserve bounded queue capacity before the endpoint starts."""

        if self._store_error is not None and time.monotonic() < self._store_error_until:
            raise self._store_error
        if len(self._events) + len(self._reservations) >= self._max_items:
            raise UsageQueueFull(self._max_items)
        token = str(uuid.uuid4())
        self._reservations.add(token)
        return UsageReservation(token)

    def release(self, reservation: UsageReservation) -> None:
        self._reservations.discard(reservation.token)

    async def record(
        self,
        api_key_id: str,
        status_code: int,
        *,
        usage_policy_id: str,
        reservation: UsageReservation | None = None,
        occurred_at: datetime | None = None,
        attachment: dict[str, Any] | None = None,
        unit_charge_micro: int | None = None,
    ) -> str:
        """Durably count one completed authenticated request."""

        api_key_id = _canonical_uuid(api_key_id, "api_key_id")
        usage_policy_id = _canonical_uuid(usage_policy_id, "usage_policy_id")
        if isinstance(status_code, bool) or not isinstance(status_code, int):
            raise TypeError("status_code must be an integer")
        if status_code < 100 or status_code > 599:
            raise ValueError("status_code must be between 100 and 599")
        if unit_charge_micro is not None and (
            isinstance(unit_charge_micro, bool)
            or not isinstance(unit_charge_micro, int)
            or unit_charge_micro < 0
            or unit_charge_micro > MAX_SAFE_INTEGER
        ):
            raise ValueError("unit_charge_micro must be a non-negative safe integer")
        normalized_attachment = _normalize_attachment(attachment)
        if reservation is not None and reservation.token not in self._reservations:
            raise ValueError("usage queue reservation is invalid or already consumed")
        period_start = _hour_bucket(occurred_at or self._clock.now())

        if reservation is None and (len(self._events) + len(self._reservations) >= self._max_items):
            raise UsageQueueFull(self._max_items)

        merge_key: _MergeKey = (
            api_key_id,
            usage_policy_id,
            status_code,
            period_start,
            unit_charge_micro,
        )
        for _ in range(2):
            merged_id = await self._try_merge(merge_key, normalized_attachment)
            if merged_id is not None:
                if reservation is not None:
                    self._consume_reservation(reservation)
                self._pending_requests += 1
                self._schedule_flush()
                return merged_id
            # A cold concurrent burst would otherwise open one event per
            # in-flight request: the first request registers the open event
            # only after its durable write completes. Followers wait for the
            # in-flight creation and merge into it instead.
            creating = self._creating.get(merge_key)
            if creating is None:
                break
            try:
                await asyncio.shield(creating)
            except Exception:  # noqa: BLE001, S110 - creator failures are
                # handled by each follower independently: the retry loop
                # makes one of them the next creator, which surfaces the
                # underlying persistence error through its own attempt.
                pass
            continue

        event = _UsageEvent(
            idempotency_key=str(uuid.uuid4()),
            api_key_id=api_key_id,
            usage_policy_id=usage_policy_id,
            status_code=status_code,
            count=1,
            period_start=period_start,
            unit_charge_micro=unit_charge_micro,
            queued_at=round(self._clock.time(), 3),
            attachments=[normalized_attachment],
        )
        creation: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        if merge_key not in self._creating:
            self._creating[merge_key] = creation
        try:
            await self._persist_event(event)
        except BaseException as exc:
            if not creation.done():
                creation.set_exception(exc)
                # Consume the exception if no follower awaited this future.
                creation.exception()
            raise
        finally:
            if self._creating.get(merge_key) is creation:
                del self._creating[merge_key]
        if reservation is not None and reservation.token not in self._reservations:
            # Validated before the durable write; a concurrent consumer while
            # awaiting persistence indicates a caller bug.
            raise ValueError("usage queue reservation is invalid or already consumed")
        if reservation is not None:
            self._consume_reservation(reservation)
        self._events[event.idempotency_key] = event
        self._open_events[merge_key] = event.idempotency_key
        self._pending.append(event.idempotency_key)
        self._pending_requests += 1
        self._schedule_flush()
        if not creation.done():
            creation.set_result(None)
        return event.idempotency_key

    async def _try_merge(
        self,
        merge_key: _MergeKey,
        attachment: dict[str, Any],
    ) -> str | None:
        """Aggregate this request into an open event with the same identity.

        Merging keeps one counted event (and later one receipt and one API
        item) per key, policy, status and hour per flush window, instead of
        one row per request. Only never-delivered events are merged: once a
        payload has been attempted, its idempotency key pins its exact count.
        """

        event_id = self._open_events.get(merge_key)
        if event_id is None:
            return None
        event = self._events.get(event_id)
        if event is None or event.frozen or event.count >= self._merge_limit:
            self._open_events.pop(merge_key, None)
            return None
        event.merging += 1
        try:
            if event.backend == BACKEND_REDIS:
                store = self._store
                if store is None:
                    self._open_events.pop(merge_key, None)
                    return None
                try:
                    result = await store.merge_claimed(
                        event_id,
                        attachment or None,
                        max_count=self._merge_limit,
                    )
                except (UsageQueueFull, UsageStoreError):
                    # Fall back to an independent event; its own persistence
                    # path handles a struggling store.
                    return None
                if result != UPSERT_MERGED:
                    # Fenced (another worker recovered the event) or capped;
                    # this open event can no longer accept requests.
                    self._open_events.pop(merge_key, None)
                    return None
            elif event.backend == BACKEND_JOURNAL:
                # Commit in memory first, then journal a constant-size merge
                # record: one appended line per request, never a rewrite of
                # the whole (growing) merged event.
                event.count += 1
                if attachment:
                    event.attachments.append(attachment)
                try:
                    future = self._submit_journal_ops(
                        [
                            JournalOp(
                                op="merge",
                                event_id=event_id,
                                attachment=attachment or None,
                            )
                        ]
                    )
                except BaseException:
                    _undo_merge(event, attachment)
                    raise
                if future is None:  # pragma: no cover - a journaled event implies a journal
                    return event_id
                try:
                    await asyncio.shield(future)
                except asyncio.CancelledError:
                    # The detached writer will still resolve the write. Keep
                    # the merge latch held and reconcile the in-memory count
                    # with the journal's actual outcome, so a crash can never
                    # find the two disagreeing about this increment.
                    event.merging += 1
                    future.add_done_callback(self._merge_reconciler(event, attachment))
                    raise
                except BaseException:
                    _undo_merge(event, attachment)
                    raise
                return event_id
            # Redis took the increment, or the event lives in memory only.
            event.count += 1
            if attachment:
                event.attachments.append(attachment)
            return event_id
        finally:
            event.merging -= 1

    def _merge_reconciler(
        self,
        event: _UsageEvent,
        attachment: dict[str, Any],
    ) -> Callable[[asyncio.Future[None]], None]:
        def reconcile(future: asyncio.Future[None]) -> None:
            try:
                failed = future.cancelled() or future.exception() is not None
                if failed:
                    # The journal never took the increment; undo it so the
                    # delivered count matches the durable copy.
                    _undo_merge(event, attachment)
            finally:
                event.merging -= 1

        return reconcile

    async def _persist_event(self, event: _UsageEvent) -> None:
        """Complete the durable handoff before the caller's response is final."""

        if self._store is not None:
            try:
                await self._store.enqueue_claimed(
                    event.idempotency_key,
                    event.as_static_payload(),
                    event.attachments[0] if event.attachments[0] else None,
                )
                event.backend = BACKEND_REDIS
                return
            except UsageQueueFull:
                raise
            except UsageStoreError as exc:
                if self._journal_dir is None:
                    logger.error(
                        "microauth: the Redis usage queue is unavailable (%s); "
                        "the event is kept in memory only",
                        exc,
                    )
                    event.backend = BACKEND_MEMORY
                    return
                logger.warning(
                    "microauth: the Redis usage queue is unavailable (%s); "
                    "falling back to the local journal",
                    exc,
                )
        future = self._submit_journal_ops([JournalOp(op="create", event=_event_payload(event))])
        if future is None:
            event.backend = BACKEND_MEMORY
            return
        # The shield keeps the shared future alive when this request is
        # cancelled: the detached writer still resolves it, so its outcome
        # remains observable and other waiters are unaffected.
        await asyncio.shield(future)
        event.backend = BACKEND_JOURNAL

    # -------------------------------------------------------------- journal

    def _ensure_journal(self) -> WalJournal | None:
        if self._journal_dir is None:
            return None
        if self._journal is None:
            self._journal = WalJournal(
                self._journal_dir,
                max_items=self._max_items,
                grace_seconds=self._journal_grace,
            )
        return self._journal

    def _submit_journal_ops(
        self,
        ops: list[JournalOp],
    ) -> asyncio.Future[None] | None:
        journal = self._ensure_journal()
        if journal is None or not ops:
            return None
        if self._store_error is not None and time.monotonic() < self._store_error_until:
            # Fail fast during the cooldown; afterwards the next write probes
            # the journal again instead of staying poisoned until restart.
            raise self._store_error
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._journal_writes.append((ops, future))
        writer = self._journal_writer_task
        if writer is None or writer.done():
            # A detached task owns the write loop, so cancelling any waiting
            # request can never strand other requests' futures unresolved.
            self._journal_writer_task = asyncio.create_task(
                self._run_journal_writer(),
                name="microauth-usage-journal-writer",
            )
        return future

    async def _run_journal_writer(self) -> None:
        journal = self._journal
        assert journal is not None  # guarded by _submit_journal_ops
        while self._journal_writes:
            batch = self._journal_writes
            self._journal_writes = []
            combined = [op for batch_ops, _ in batch for op in batch_ops]
            try:
                # Fast path first: no live-state payloads. Building them
                # costs O(backlog) (every event's attachment list), which
                # once per group commit turns a growing backlog into a
                # quadratic slowdown. The journal asks for them (returns
                # False, writing nothing) only when it actually needs live
                # state: a stolen or removed file, or a due compaction.
                applied = await asyncio.to_thread(journal.apply, combined, None)
                if not applied:
                    await asyncio.to_thread(journal.apply, combined, self._journaled_payloads())
            except BaseException as exc:
                error: Exception
                if isinstance(exc, (UsageQueueFull, UsageStoreError)):
                    error = exc
                elif isinstance(exc, asyncio.CancelledError):
                    error = UsageStoreError("usage journal write was interrupted")
                else:
                    error = UsageStoreError(f"could not persist usage journal: {exc}")
                if isinstance(error, UsageStoreError):
                    self._store_error = error
                    self._store_error_until = time.monotonic() + _STORE_ERROR_COOLDOWN_SECONDS
                for _, waiter in batch:
                    if not waiter.done():
                        waiter.set_exception(error)
                if isinstance(exc, asyncio.CancelledError):
                    raise
            else:
                self._store_error = None
                for _, waiter in batch:
                    if not waiter.done():
                        waiter.set_result(None)

    def _journaled_payloads(self) -> dict[str, dict[str, Any]]:
        return {
            event_id: _event_payload(event)
            for event_id, event in self._events.items()
            if event.backend == BACKEND_JOURNAL
        }

    async def _write_journal(self, ops: list[JournalOp]) -> None:
        future = self._submit_journal_ops(ops)
        if future is not None:
            await asyncio.shield(future)

    # ------------------------------------------------------------ lifecycle

    async def start(self) -> None:
        async with self._start_lock:
            if not self._restored:
                await self._ensure_restored()
                await self._maybe_sweep()
            if self._task is None or self._task.done():
                self._task = asyncio.create_task(
                    self._loop(),
                    name="microauth-usage-reporter",
                )

    async def _ensure_restored(self) -> None:
        if self._restored:
            return
        task = self._restore_task
        if task is None or (task.done() and (task.cancelled() or task.exception() is not None)):
            # Restoration renames adopted journal files; running it in its
            # own task keeps a cancelled caller from abandoning it halfway.
            task = self._restore_task = asyncio.create_task(
                self._restore(),
                name="microauth-usage-restore",
            )
        await asyncio.shield(task)
        self._restored = True

    async def _loop(self) -> None:
        while True:
            deadline = self._flush_deadline
            if deadline is None:
                if self._store is None and self._journal_dir is None:
                    await self._wake.wait()
                    self._wake.clear()
                    continue
                # Idle workers still sweep the shared queue (or the journal
                # directory) so a dead worker's events are recovered without
                # waiting for local traffic.
                try:
                    await asyncio.wait_for(
                        self._wake.wait(),
                        timeout=self._interval,
                    )
                except asyncio.TimeoutError:
                    await self._maybe_sweep()
                else:
                    self._wake.clear()
                continue
            delay = deadline - time.monotonic()
            if delay > 0:
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=delay)
                except asyncio.TimeoutError:
                    pass
                else:
                    self._wake.clear()
                    continue
            await self._maybe_sweep()
            try:
                await self.flush()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - every failure is retried
                self._log_flush_failure(exc)
                self._defer_pending(backoff=True)

    def _log_flush_failure(self, exc: Exception) -> None:
        queued = len(self._events)
        if isinstance(exc, MicroAuthError):
            level = (
                logging.ERROR
                if self._counters.consecutive_failures >= _FAILURES_BEFORE_ERROR
                else logging.WARNING
            )
            logger.log(
                level,
                "microauth: usage delivery failed (%s); %d item(s) stay queued and will be retried",
                exc,
                queued,
            )
            return
        logger.exception("microauth: usage delivery failed; %d item(s) stay queued", queued)

    async def _maybe_sweep(self) -> None:
        """Claim due and abandoned events from the durable backends."""

        if self._store is None and self._journal_dir is None:
            return
        now = time.monotonic()
        if self._last_sweep and now - self._last_sweep < self._interval:
            return
        self._last_sweep = now
        if self._store is not None:
            await self._sweep_store()
        if self._journal_dir is not None and self._restored:
            await self._sweep_journal()

    async def _sweep_store(self) -> None:
        assert self._store is not None
        capacity = self._max_items - len(self._events) - len(self._reservations)
        if capacity <= 0:
            return
        try:
            claimed = await self._store.claim_due(min(capacity, self._batch_size))
        except UsageStoreError as exc:
            logger.warning(
                "microauth: the Redis usage queue sweep failed (%s)",
                exc,
            )
            return
        recovered: list[_UsageEvent] = []
        for event_id, payload in claimed:
            if event_id in self._events:
                continue
            try:
                event = _event_from_store_payload(event_id, payload)
            except UsageStoreError as exc:
                logger.error(
                    "microauth: dead-lettering an unreadable usage event %s "
                    "from the Redis queue (%s)",
                    event_id,
                    exc,
                )
                try:
                    await self._store.dead_letter(
                        event_id,
                        str(exc),
                        payload,
                        rejected_at=_iso(self._clock.time()),
                    )
                except UsageStoreError:
                    logger.exception("microauth: unreadable usage event could not be dead-lettered")
                continue
            event.backend = BACKEND_REDIS
            recovered.append(event)
        await self._absorb_recovered(recovered)

    async def _sweep_journal(self) -> None:
        """Keep our journal claimed and adopt files abandoned by others."""

        journal = self._ensure_journal()
        if journal is None:
            return
        try:
            await asyncio.to_thread(journal.heartbeat)
        except OSError as exc:
            logger.warning("microauth: could not refresh the usage journal (%s)", exc)
        if len(self._events) + len(self._reservations) >= self._max_items:
            return  # adopt once there is room; the files wait safely
        try:
            adopted, claimed_paths = await asyncio.to_thread(journal.adopt_orphans)
        except Exception as exc:  # noqa: BLE001 - storage boundary
            logger.warning(
                "microauth: usage journal sweep failed (%s)",
                exc,
            )
            return
        try:
            await self._absorb_payloads(adopted)
        except UsageStoreError as exc:
            # The claimed files survive and stay adoptable by any process;
            # nothing is lost, the adoption simply retries later.
            logger.warning(
                "microauth: could not re-journal adopted usage events (%s)",
                exc,
            )
            return
        # Reached only after the adopted events are durably re-journaled
        # under our ownership (inside _absorb_payloads).
        if claimed_paths:
            await asyncio.to_thread(journal.remove_adopted, claimed_paths)

    async def _absorb_payloads(self, payloads: dict[str, dict[str, Any]]) -> None:
        """Validate adopted payloads, re-journal them as ours, absorb them.

        Everything adopted is absorbed, even past the queue bound: the bound
        limits new admissions, and dropping adopted usage would lose it.
        """

        recovered: list[_UsageEvent] = []
        unreadable: list[JournalOp] = []
        for event_id, payload in payloads.items():
            if event_id in self._events:
                continue
            try:
                event = _event_from_store_payload(event_id, payload)
            except UsageStoreError as exc:
                unreadable.append(self._unreadable_op(event_id, payload, exc))
                continue
            event.backend = BACKEND_JOURNAL
            recovered.append(event)
        if not recovered and not unreadable:
            return
        await self._write_journal(
            [JournalOp(op="create", event=_event_payload(event)) for event in recovered]
            + unreadable
        )
        await self._absorb_recovered(recovered)

    def _unreadable_op(
        self,
        event_id: str,
        payload: dict[str, Any],
        exc: Exception,
    ) -> JournalOp:
        logger.error(
            "microauth: a queued usage event %s in the journal is unreadable "
            "(%s); it was moved to the dead letters for inspection",
            event_id,
            exc,
        )
        return JournalOp(
            op="dead",
            event_id=event_id,
            event=payload,
            detail=f"unreadable usage event: {exc}",
            rejected_at=self._clock.time(),
        )

    async def _absorb_recovered(self, recovered: list[_UsageEvent]) -> None:
        if not recovered:
            return
        for event in recovered:
            # A recovered event may already have been attempted by its dead
            # owner; its payload is pinned by the server's receipt.
            event.frozen = True
        await self._notify(self._on_restored, _event_attachments(recovered))
        for event in recovered:
            self._events[event.idempotency_key] = event
            self._pending.append(event.idempotency_key)
            self._pending_requests += event.count
        self._schedule_flush()

    async def _restore(self) -> None:
        journal = self._ensure_journal()
        if journal is None:
            return
        try:
            state = await asyncio.to_thread(journal.replay_own)
            adopted, claimed_paths = await asyncio.to_thread(journal.adopt_orphans)
        except UsageStoreError:
            raise
        except Exception as exc:
            raise UsageStoreError(
                f"could not restore the usage journal in {self._journal_dir}: {exc}"
            ) from exc
        own: list[_UsageEvent] = []
        unreadable: list[JournalOp] = []
        for event_id, payload in state.items():
            if event_id in self._events:
                continue
            try:
                event = _event_from_store_payload(event_id, payload)
            except UsageStoreError as exc:
                unreadable.append(self._unreadable_op(event_id, payload, exc))
                continue
            event.backend = BACKEND_JOURNAL
            own.append(event)
        if unreadable:
            await self._write_journal(unreadable)
        await self._absorb_payloads(
            {event_id: payload for event_id, payload in adopted.items() if event_id not in state}
        )
        if claimed_paths:
            await asyncio.to_thread(journal.remove_adopted, claimed_paths)
        await self._absorb_recovered(own)
        if self._events:
            logger.info(
                "microauth: recovered %d queued usage item(s) covering %d request(s) from %s",
                len(self._events),
                self.pending_requests,
                self._journal_dir,
            )

    async def aclose(self) -> None:
        """Stop the loop and drain, or raise ``UsageDrainError`` clearly."""

        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.exception("microauth: usage reporter task stopped with an error")
            self._task = None
        # A trailing waiter sleeping toward its deadline must not delay
        # shutdown; the drain below delivers everything it was waiting for.
        await self._cancel_trailing_flush()
        writer = self._journal_writer_task
        if writer is not None and not writer.done():
            # The journal writer self-terminates once its queue drains; wait
            # for in-flight writes so the drain below sees their outcome.
            try:
                await writer
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.exception("microauth: usage journal writer stopped with an error")
        self._journal_writer_task = None
        try:
            await asyncio.wait_for(
                self._drain(),
                timeout=self._shutdown_timeout,
            )
        except Exception as exc:
            await self._cancel_response_flush()
            if not self._reservations and await self._hand_back():
                return
            raise UsageDrainError(self.pending_items, str(exc)) from exc
        await self._cancel_response_flush()
        if self._events or self._reservations:
            if not self._reservations and await self._hand_back():
                return
            raise UsageDrainError(
                len(self._events) + len(self._reservations),
                "queue changed while shutdown was draining",
            )
        if self._journal is not None:
            # A clean drain leaves nothing to recover; remove the journal so
            # hosts do not accumulate one file per past process.
            await asyncio.to_thread(self._journal.remove_if_empty, {})

    async def _hand_back(self) -> bool:
        """Leave undelivered events where another process will deliver them.

        Returns True when every locally queued event is durably owned by
        Redis or the journal again, meaning shutdown lost nothing and need
        not raise.
        """

        if not self._events:
            return True
        by_backend: dict[str, list[str]] = {}
        for event_id, event in self._events.items():
            by_backend.setdefault(event.backend, []).append(event_id)
        if by_backend.get(BACKEND_MEMORY):
            return False
        redis_ids = by_backend.get(BACKEND_REDIS, [])
        journal_ids = by_backend.get(BACKEND_JOURNAL, [])
        if redis_ids:
            if self._store is None:  # pragma: no cover - redis events imply a store
                return False
            try:
                released = await self._store.release(redis_ids)
            except UsageStoreError:
                logger.exception(
                    "microauth: undelivered usage could not be handed back to "
                    "the Redis queue during shutdown"
                )
                return False
            logger.warning(
                "microauth: %d undelivered usage item(s) were handed back to "
                "the Redis queue for another worker (released %d lease(s))",
                len(redis_ids),
                released,
            )
        if journal_ids:
            journal = self._ensure_journal()
            if journal is None:  # pragma: no cover - journal events imply a journal
                return False
            try:
                # Compact first so the released file carries exactly the
                # undelivered events, then backdate it for instant adoption.
                await asyncio.to_thread(journal.compact, self._journaled_payloads())
                await asyncio.to_thread(journal.disown)
            except Exception:
                logger.exception(
                    "microauth: undelivered usage could not be handed back to "
                    "the journal during shutdown"
                )
                return False
            logger.warning(
                "microauth: %d undelivered usage item(s) were left in %s for "
                "the next process to deliver",
                len(journal_ids),
                self._journal_dir,
            )
        self._remove_events(list(self._events))
        self._pending.clear()
        return True

    async def _drain(self) -> None:
        response_task = self._response_flush_task
        if response_task is not None and response_task is not asyncio.current_task():
            try:
                await response_task
            finally:
                if self._response_flush_task is response_task:
                    self._response_flush_task = None
        await self._ensure_restored()
        await self.flush()

    # ---------------------------------------------------------- flush paths

    async def flush_on_response(
        self,
        event_id: str | None = None,
        *,
        only_if_due: bool = False,
    ) -> None:
        """Deliver a response's event, coalescing concurrent callers.

        With ``only_if_due`` the call returns without delivering unless the
        batching rule (full batch, or the interval elapsed since the last
        flush) calls for it; the event stays durably queued for a later batch.
        """

        if only_if_due:
            # Batching mode: join (or start) one coalesced delivery pass and
            # return. Waiting until this response's own event ships would
            # serialize every in-flight request onto delivery latency under
            # sustained load; an event that misses this pass is durably
            # queued and ships with the next due batch.
            if not self.flush_is_due(event_id):
                return
            task = self._response_flush_task
            if task is None or task.done():
                task = asyncio.create_task(
                    self._flush_response_batch(),
                    name="microauth-usage-response-flush",
                )
                self._response_flush_task = task
            try:
                await asyncio.shield(task)
            finally:
                if self._response_flush_task is task and task.done():
                    self._response_flush_task = None
            return

        targets = {event_id} if event_id is not None else set(self._events)
        while any(target in self._events for target in targets):
            task = self._response_flush_task
            if task is None or task.done():
                task = asyncio.create_task(
                    self._flush_response_batch(),
                    name="microauth-usage-response-flush",
                )
                self._response_flush_task = task
            try:
                await asyncio.shield(task)
            finally:
                if self._response_flush_task is task and task.done():
                    self._response_flush_task = None

    async def _flush_response_batch(self) -> None:
        # A very short post-response window lets concurrently completed ASGI
        # requests share one usage call. The client response has already been
        # sent, so this reduces serverless request amplification without adding
        # user-visible latency.
        await asyncio.sleep(_RESPONSE_BATCH_WINDOW)
        # Serverless workers may never run the background loop between
        # invocations, so the response-bound path also recovers abandoned
        # events (throttled to one claim per interval).
        await self._maybe_sweep()
        await self.flush()

    async def flush_trailing(self, event_id: str | None = None) -> None:
        """Hold the caller until the batching deadline, then deliver.

        A serverless surrogate for the background loop's timer: runtimes
        that freeze the event loop between invocations never fire the
        interval deadline, so a response whose event was not yet due keeps
        the still-active invocation alive until the deadline and delivers
        the trailing batch. Concurrent responses coalesce onto one waiter.
        The waiter makes at most one delivery attempt; a failure arms the
        normal failure backoff and leaves every event durably queued for a
        later invocation instead of retrying inside the held invocation.
        """

        if event_id is not None and event_id not in self._events:
            return
        if not self._events:
            return
        task = self._trailing_flush_task
        if task is None or task.done():
            task = asyncio.create_task(
                self._trailing_flush(),
                name="microauth-usage-trailing-flush",
            )
            self._trailing_flush_task = task
        try:
            await asyncio.shield(task)
        finally:
            if self._trailing_flush_task is task and task.done():
                self._trailing_flush_task = None

    async def _trailing_flush(self) -> None:
        while True:
            if not self._events:
                # A concurrent due-path flush delivered everything while this
                # waiter slept; there is nothing left to hold the invocation
                # open for.
                return
            deadline = self._flush_deadline
            if deadline is None:
                # Pending events normally carry a deadline; an in-flight
                # flush clears it while delivering. Fall back to one interval
                # so a deferred remainder is still attempted exactly once.
                deadline = time.monotonic() + self._interval
            delay = deadline - time.monotonic()
            if delay <= 0:
                break
            # Chunked sleep so a deadline moved by the failure backoff (or
            # cleared by a concurrent delivery) is observed without wiring
            # this waiter into the background loop's wake event.
            await asyncio.sleep(min(delay, self._interval))
        await self._maybe_sweep()
        try:
            await self.flush()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - every failure is retried
            self._log_flush_failure(exc)
            self._defer_pending(backoff=True)

    async def flush(self) -> None:
        """Deliver all selected events while retaining only transient failures."""

        async with self._flush_lock:
            self._last_flush = time.monotonic()
            await self._expire_stale_events()
            selected: list[str] = []
            deferred: list[str] = []
            settling: list[str] = []
            for event_id in self._pending:
                event = self._events.get(event_id)
                if event is None:
                    continue
                # Close the event to new merges first: under sustained
                # concurrency its merge latch may never otherwise reach
                # zero, and skipping busy events would starve delivery
                # entirely (no posts, unbounded backlog, a hot flush loop).
                if self._open_events.get(event.merge_key()) == event_id:
                    del self._open_events[event.merge_key()]
                settling.append(event_id)
            for event_id in settling:
                event = self._events.get(event_id)
                if event is None:
                    continue
                # In-flight durable increments finish within a group commit;
                # wait them out so a payload is never frozen halfway through
                # a merge (a failed merge's rollback must never mutate a
                # frozen, receipt-pinned count).
                settle_deadline = time.monotonic() + 2.0
                while event.merging and time.monotonic() < settle_deadline:
                    await asyncio.sleep(0.001)
                if event.merging:
                    # Pathologically stuck increment: deliver everyone else.
                    deferred.append(event_id)
                    continue
                # Selection permanently freezes the payload: the server's
                # receipt pins this idempotency key to this exact count.
                event.frozen = True
                selected.append(event_id)
            self._pending = deque(deferred)
            # Exact recompute of the additive request counter (deferred lists
            # are tiny: only events with a pathologically stuck merge).
            self._pending_requests = sum(
                event.count
                for event_id in deferred
                if (event := self._events.get(event_id)) is not None
            )
            if not selected:
                if deferred:
                    # Retry shortly without spinning: the immediate full-batch
                    # fast path would otherwise hot-loop on a stuck merge.
                    self._flush_deadline = max(time.monotonic() + 0.05, self._backoff_until)
                    self._wake.set()
                else:
                    self._flush_deadline = None
                return
            self._flush_deadline = None

            first_error: Exception | None = None
            try:
                for offset in range(0, len(selected), self._batch_size):
                    chunk_ids = [
                        event_id
                        for event_id in selected[offset : offset + self._batch_size]
                        if event_id in self._events
                    ]
                    if not chunk_ids:
                        continue
                    await self._extend_store_leases(chunk_ids)
                    try:
                        retry_ids, error = await self._deliver(chunk_ids)
                    except MicroAuthAuthorizationError as exc:
                        await self._notify_authorization_failure(exc)
                        self._requeue_back(selected[offset:])
                        raise
                    except BaseException:
                        self._requeue_back(selected[offset:])
                        raise
                    self._requeue_back(retry_ids)
                    if first_error is None and error is not None:
                        first_error = error
                if first_error is not None:
                    raise first_error
                # Deliveries succeeded end to end; retries resume immediately.
                self._backoff_until = 0.0
                self._counters.consecutive_failures = 0
            except BaseException as exc:
                # Armed here, inside flush, so every trigger observes it:
                # the background loop, explicit drains, and response-bound
                # serverless flushes alike. Without it a failing delivery
                # retries as fast as it fails, fragmenting the durable queue.
                self._backoff_until = time.monotonic() + self._interval
                if not isinstance(exc, asyncio.CancelledError):
                    self._note_failure(exc)
                raise
            finally:
                if self._pending:
                    self._defer_pending()
                    await self._extend_store_leases(list(self._pending))

    def _note_failure(self, exc: BaseException) -> None:
        counters = self._counters
        counters.consecutive_failures += 1
        counters.last_error = f"{type(exc).__name__}: {exc}"[:500]
        counters.last_error_at = self._clock.time()

    async def _expire_stale_events(self) -> None:
        """Dead-letter events the API would terminally reject by age."""

        cutoff = self._clock.time() - _MAX_EVENT_AGE_SECONDS
        expired = [
            event_id
            for event_id, event in self._events.items()
            if not event.merging and event.period_epoch() < cutoff
        ]
        if expired:
            await self._dead_letter(
                [
                    (
                        event_id,
                        _ItemRejection(
                            http_status=None,
                            detail=(
                                "the item passed MicroAuth's 45 day usage age "
                                "limit before it could be delivered"
                            ),
                        ),
                    )
                    for event_id in expired
                ]
            )

    async def _extend_store_leases(self, event_ids: list[str]) -> None:
        if self._store is None or not event_ids:
            return
        redis_ids = [
            event_id
            for event_id in event_ids
            if (event := self._events.get(event_id)) is not None and event.backend == BACKEND_REDIS
        ]
        if not redis_ids:
            return
        try:
            await self._store.extend_leases(redis_ids)
        except UsageStoreError as exc:
            logger.warning(
                "microauth: Redis usage delivery leases could not be renewed (%s)",
                exc,
            )

    async def _deliver(
        self,
        event_ids: list[str],
    ) -> tuple[list[str], UsageAcknowledgementError | None]:
        payload = [
            self._events[event_id].as_payload()
            for event_id in event_ids
            if event_id in self._events
        ]
        if not payload:
            return [], None
        try:
            response = await self._client.report_usage(payload)
        except MicroAuthAuthorizationError:
            raise
        except MicroAuthAPIError as exc:
            if not _is_terminal_item_error(exc):
                raise
            if len(event_ids) > 1:
                # Bisection over a poisoned chunk can outlive the original
                # delivery lease; renew it so another worker does not start
                # re-delivering the same frozen events mid-isolation.
                await self._extend_store_leases(event_ids)
                midpoint = len(event_ids) // 2
                left_retry, left_error = await self._deliver(event_ids[:midpoint])
                right_retry, right_error = await self._deliver(event_ids[midpoint:])
                return left_retry + right_retry, left_error or right_error
            event_id = event_ids[0]
            if event_id in self._events:
                await self._dead_letter(
                    [
                        (
                            event_id,
                            _ItemRejection(
                                http_status=exc.status_code,
                                detail=exc.detail or f"HTTP {exc.status_code}",
                            ),
                        )
                    ]
                )
            return [], None

        self._counters.last_delivery_at = self._clock.time()
        plan = _parse_acknowledgements(response, event_ids)
        accepted_events = [
            self._events[event_id] for event_id in plan.accepted if event_id in self._events
        ]
        if accepted_events:
            accepted_ids = [event.idempotency_key for event in accepted_events]
            attachments = _event_attachments(accepted_events)
            if self._on_acknowledged is not None and attachments:
                result = self._on_acknowledged(attachments, plan.balances)
                if inspect.isawaitable(result):
                    await result
            receipts = self._issue_receipts(accepted_events, plan.receipts)
            await self._run_hook("on_receipts", self._on_receipts, receipts)
            redis_ids = [
                event.idempotency_key for event in accepted_events if event.backend == BACKEND_REDIS
            ]
            if redis_ids and self._store is not None:
                try:
                    await self._store.ack(redis_ids)
                except UsageStoreError as exc:
                    # MicroAuth already recorded these idempotent items; a
                    # re-claimed copy will be acknowledged as a duplicate.
                    logger.warning(
                        "microauth: delivered usage could not be removed from the Redis queue (%s)",
                        exc,
                    )
            journal_ids = [
                event.idempotency_key
                for event in accepted_events
                if event.backend == BACKEND_JOURNAL
            ]
            if journal_ids:
                await self._write_journal([JournalOp(op="ack", event_ids=journal_ids)])
            self._remove_events(accepted_ids)

        rejected = [
            (event_id, rejection)
            for event_id, rejection in plan.rejected.items()
            if event_id in self._events
        ]
        if rejected:
            await self._dead_letter(rejected)

        retry = [event_id for event_id in plan.retry if event_id in self._events]
        return retry, plan.error

    def _issue_receipts(
        self,
        events: list[_UsageEvent],
        fields: dict[str, _ItemReceipt],
    ) -> list[UsageReceipt]:
        delivered_at = self._clock.now()
        counters = self._counters
        receipts: list[UsageReceipt] = []
        for event in events:
            item = fields.get(event.idempotency_key) or _ItemReceipt(
                outcome="accepted",
                customer_id=None,
                charged_micro=None,
                recorded_at=None,
            )
            receipt = UsageReceipt(
                idempotency_key=event.idempotency_key,
                outcome=item.outcome,
                customer_id=item.customer_id,
                api_key_id=event.api_key_id,
                usage_policy_id=event.usage_policy_id,
                status_code=event.status_code,
                count=event.count,
                period_start=datetime.fromtimestamp(event.period_epoch(), timezone.utc),
                charged_micro=item.charged_micro,
                expected_charge_micro=event.expected_charge(),
                recorded_at=item.recorded_at,
                delivered_at=delivered_at,
            )
            counters.delivered_items += 1
            counters.delivered_requests += event.count
            if receipt.outcome == "duplicate":
                counters.duplicate_items += 1
            if receipt.charged_micro is not None:
                counters.charged_micro += receipt.charged_micro
            elif not self._warned_missing_receipt:
                self._warned_missing_receipt = True
                logger.warning(
                    "microauth: MicroAuth acknowledged usage without saying "
                    "what it charged, so charges can't be checked. Update "
                    "microauth-fastapi if this keeps happening"
                )
            if receipt.charge_matches is False:
                counters.charge_mismatches += 1
                logger.error(
                    "microauth: MicroAuth charged %d micro-USD for usage item "
                    "%s, but the SDK expected %d (%d request(s) with status %d "
                    "under usage policy %s, customer %s)",
                    receipt.charged_micro,
                    receipt.idempotency_key,
                    receipt.expected_charge_micro,
                    receipt.count,
                    receipt.status_code,
                    receipt.usage_policy_id,
                    receipt.customer_id or "unknown",
                )
            receipts.append(receipt)
        return receipts

    async def _dead_letter(
        self,
        entries: list[tuple[str, _ItemRejection]],
    ) -> None:
        """Retire items MicroAuth refused for good, keeping a durable record."""

        rejected_at = self._clock.time()
        targets = [
            (self._events[event_id], rejection)
            for event_id, rejection in entries
            if event_id in self._events
        ]
        if not targets:
            return
        # Refused usage is never charged; the limiter returns its holds.
        await self._notify(
            self._on_rejected,
            _event_attachments(event for event, _ in targets),
        )
        rejected_on = _datetime(rejected_at)
        assert rejected_on is not None
        rejections = [
            UsageRejection(
                idempotency_key=event.idempotency_key,
                api_key_id=event.api_key_id,
                usage_policy_id=event.usage_policy_id,
                status_code=event.status_code,
                count=event.count,
                period_start=datetime.fromtimestamp(event.period_epoch(), timezone.utc),
                http_status=rejection.http_status,
                detail=rejection.detail,
                rejected_at=rejected_on,
            )
            for event, rejection in targets
        ]
        await self._run_hook("on_rejections", self._on_rejections, rejections)
        journal_ops: list[JournalOp] = []
        for event, rejection in targets:
            # Redis keeps its own dead letters; the journal's dead-letter
            # file is the record for everything else, and the fallback when
            # Redis can't take one.
            needs_local_record = event.backend != BACKEND_REDIS
            if event.backend == BACKEND_REDIS and self._store is not None:
                try:
                    await self._store.dead_letter(
                        event.idempotency_key,
                        rejection.detail,
                        _event_payload(event),
                        http_status=rejection.http_status,
                        rejected_at=_iso(rejected_at),
                    )
                except UsageStoreError:
                    logger.exception(
                        "microauth: a rejected usage item could not be moved "
                        "to the Redis dead letters"
                    )
                    needs_local_record = True
            if needs_local_record:
                journal_ops.append(
                    JournalOp(
                        op="dead",
                        event_id=event.idempotency_key,
                        event=_event_payload(event),
                        detail=rejection.detail,
                        http_status=rejection.http_status,
                        rejected_at=rejected_at,
                    )
                )
        if journal_ops:
            await self._write_journal(journal_ops)
        self._remove_events([event.idempotency_key for event, _ in targets])
        counters = self._counters
        for event, rejection in targets:
            counters.rejected_items += 1
            counters.rejected_requests += event.count
            logger.error(
                "microauth: MicroAuth refused usage item %s (%d request(s) with status %d): %s",
                event.idempotency_key,
                event.count,
                event.status_code,
                rejection.detail,
            )

    async def _run_hook(
        self,
        name: str,
        callback: Callable[[list[Any]], Awaitable[None] | None] | None,
        records: list[Any],
    ) -> None:
        """Hand records to user code without letting it stall delivery."""

        if callback is None or not records:
            return
        try:
            if _is_async_callable(callback):
                awaitable = callback(list(records))
                if awaitable is not None:
                    await asyncio.wait_for(awaitable, self._hook_timeout)
            else:
                result = await asyncio.wait_for(
                    asyncio.to_thread(callback, list(records)),
                    self._hook_timeout,
                )
                if inspect.isawaitable(result):
                    await asyncio.wait_for(result, self._hook_timeout)
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            self._counters.hook_failures += 1
            logger.error(
                "microauth: the %s hook did not finish within %.0fs; usage "
                "delivery went on without it",
                name,
                self._hook_timeout,
            )
        except Exception:
            self._counters.hook_failures += 1
            logger.exception(
                "microauth: the %s hook raised; usage delivery went on without it",
                name,
            )

    # ------------------------------------------------------------- helpers

    async def _cancel_response_flush(self) -> None:
        task = self._response_flush_task
        if task is None:
            return
        if not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.exception("microauth: response-bound usage flush stopped with an error")
        if self._response_flush_task is task:
            self._response_flush_task = None

    async def _cancel_trailing_flush(self) -> None:
        task = self._trailing_flush_task
        if task is None:
            return
        if not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.exception("microauth: trailing usage flush stopped with an error")
        if self._trailing_flush_task is task:
            self._trailing_flush_task = None

    def _consume_reservation(self, reservation: UsageReservation) -> None:
        if reservation.token not in self._reservations:
            raise ValueError("usage queue reservation is invalid or already consumed")
        self._reservations.remove(reservation.token)

    def _remove_events(self, event_ids: Iterable[str]) -> None:
        for event_id in event_ids:
            event = self._events.pop(event_id, None)
            if event is not None and self._open_events.get(event.merge_key()) == event_id:
                del self._open_events[event.merge_key()]

    def _requeue_back(self, event_ids: Iterable[str]) -> None:
        requested = [event_id for event_id in event_ids if event_id in self._events]
        if not requested:
            return
        existing = set(self._pending)
        for event_id in requested:
            if event_id in existing:
                continue
            self._pending.append(event_id)
            self._pending_requests += self._events[event_id].count

    def _full_batch_pending(self) -> bool:
        """True when at least one full batch of requests awaits delivery.

        The running counter is maintained additively on the hot path and can
        only over-approximate (removals do not decrement it); flush selection
        recomputes it exactly. Over-approximation is harmless: it can only
        trigger a slightly early flush.
        """

        return self._pending_requests >= self._batch_size

    def _schedule_flush(self) -> None:
        now = time.monotonic()
        if self._full_batch_pending():
            # A full batch of requests flushes immediately instead of waiting
            # out the interval deadline.
            deadline = now
        elif self._flush_deadline is None:
            deadline = now + self._interval
        else:
            deadline = self._flush_deadline
        # The failure backoff is authoritative: a permanently full backlog
        # during an outage must not turn every request into a retry trigger.
        self._flush_deadline = max(deadline, self._backoff_until)
        self._wake.set()

    def flush_is_due(self, event_id: str | None = None) -> bool:
        """True when the 500-or-interval batching rule calls for a delivery.

        A delivery is due when a full batch of requests has accumulated or
        the interval has elapsed since the last flush while events are queued.
        Never during the failure backoff window: retrying on every response
        while the control plane is down would fragment the durable queue.
        """

        if event_id is not None and event_id not in self._events:
            return False
        if not self._events:
            return False
        if time.monotonic() < self._backoff_until:
            return False
        if self._full_batch_pending():
            return True
        return time.monotonic() - self._last_flush >= self._interval

    def _defer_pending(self, *, backoff: bool = False) -> None:
        if not self._pending:
            self._flush_deadline = None
            return
        now = time.monotonic()
        if backoff:
            self._backoff_until = now + self._interval
        if not backoff and self._full_batch_pending():
            # A full batch completed while a flush was in flight; deliver it
            # immediately instead of waiting out another interval. Failed
            # flushes pass backoff=True and always wait the interval.
            deadline = now
        elif self._flush_deadline is None or self._flush_deadline <= now:
            deadline = now + self._interval
        else:
            deadline = self._flush_deadline
        self._flush_deadline = max(deadline, self._backoff_until)
        self._wake.set()

    async def _notify(
        self,
        callback: UsageCallback | None,
        attachments: list[dict[str, Any]],
    ) -> None:
        if callback is None or not attachments:
            return
        result = callback(attachments)
        if inspect.isawaitable(result):
            await result

    async def _notify_authorization_failure(
        self,
        error: MicroAuthAuthorizationError,
    ) -> None:
        if self._on_authorization_failure is None:
            return
        result = self._on_authorization_failure(error)
        if inspect.isawaitable(result):
            await result


def _undo_merge(event: _UsageEvent, attachment: dict[str, Any]) -> None:
    event.count -= 1
    if attachment:
        try:
            event.attachments.remove(attachment)
        except ValueError:
            pass


def _is_async_callable(callback: Any) -> bool:
    return inspect.iscoroutinefunction(callback) or inspect.iscoroutinefunction(
        getattr(callback, "__call__", None)  # noqa: B004 - callable objects
    )


def _is_terminal_item_error(error: MicroAuthAPIError) -> bool:
    return error.status_code in _TERMINAL_ITEM_HTTP_STATUSES


def _parse_acknowledgements(
    response: dict[str, Any],
    expected_ids: list[str],
) -> _Acknowledgements:
    raw_results = response.get("results")
    if not isinstance(raw_results, list):
        return _Acknowledgements(
            accepted=[],
            rejected={},
            retry=list(expected_ids),
            error=UsageAcknowledgementError("usage response must contain a results array"),
        )

    expected = set(expected_ids)
    seen: set[str] = set()
    accepted: set[str] = set()
    receipts: dict[str, _ItemReceipt] = {}
    rejected: dict[str, _ItemRejection] = {}
    retryable: set[str] = set()
    invalid_ids: set[str] = set()
    malformed = False
    detail = ""

    for index, raw in enumerate(raw_results):
        if not isinstance(raw, dict):
            malformed = True
            detail = f"usage result at index {index} must be an object"
            continue
        event_id = raw.get("idempotency_key")
        status = raw.get("status")
        if not isinstance(event_id, str) or event_id not in expected:
            malformed = True
            detail = f"usage result at index {index} has an unknown idempotency_key"
            continue
        if event_id in seen:
            malformed = True
            detail = f"usage result repeats idempotency_key {event_id}"
            invalid_ids.add(event_id)
            continue
        seen.add(event_id)
        if status in _SUCCESS_STATUSES:
            accepted.add(event_id)
            receipts[event_id] = _parse_receipt(str(status), raw)
        elif status == "rejected":
            rejected[event_id] = _parse_rejection(raw)
        elif status == "retry":
            # A transient server-side failure for this item only; it stays
            # queued with an unchanged payload for the next delivery.
            retryable.add(event_id)
        else:
            malformed = True
            detail = f"usage item {event_id} has unsupported status {status!r}"
            invalid_ids.add(event_id)

    accepted.difference_update(invalid_ids)
    for event_id in invalid_ids:
        rejected.pop(event_id, None)
        receipts.pop(event_id, None)
    retry = [
        event_id
        for event_id in expected_ids
        if event_id not in accepted and event_id not in rejected
    ]
    missing = [event_id for event_id in expected_ids if event_id not in seen]
    if missing:
        malformed = True
        detail = f"usage response omitted {len(missing)} submitted item(s)"
    if len(raw_results) != len(expected_ids):
        malformed = True
        if not detail:
            detail = "usage response must contain exactly one result per submitted item"
    error = UsageAcknowledgementError(detail) if malformed else None
    if error is None and retryable:
        logger.info(
            "microauth: %d usage item(s) will be retried at the next flush",
            len(retryable),
        )
    return _Acknowledgements(
        accepted=[event_id for event_id in expected_ids if event_id in accepted],
        rejected={
            event_id: rejected[event_id] for event_id in expected_ids if event_id in rejected
        },
        retry=retry,
        error=error,
        receipts=receipts,
        balances=_parse_committed_balances(response.get("customers")),
    )


def _parse_receipt(outcome: str, raw: dict[str, Any]) -> _ItemReceipt:
    """Receipt fields of one recorded item, each dropped if malformed.

    The item's status alone decides that it was recorded; a receipt field
    the SDK can't read only leaves that field unknown.
    """

    customer_id = raw.get("customer_id")
    charged = raw.get("charged_micro")
    return _ItemReceipt(
        outcome=outcome,
        customer_id=(
            customer_id if isinstance(customer_id, str) and 0 < len(customer_id) <= 64 else None
        ),
        charged_micro=(
            charged
            if isinstance(charged, int)
            and not isinstance(charged, bool)
            and 0 <= charged <= MAX_SAFE_INTEGER
            else None
        ),
        recorded_at=_optional_timestamp(raw.get("recorded_at")),
    )


def _parse_rejection(raw: dict[str, Any]) -> _ItemRejection:
    http_status = raw.get("http_status")
    detail = raw.get("detail")
    return _ItemRejection(
        http_status=(
            http_status
            if isinstance(http_status, int)
            and not isinstance(http_status, bool)
            and 400 <= http_status <= 599
            else None
        ),
        detail=(
            detail[:2000]
            if isinstance(detail, str) and detail
            else "MicroAuth rejected the usage item"
        ),
    )


def _optional_timestamp(raw: Any) -> datetime | None:
    if not isinstance(raw, str) or len(raw) > 64:
        return None
    try:
        parsed = parse_iso8601(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _parse_committed_balances(raw: Any) -> list[CustomerBalance]:
    """Committed per-customer balances that came back with an ack.

    Anything malformed is dropped as a whole: the limiter then falls back
    to snapshot-based reconciliation, which is slower but always safe.
    """

    if not isinstance(raw, list):
        return []
    balances: list[CustomerBalance] = []
    for entry in raw:
        if not isinstance(entry, dict):
            return []
        customer_id = entry.get("id")
        balance = entry.get("credit_balance_micro")
        seq = entry.get("balance_seq")
        if (
            not isinstance(customer_id, str)
            or not customer_id
            or isinstance(balance, bool)
            or not isinstance(balance, int)
            or abs(balance) > MAX_SAFE_INTEGER
            or isinstance(seq, bool)
            or not isinstance(seq, int)
            or seq < 0
            or seq > MAX_SAFE_INTEGER
        ):
            logger.warning(
                "microauth: usage acknowledgement carried an invalid "
                "committed balance; falling back to snapshot reconciliation"
            )
            return []
        balances.append(
            CustomerBalance(
                customer_id=customer_id,
                credit_balance_micro=balance,
                balance_seq=seq,
            )
        )
    return balances


def _normalize_attachment(
    attachment: dict[str, Any] | None,
) -> dict[str, Any]:
    if attachment is None:
        return {}
    if not isinstance(attachment, dict):
        raise TypeError("usage attachment must be an object")
    if all(type(key) is str and type(value) in (str, int) for key, value in attachment.items()):
        # Flat limiter attachments skip the JSON round trip. Every request
        # for one customer repeats the same scope, keys and period, so
        # interning them keeps a large outage backlog from holding one copy
        # of each string per queued request.
        return {
            key: (
                sys.intern(value)
                if type(value) is str and key not in _UNIQUE_ATTACHMENT_FIELDS
                else value
            )
            for key, value in sorted(attachment.items())
        }
    try:
        encoded = json.dumps(
            attachment,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        decoded = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise ValueError("usage attachment must be JSON safe") from exc
    if not isinstance(decoded, dict):
        raise TypeError("usage attachment must be an object")
    return decoded


def _event_attachments(events: Iterable[_UsageEvent]) -> list[dict[str, Any]]:
    return [attachment for event in events for attachment in event.attachments if attachment]


def _event_payload(event: _UsageEvent) -> dict[str, Any]:
    """The canonical durable envelope: the item plus request attachments."""

    return {
        "item": event.durable_item(),
        "attachments": list(event.attachments),
    }


def _canonical_uuid(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be a UUID") from exc
    if parsed.int == 0:
        raise ValueError(f"{field} must be a non-zero UUID")
    return str(parsed)


def _stored_int(raw: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int) or not minimum <= raw <= maximum:
        raise UsageStoreError(f"usage event has an invalid {field}")
    return raw


def _event_from_store_payload(
    event_id: str,
    payload: dict[str, Any],
) -> _UsageEvent:
    """Rebuild a queued event from its durable envelope, strictly."""

    if not isinstance(payload, dict):
        raise UsageStoreError("usage event envelope must be an object")
    item = payload.get("item")
    attachments_raw = payload.get("attachments")
    if not isinstance(item, dict) or not isinstance(attachments_raw, list):
        raise UsageStoreError("usage event envelope is malformed")
    if item.get("idempotency_key") != event_id:
        raise UsageStoreError("usage event has a mismatched idempotency key")
    try:
        api_key_id = _canonical_uuid(item.get("api_key_id"), "api_key_id")
        usage_policy_id = _canonical_uuid(item.get("usage_policy_id"), "usage_policy_id")
    except ValueError as exc:
        raise UsageStoreError(f"usage event has an invalid id: {exc}") from exc
    status_code = _stored_int(item.get("status_code"), "status_code", 100, 599)
    count = _stored_int(item.get("count"), "count", 1, MAX_USAGE_COUNT)
    period_start = item.get("period_start")
    if not isinstance(period_start, str):
        raise UsageStoreError("usage event has an invalid period_start")
    try:
        parsed = parse_iso8601(period_start)
    except ValueError as exc:
        raise UsageStoreError("usage event has an invalid period_start") from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != timezone.utc.utcoffset(parsed)
        or parsed.minute
        or parsed.second
        or parsed.microsecond
    ):
        raise UsageStoreError("usage event period_start must be an exact UTC hour")
    unit_raw = item.get("unit_charge_micro")
    unit = (
        None
        if unit_raw is None
        else _stored_int(unit_raw, "unit_charge_micro", 0, MAX_SAFE_INTEGER)
    )
    queued_raw = item.get("queued_at")
    queued_at = (
        float(queued_raw)
        if isinstance(queued_raw, (int, float))
        and not isinstance(queued_raw, bool)
        and math.isfinite(float(queued_raw))
        and queued_raw > 0
        else 0.0
    )
    if len(attachments_raw) > count:
        raise UsageStoreError("usage event has more request attachments than requests")
    try:
        attachments = [_normalize_attachment(attachment) for attachment in attachments_raw]
    except (TypeError, ValueError) as exc:
        raise UsageStoreError("usage event has invalid request attachments") from exc
    return _UsageEvent(
        idempotency_key=event_id,
        api_key_id=api_key_id,
        usage_policy_id=usage_policy_id,
        status_code=status_code,
        count=count,
        period_start=period_start,
        unit_charge_micro=unit,
        queued_at=queued_at,
        attachments=attachments,
    )


def _datetime(epoch: float | None) -> datetime | None:
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, timezone.utc)


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")
