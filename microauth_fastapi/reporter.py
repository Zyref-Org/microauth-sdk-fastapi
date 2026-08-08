"""Durable, bounded, idempotent reporting for every completed request."""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import sqlite3
import time
import uuid
from collections import deque
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .client import APIClient
from .exceptions import (
    MicroAuthAPIError,
    MicroAuthAuthorizationError,
    UsageAcknowledgementError,
    UsageDrainError,
    UsageQueueFull,
    UsageStoreError,
)
from .models import MAX_USAGE_COUNT
from .usage_store import (
    UPSERT_MERGED,
    RedisUsageStore,
)

logger = logging.getLogger("microauth")

_DEFAULT_MAX_ITEMS = 10_000
# Deliveries batch up to this many events; reaching it triggers an immediate
# flush instead of waiting for the interval deadline.
_DEFAULT_BATCH_SIZE = 500
_RESPONSE_BATCH_WINDOW = 0.01
_SUCCESS_STATUSES = frozenset({"accepted", "duplicate"})
_TERMINAL_ITEM_HTTP_STATUSES = frozenset({400, 402, 409, 422})

# The API terminally rejects usage older than 45 days; retrying past that only
# converts a delayed delivery into a guaranteed rejection.
_MAX_EVENT_AGE_SECONDS = 45 * 86_400

# After a journal failure the reporter fails fast for this long, then probes
# the store again. A transient locked database or disk blip must not poison
# the process into permanent 503s.
_STORE_ERROR_COOLDOWN_SECONDS = 5.0


class _SpoolFencedError(UsageStoreError):
    """The journal row is owned by another process and must not be mutated."""

UsageCallback = Callable[[list[dict[str, Any]]], Awaitable[None] | None]
AuthorizationCallback = Callable[
    [MicroAuthAuthorizationError],
    Awaitable[None] | None,
]


@dataclass(slots=True)
class _UsageEvent:
    idempotency_key: str
    api_key_id: str
    usage_policy_id: str | None
    status_code: int
    count: int
    period_start: str
    attachments: list[dict[str, Any]] = field(default_factory=list)
    # Once an event has been selected for delivery (or restored from a spool,
    # where a previous attempt may have happened), its payload is immutable:
    # the server's receipt is keyed by idempotency_key and a retry with a
    # different count would be a 409 conflict.
    frozen: bool = False
    # Number of merges currently persisting into this event. Flush selection
    # defers events with active merges so a delivery can never freeze a
    # payload halfway through a durable count increment.
    merging: int = 0
    # Cached epoch seconds of period_start (filled lazily).
    period_ts: float = 0.0

    def as_payload(self) -> dict[str, Any]:
        payload = {
            "idempotency_key": self.idempotency_key,
            "api_key_id": self.api_key_id,
            "status_code": self.status_code,
            "count": self.count,
            "period_start": self.period_start,
        }
        if self.usage_policy_id is not None:
            payload["usage_policy_id"] = self.usage_policy_id
        return payload

    def as_static_payload(self) -> dict[str, Any]:
        payload = self.as_payload()
        del payload["count"]
        return payload

    def merge_key(self) -> tuple[str, str | None, int, str]:
        return (
            self.api_key_id,
            self.usage_policy_id,
            self.status_code,
            self.period_start,
        )


@dataclass(frozen=True, slots=True)
class UsageReservation:
    token: str


@dataclass(frozen=True, slots=True)
class _Acknowledgements:
    accepted: list[str]
    rejected: dict[str, str]
    retry: list[str]
    error: UsageAcknowledgementError | None


def _hour_bucket(value: datetime | None = None) -> str:
    value = value or datetime.now(timezone.utc)
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
        max_items: int = _DEFAULT_MAX_ITEMS,
        batch_size: int = _DEFAULT_BATCH_SIZE,
        shutdown_timeout: float = 10.0,
        spool_path: str | os.PathLike[str] | None = None,
        spool_claim_grace: float = 120.0,
        store: RedisUsageStore | None = None,
        on_acknowledged: UsageCallback | None = None,
        on_rejected: UsageCallback | None = None,
        on_restored: UsageCallback | None = None,
        on_authorization_failure: AuthorizationCallback | None = None,
    ) -> None:
        if interval <= 0:
            raise ValueError("interval must be positive")
        if max_items <= 0:
            raise ValueError("max_items must be positive")
        if batch_size <= 0 or batch_size > 1000:
            raise ValueError("batch_size must be between 1 and 1000")
        if shutdown_timeout <= 0:
            raise ValueError("shutdown_timeout must be positive")
        if spool_claim_grace < 0:
            raise ValueError("spool_claim_grace must not be negative")
        self._client = client
        self._interval = interval
        self._max_items = max_items
        self._batch_size = batch_size
        self._shutdown_timeout = shutdown_timeout
        self._spool_path = Path(spool_path).expanduser() if spool_path else None
        self._on_acknowledged = on_acknowledged
        self._on_rejected = on_rejected
        self._on_restored = on_restored
        self._on_authorization_failure = on_authorization_failure

        self._store = store
        self._events: dict[str, _UsageEvent] = {}
        # Open (unfrozen, pending) events by identity, so requests sharing an
        # API key, policy, status and hour merge into one counted event
        # instead of one row per request.
        self._open_events: dict[tuple[str, str | None, int, str], str] = {}
        self._merge_limit = min(batch_size, MAX_USAGE_COUNT)
        self._pending: deque[str] = deque()
        self._reservations: set[str] = set()
        self._task: asyncio.Task[None] | None = None
        self._response_flush_task: asyncio.Task[None] | None = None
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
        self._spool_writes: list[tuple[list[_UsageEvent], asyncio.Future[None]]] = []
        self._spool_writer_task: asyncio.Task[None] | None = None
        # The default spool file is shared by every worker process on the
        # host, so rows are owner-fenced like the Redis queue: each process
        # claims rows under its own identity, and abandoned rows (owner not
        # writing for spool_claim_grace) are recoverable by any process.
        self._spool_owner = str(uuid.uuid4())
        self._spool_grace = spool_claim_grace
        # Requests awaiting delivery (an O(1) counter for the batch trigger);
        # merged events contribute their full counts.
        self._pending_requests = 0

    @property
    def pending_items(self) -> int:
        return len(self._events)

    @property
    def pending_requests(self) -> int:
        return sum(event.count for event in self._events.values())

    @property
    def spool_path(self) -> Path | None:
        return self._spool_path

    def set_spool_path(self, path: str | os.PathLike[str]) -> bool:
        """Select a stable default namespace before journal restoration."""

        resolved = Path(path).expanduser()
        if self._restored:
            return resolved == self._spool_path
        self._spool_path = resolved
        return True

    def reserve(self) -> UsageReservation:
        """Reserve bounded queue capacity before the endpoint starts."""

        if (
            self._store_error is not None
            and time.monotonic() < self._store_error_until
        ):
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
        usage_policy_id: str | None = None,
        reservation: UsageReservation | None = None,
        occurred_at: datetime | None = None,
        attachment: dict[str, Any] | None = None,
    ) -> str:
        """Durably count one completed authenticated request."""

        if not isinstance(api_key_id, str) or not api_key_id:
            raise ValueError("api_key_id must be a non-empty string")
        try:
            parsed_api_key_id = uuid.UUID(api_key_id)
        except ValueError as exc:
            raise ValueError("api_key_id must be a UUID") from exc
        if parsed_api_key_id.int == 0:
            raise ValueError("api_key_id must be a non-zero UUID")
        api_key_id = str(parsed_api_key_id)
        if usage_policy_id is not None:
            try:
                parsed_policy_id = uuid.UUID(usage_policy_id)
            except ValueError as exc:
                raise ValueError("usage_policy_id must be a UUID") from exc
            if parsed_policy_id.int == 0:
                raise ValueError("usage_policy_id must be a non-zero UUID")
            usage_policy_id = str(parsed_policy_id)
        if isinstance(status_code, bool) or not isinstance(status_code, int):
            raise TypeError("status_code must be an integer")
        if status_code < 100 or status_code > 599:
            raise ValueError("status_code must be between 100 and 599")
        normalized_attachment = _normalize_attachment(attachment)
        if (
            reservation is not None
            and reservation.token not in self._reservations
        ):
            raise ValueError("usage queue reservation is invalid or already consumed")
        period_start = _hour_bucket(occurred_at)

        if reservation is None and (
            len(self._events) + len(self._reservations) >= self._max_items
        ):
            raise UsageQueueFull(self._max_items)

        merge_key = (api_key_id, usage_policy_id, status_code, period_start)
        merged_id = await self._try_merge(merge_key, normalized_attachment)
        if merged_id is not None:
            if reservation is not None:
                self._consume_reservation(reservation)
            self._pending_requests += 1
            self._schedule_flush()
            return merged_id

        event = _UsageEvent(
            idempotency_key=str(uuid.uuid4()),
            api_key_id=api_key_id,
            usage_policy_id=usage_policy_id,
            status_code=status_code,
            count=1,
            period_start=period_start,
            attachments=[normalized_attachment],
        )
        await self._persist_event(event)
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
        return event.idempotency_key

    async def _try_merge(
        self,
        merge_key: tuple[str, str | None, int, str],
        attachment: dict[str, Any],
    ) -> str | None:
        """Aggregate this request into an open event with the same identity.

        Merging keeps one counted event (and later one receipt and one API
        item) per key/policy/status/hour per flush window, instead of one row
        per request. Only never-delivered events are merged: once a payload
        has been attempted, its idempotency key pins its exact count.
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
            if self._store is not None:
                try:
                    result = await self._store.merge_claimed(
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
            elif self._spool_path is not None:
                # Commit in memory first and journal a synchronous snapshot of
                # the merged state, so concurrent merges into the same event
                # serialize correctly through the group-commit writer.
                event.count += 1
                if attachment:
                    event.attachments.append(attachment)
                snapshot = _UsageEvent(
                    idempotency_key=event.idempotency_key,
                    api_key_id=event.api_key_id,
                    usage_policy_id=event.usage_policy_id,
                    status_code=event.status_code,
                    count=event.count,
                    period_start=event.period_start,
                    attachments=list(event.attachments),
                )
                future = self._submit_spool_write([snapshot])
                try:
                    if future is not None:
                        await asyncio.shield(future)
                except asyncio.CancelledError:
                    # The detached writer will still resolve the write. Keep
                    # the merge latch held and reconcile the in-memory count
                    # with the journal's actual outcome, so a crash can never
                    # find the two disagreeing about this increment.
                    assert future is not None
                    event.merging += 1
                    future.add_done_callback(
                        self._merge_reconciler(event, attachment)
                    )
                    raise
                except _SpoolFencedError:
                    # Another process claimed this row during spool recovery;
                    # fall back to an independent event.
                    event.count -= 1
                    if attachment:
                        try:
                            event.attachments.remove(attachment)
                        except ValueError:
                            pass
                    self._open_events.pop(merge_key, None)
                    return None
                except BaseException:
                    event.count -= 1
                    if attachment:
                        try:
                            event.attachments.remove(attachment)
                        except ValueError:
                            pass
                    raise
                return event_id
            # The merging latch kept flush selection away; commit in memory.
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
                    event.count -= 1
                    if attachment:
                        try:
                            event.attachments.remove(attachment)
                        except ValueError:
                            pass
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
                return
            except UsageQueueFull:
                raise
            except UsageStoreError as exc:
                if self._spool_path is None:
                    logger.error(
                        "microauth: durable usage queue is unavailable (%s); "
                        "the event is retained in memory only",
                        exc,
                    )
                    return
                logger.warning(
                    "microauth: durable usage queue is unavailable (%s); "
                    "falling back to the local journal",
                    exc,
                )
        await self._persist_batched([event])

    async def _persist_batched(self, events: list[_UsageEvent]) -> None:
        """Group concurrent journal writes into one SQLite transaction."""

        future = self._submit_spool_write(events)
        if future is None:
            return
        # The shield keeps the shared future alive when this request is
        # cancelled: the detached writer still resolves it, so its outcome
        # remains observable and other waiters are unaffected.
        await asyncio.shield(future)

    def _submit_spool_write(
        self,
        events: list[_UsageEvent],
    ) -> asyncio.Future[None] | None:
        if self._spool_path is None or not events:
            return None
        if (
            self._store_error is not None
            and time.monotonic() < self._store_error_until
        ):
            # Fail fast during the cooldown; afterwards the next write probes
            # the store again instead of staying poisoned until restart.
            raise self._store_error
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._spool_writes.append((events, future))
        writer = self._spool_writer_task
        if writer is None or writer.done():
            # A detached task owns the write loop, so cancelling any waiting
            # request can never strand other requests' futures unresolved.
            self._spool_writer_task = asyncio.create_task(
                self._run_spool_writer(),
                name="microauth-usage-journal-writer",
            )
        return future

    async def _run_spool_writer(self) -> None:
        spool_path = self._spool_path
        assert spool_path is not None  # guarded by _submit_spool_write
        while self._spool_writes:
            batch = self._spool_writes
            self._spool_writes = []
            combined = [
                event
                for batch_events, _ in batch
                for event in batch_events
            ]
            try:
                fenced = await asyncio.to_thread(
                    _persist_spool,
                    spool_path,
                    combined,
                    self._max_items,
                    self._spool_owner,
                )
            except BaseException as exc:
                error: Exception
                if isinstance(exc, (UsageQueueFull, UsageStoreError)):
                    error = exc
                elif isinstance(exc, asyncio.CancelledError):
                    error = UsageStoreError("usage journal write was interrupted")
                else:
                    error = UsageStoreError(
                        f"could not persist usage journal: {exc}"
                    )
                if isinstance(error, UsageStoreError):
                    self._store_error = error
                    self._store_error_until = (
                        time.monotonic() + _STORE_ERROR_COOLDOWN_SECONDS
                    )
                for _, waiter in batch:
                    if not waiter.done():
                        waiter.set_exception(error)
                if isinstance(exc, asyncio.CancelledError):
                    raise
            else:
                self._store_error = None
                for batch_events, waiter in batch:
                    if waiter.done():
                        continue
                    if any(
                        event.idempotency_key in fenced
                        for event in batch_events
                    ):
                        # Not a store failure: the row belongs to another
                        # process now. The caller opens an independent event.
                        waiter.set_exception(
                            _SpoolFencedError(
                                "the journal row is owned by another process"
                            )
                        )
                    else:
                        waiter.set_result(None)

    async def start(self) -> None:
        async with self._start_lock:
            if not self._restored:
                await self._restore()
                self._restored = True
                await self._maybe_sweep()
            if self._task is None or self._task.done():
                self._task = asyncio.create_task(
                    self._loop(),
                    name="microauth-usage-reporter",
                )

    async def _loop(self) -> None:
        while True:
            deadline = self._flush_deadline
            if deadline is None:
                if self._store is None and self._spool_path is None:
                    await self._wake.wait()
                    self._wake.clear()
                    continue
                # Idle workers still sweep the shared queue (or the shared
                # spool file) so a dead worker's events are recovered without
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
            except Exception:
                logger.exception("microauth: usage flush failed; stable items remain queued")
                self._defer_pending(backoff=True)

    async def _maybe_sweep(self) -> None:
        """Claim due and abandoned events from the shared durable backend."""

        if self._store is None and self._spool_path is None:
            return
        now = time.monotonic()
        if self._last_sweep and now - self._last_sweep < self._interval:
            return
        self._last_sweep = now
        if self._store is not None:
            await self._sweep_store()
        elif self._restored:
            await self._sweep_spool()

    async def _sweep_store(self) -> None:
        assert self._store is not None
        capacity = self._max_items - len(self._events) - len(self._reservations)
        if capacity <= 0:
            return
        try:
            claimed = await self._store.claim_due(min(capacity, self._batch_size))
        except UsageStoreError as exc:
            logger.warning(
                "microauth: durable usage queue sweep failed (%s)",
                exc,
            )
            return
        recovered: list[_UsageEvent] = []
        for event_id, payload in claimed:
            if event_id in self._events:
                continue
            try:
                event = _event_from_store_payload(event_id, payload)
                recovered.append(event)
            except UsageStoreError as exc:
                logger.error(
                    "microauth: dead-lettering an invalid durable usage "
                    "event %s (%s)",
                    event_id,
                    exc,
                )
                try:
                    await self._store.dead_letter(event_id, str(exc), payload)
                except UsageStoreError:
                    logger.exception(
                        "microauth: invalid durable usage event could not "
                        "be dead-lettered"
                    )
        await self._absorb_recovered(recovered)

    async def _sweep_spool(self) -> None:
        """Reclaim abandoned rows other host processes left in the journal."""

        assert self._spool_path is not None
        try:
            events = await asyncio.to_thread(
                _restore_spool,
                self._spool_path,
                self._spool_owner,
                self._spool_grace,
            )
        except Exception as exc:  # noqa: BLE001 - storage boundary
            logger.warning(
                "microauth: usage journal sweep failed (%s)",
                exc,
            )
            return
        capacity = self._max_items - len(self._events) - len(self._reservations)
        recovered = [
            event
            for event in events
            if event.idempotency_key not in self._events
        ][: max(0, capacity)]
        await self._absorb_recovered(recovered)

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

        if only_if_due and not self.flush_is_due(event_id):
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

    async def flush(self) -> None:
        """Deliver all selected events while retaining only transient failures."""

        async with self._flush_lock:
            self._last_flush = time.monotonic()
            await self._expire_stale_events()
            selected: list[str] = []
            deferred: list[str] = []
            for event_id in self._pending:
                event = self._events.get(event_id)
                if event is None:
                    continue
                if event.merging:
                    # A durable count increment is mid-flight; deliver this
                    # event in the next cycle rather than freezing a payload
                    # halfway through a merge.
                    deferred.append(event_id)
                    continue
                # Selection permanently freezes the payload: the server's
                # receipt pins this idempotency key to this exact count.
                event.frozen = True
                if self._open_events.get(event.merge_key()) == event_id:
                    del self._open_events[event.merge_key()]
                selected.append(event_id)
            self._pending = deque(deferred)
            # Exact recompute of the additive request counter (deferred lists
            # are tiny: only events with a merge mid-flight).
            self._pending_requests = sum(
                event.count
                for event_id in deferred
                if (event := self._events.get(event_id)) is not None
            )
            if not selected:
                if deferred:
                    self._defer_pending()
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
                        remaining = [
                            event_id
                            for event_id in selected[offset:]
                            if event_id in self._events
                        ]
                        self._requeue_back(remaining)
                        raise
                    except BaseException:
                        remaining = [
                            event_id
                            for event_id in selected[offset:]
                            if event_id in self._events
                        ]
                        self._requeue_back(remaining)
                        raise
                    self._requeue_back(retry_ids)
                    if first_error is None and error is not None:
                        first_error = error
                if first_error is not None:
                    raise first_error
            finally:
                if self._pending:
                    self._defer_pending()
                    await self._extend_store_leases(list(self._pending))

    async def _expire_stale_events(self) -> None:
        """Dead-letter events the API would terminally reject by age."""

        cutoff = datetime.now(timezone.utc).timestamp() - _MAX_EVENT_AGE_SECONDS
        expired: list[str] = []
        for event_id, event in self._events.items():
            if event.merging:
                continue
            if event.period_ts == 0.0:
                # Parsed once per event lifetime, not once per flush.
                event.period_ts = datetime.fromisoformat(
                    event.period_start.replace("Z", "+00:00")
                ).timestamp()
            if event.period_ts < cutoff:
                expired.append(event_id)
        for event_id in expired:
            await self._dead_letter(
                event_id,
                "the event exceeded the API's 45-day usage age limit "
                "before it could be delivered",
            )

    async def _extend_store_leases(self, event_ids: list[str]) -> None:
        if self._store is None or not event_ids:
            return
        try:
            await self._store.extend_leases(event_ids)
        except UsageStoreError as exc:
            logger.warning(
                "microauth: durable usage delivery leases could not be "
                "renewed (%s)",
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
                    event_id,
                    f"HTTP {exc.status_code}: {exc.detail}",
                )
            return [], None

        plan = _parse_acknowledgements(response, event_ids)
        accepted_events = [
            self._events[event_id]
            for event_id in plan.accepted
            if event_id in self._events
        ]
        if accepted_events:
            accepted_ids = [event.idempotency_key for event in accepted_events]
            await self._notify(
                self._on_acknowledged,
                _event_attachments(accepted_events),
            )
            if self._store is not None:
                try:
                    await self._store.ack(accepted_ids)
                except UsageStoreError as exc:
                    # The server already recorded these idempotent items; a
                    # re-claimed copy will be acknowledged as a duplicate.
                    logger.warning(
                        "microauth: delivered usage could not be removed from "
                        "the durable queue (%s)",
                        exc,
                    )
            await self._delete_persisted(accepted_ids)
            self._remove_events(accepted_ids)

        for event_id, detail in plan.rejected.items():
            if event_id in self._events:
                await self._dead_letter(event_id, detail or "usage item rejected")

        retry = [event_id for event_id in plan.retry if event_id in self._events]
        return retry, plan.error

    async def _dead_letter(self, event_id: str, detail: str) -> None:
        event = self._events[event_id]
        await self._notify(self._on_rejected, list(event.attachments))
        if self._store is not None:
            try:
                await self._store.dead_letter(
                    event_id,
                    detail,
                    {
                        "item": event.as_payload(),
                        "attachments": event.attachments,
                    },
                )
            except UsageStoreError:
                logger.exception(
                    "microauth: terminal usage item could not be moved to "
                    "the durable dead-letter queue"
                )
        await self._persist_dead_letter(event, detail)
        self._remove_events([event_id])
        logger.error(
            "microauth: dead-lettered terminal usage item %s: %s",
            event_id,
            detail,
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
        writer = self._spool_writer_task
        if writer is not None and not writer.done():
            # The journal writer self-terminates once its queue drains; wait
            # for in-flight writes so the drain below sees their outcome.
            try:
                await writer
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.exception(
                    "microauth: usage journal writer stopped with an error"
                )
        self._spool_writer_task = None
        try:
            await asyncio.wait_for(
                self._drain(),
                timeout=self._shutdown_timeout,
            )
        except Exception as exc:
            await self._cancel_response_flush()
            if not self._reservations and await self._release_store_claims():
                return
            raise UsageDrainError(self.pending_items, str(exc)) from exc
        await self._cancel_response_flush()
        if self._events or self._reservations:
            if not self._reservations and await self._release_store_claims():
                return
            raise UsageDrainError(
                len(self._events) + len(self._reservations),
                "queue changed while shutdown was draining",
            )

    async def _release_store_claims(self) -> bool:
        """Hand undelivered events back to the shared backend at shutdown.

        Returns True when every locally queued event is durably owned by the
        shared queue (or shared journal) again, meaning shutdown lost nothing
        and need not raise.
        """

        if self._store is None and self._spool_path is None:
            return False
        event_ids = list(self._events)
        if not event_ids:
            return True
        if self._store is not None:
            try:
                released = await self._store.release(event_ids)
            except UsageStoreError:
                logger.exception(
                    "microauth: undelivered usage could not be handed back to "
                    "the durable queue during shutdown"
                )
                return False
            logger.warning(
                "microauth: %d undelivered usage item(s) were handed back to "
                "the durable queue for another worker (released %d lease(s))",
                len(event_ids),
                released,
            )
        else:
            assert self._spool_path is not None
            try:
                await asyncio.to_thread(
                    _disown_spool,
                    self._spool_path,
                    event_ids,
                    self._spool_owner,
                )
            except Exception:
                logger.exception(
                    "microauth: undelivered usage could not be handed back to "
                    "the shared journal during shutdown"
                )
                return False
            logger.warning(
                "microauth: %d undelivered usage item(s) were handed back to "
                "the shared journal for another process",
                len(event_ids),
            )
        self._remove_events(event_ids)
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
        if not self._restored:
            await self._restore()
            self._restored = True
        await self.flush()

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
                logger.exception(
                    "microauth: response-bound usage flush stopped with an error"
                )
        if self._response_flush_task is task:
            self._response_flush_task = None

    def _consume_reservation(self, reservation: UsageReservation) -> None:
        if reservation.token not in self._reservations:
            raise ValueError("usage queue reservation is invalid or already consumed")
        self._reservations.remove(reservation.token)

    def _remove_events(self, event_ids: Iterable[str]) -> None:
        for event_id in event_ids:
            event = self._events.pop(event_id, None)
            if (
                event is not None
                and self._open_events.get(event.merge_key()) == event_id
            ):
                del self._open_events[event.merge_key()]

    def _requeue_back(self, event_ids: Iterable[str]) -> None:
        requested = [
            event_id
            for event_id in event_ids
            if event_id in self._events
        ]
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
            self._flush_deadline = now
        elif self._flush_deadline is None:
            self._flush_deadline = now + self._interval
        self._wake.set()

    def flush_is_due(self, event_id: str | None = None) -> bool:
        """True when the 500-or-interval batching rule calls for a delivery.

        A delivery is due when a full batch of requests has accumulated or
        the interval has elapsed since the last flush while events are queued.
        """

        if event_id is not None and event_id not in self._events:
            return False
        if not self._events:
            return False
        if self._full_batch_pending():
            return True
        return time.monotonic() - self._last_flush >= self._interval

    def _defer_pending(self, *, backoff: bool = False) -> None:
        if not self._pending:
            self._flush_deadline = None
            return
        now = time.monotonic()
        if not backoff and self._full_batch_pending():
            # A full batch completed while a flush was in flight; deliver it
            # immediately instead of waiting out another interval. Failed
            # flushes pass backoff=True and always wait the interval.
            self._flush_deadline = now
        elif self._flush_deadline is None or self._flush_deadline <= now:
            self._flush_deadline = now + self._interval
        self._wake.set()

    async def _restore(self) -> None:
        if self._spool_path is None:
            return
        try:
            events = await asyncio.to_thread(
                _restore_spool,
                self._spool_path,
                self._spool_owner,
                self._spool_grace,
            )
        except UsageStoreError:
            raise
        except Exception as exc:
            raise UsageStoreError(f"could not restore {self._spool_path}: {exc}") from exc
        unseen = [
            event
            for event in events
            if event.idempotency_key not in self._events
        ]
        for event in unseen:
            # A restored event may already have been attempted before the
            # previous process died; its payload is pinned by the receipt.
            event.frozen = True
        if len(self._events) + len(unseen) > self._max_items:
            raise UsageQueueFull(self._max_items)
        if unseen:
            await self._notify(self._on_restored, _event_attachments(unseen))
        for event in unseen:
            self._events[event.idempotency_key] = event
            self._pending.append(event.idempotency_key)
            self._pending_requests += event.count
        if unseen:
            self._schedule_flush()

    async def _delete_persisted(self, event_ids: list[str]) -> None:
        if self._spool_path is None or not event_ids:
            return
        try:
            await asyncio.to_thread(
                _delete_spool,
                self._spool_path,
                event_ids,
                self._spool_owner,
            )
        except Exception as exc:
            raise UsageStoreError(f"could not update usage journal: {exc}") from exc

    async def _persist_dead_letter(self, event: _UsageEvent, detail: str) -> None:
        if self._spool_path is None:
            return
        try:
            await asyncio.to_thread(
                _dead_letter_spool,
                self._spool_path,
                event,
                detail,
                self._spool_owner,
            )
        except Exception as exc:
            raise UsageStoreError(f"could not update usage dead letter: {exc}") from exc

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
            error=UsageAcknowledgementError(
                "usage response must contain a results array"
            ),
        )

    expected = set(expected_ids)
    seen: set[str] = set()
    accepted: set[str] = set()
    rejected: dict[str, str] = {}
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
            detail = (
                f"usage result at index {index} has an unknown idempotency_key"
            )
            continue
        if event_id in seen:
            malformed = True
            detail = f"usage result repeats idempotency_key {event_id}"
            invalid_ids.add(event_id)
            accepted.discard(event_id)
            rejected.pop(event_id, None)
            continue
        seen.add(event_id)
        if status in _SUCCESS_STATUSES:
            accepted.add(event_id)
        elif status == "rejected":
            raw_detail = raw.get("detail", "")
            rejected[event_id] = raw_detail if isinstance(raw_detail, str) else ""
        else:
            malformed = True
            detail = f"usage item {event_id} has unsupported status {status!r}"
            invalid_ids.add(event_id)

    accepted.difference_update(invalid_ids)
    for event_id in invalid_ids:
        rejected.pop(event_id, None)
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
    return _Acknowledgements(
        accepted=[
            event_id for event_id in expected_ids if event_id in accepted
        ],
        rejected={
            event_id: rejected[event_id]
            for event_id in expected_ids
            if event_id in rejected
        },
        retry=retry,
        error=error,
    )


def _normalize_attachment(
    attachment: dict[str, Any] | None,
) -> dict[str, Any]:
    if attachment is None:
        return {}
    if not isinstance(attachment, dict):
        raise TypeError("usage attachment must be an object")
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
    return [
        attachment
        for event in events
        for attachment in event.attachments
        if attachment
    ]


def _connect_spool(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=5.0)
    try:
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("BEGIN IMMEDIATE")
        _ensure_schema(connection)
        connection.commit()
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except Exception:
        connection.rollback()
        connection.close()
        raise
    return connection


def _ensure_schema(connection: sqlite3.Connection) -> None:
    table = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='usage_events'"
    ).fetchone()
    if table is None:
        _create_usage_table(connection)
    else:
        columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(usage_events)")
        }
        if "api_key_id" not in columns and {"key_id", "requests"} <= columns:
            connection.execute(
                "ALTER TABLE usage_events RENAME TO usage_events_legacy_v1"
            )
            _create_usage_table(connection)
            connection.execute(
                """
                INSERT INTO usage_events
                    (idempotency_key, api_key_id, usage_policy_id,
                     status_code, count,
                     period_start, attachments_json)
                SELECT idempotency_key, key_id, NULL, status_code, requests,
                       period_start, '[]'
                FROM usage_events_legacy_v1
                """
            )
            connection.execute("DROP TABLE usage_events_legacy_v1")
        else:
            if "usage_policy_id" not in columns:
                connection.execute(
                    "ALTER TABLE usage_events ADD COLUMN usage_policy_id TEXT"
                )
            if "attachments_json" not in columns:
                connection.execute(
                    "ALTER TABLE usage_events "
                    "ADD COLUMN attachments_json TEXT NOT NULL DEFAULT '[]'"
                )
            if "owner" not in columns:
                connection.execute(
                    "ALTER TABLE usage_events "
                    "ADD COLUMN owner TEXT NOT NULL DEFAULT ''"
                )
            if "claimed_at" not in columns:
                connection.execute(
                    "ALTER TABLE usage_events "
                    "ADD COLUMN claimed_at REAL NOT NULL DEFAULT 0"
                )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS usage_dead_letters (
            idempotency_key TEXT PRIMARY KEY,
            payload_json TEXT NOT NULL,
            detail TEXT NOT NULL,
            rejected_at TEXT NOT NULL
        )
        """
    )


def _create_usage_table(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE usage_events (
            idempotency_key TEXT PRIMARY KEY,
            api_key_id TEXT NOT NULL,
            usage_policy_id TEXT,
            status_code INTEGER NOT NULL,
            count INTEGER NOT NULL,
            period_start TEXT NOT NULL,
            attachments_json TEXT NOT NULL,
            owner TEXT NOT NULL DEFAULT '',
            claimed_at REAL NOT NULL DEFAULT 0
        )
        """
    )


def _restore_spool(
    path: Path,
    owner: str,
    grace_seconds: float,
) -> list[_UsageEvent]:
    """Claim unowned or abandoned rows for this process and return them.

    The default spool file is shared by every worker on the host. Rows whose
    owner has not written for ``grace_seconds`` are considered abandoned and
    are claimable, exactly like an expired Redis lease; a live worker's rows
    are never stolen out from under it.
    """

    connection = _connect_spool(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        now = time.time()
        connection.execute(
            """
            UPDATE usage_events SET owner = ?, claimed_at = ?
            WHERE owner = '' OR owner = ? OR claimed_at < ?
            """,
            (owner, now, owner, now - grace_seconds),
        )
        rows = connection.execute(
            """
            SELECT idempotency_key, api_key_id, usage_policy_id,
                   status_code, count,
                   period_start, attachments_json
            FROM usage_events
            WHERE owner = ?
            ORDER BY rowid
            """,
            (owner,),
        ).fetchall()
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return [_event_from_row(row) for row in rows]


def _persist_spool(
    path: Path,
    events: list[_UsageEvent],
    max_items: int,
    owner: str,
) -> set[str]:
    """Insert or merge owned rows; return the ids fenced off by another owner.

    A row claimed by another process (spool recovery during a rolling
    restart) is never modified: its id is reported back so the caller can
    open an independent event instead of mutating a payload someone else may
    already have delivered.
    """

    connection = _connect_spool(path)
    fenced: set[str] = set()
    try:
        connection.execute("BEGIN IMMEDIATE")
        existing_count = int(
            connection.execute("SELECT COUNT(*) FROM usage_events").fetchone()[0]
        )
        event_ids = [event.idempotency_key for event in events]
        existing_ids: set[str] = set()
        for offset in range(0, len(event_ids), 900):
            id_chunk = event_ids[offset : offset + 900]
            placeholders = ",".join("?" for _ in id_chunk)
            for row in connection.execute(
                f"SELECT idempotency_key, owner FROM usage_events "
                f"WHERE idempotency_key IN ({placeholders})",
                id_chunk,
            ):
                existing_ids.add(str(row[0]))
                if str(row[1]) not in ("", owner):
                    fenced.add(str(row[0]))
        if existing_count + len(events) - len(existing_ids) > max_items:
            raise UsageQueueFull(max_items)
        now = time.time()
        for event in events:
            if event.idempotency_key in fenced:
                continue
            connection.execute(
                """
                INSERT INTO usage_events
                    (idempotency_key, api_key_id, usage_policy_id,
                     status_code, count,
                     period_start, attachments_json, owner, claimed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(idempotency_key) DO UPDATE SET
                    count = excluded.count,
                    attachments_json = excluded.attachments_json,
                    owner = excluded.owner,
                    claimed_at = excluded.claimed_at
                WHERE usage_events.api_key_id = excluded.api_key_id
                  AND usage_events.usage_policy_id IS excluded.usage_policy_id
                  AND usage_events.status_code = excluded.status_code
                  AND usage_events.period_start = excluded.period_start
                  AND excluded.count >= usage_events.count
                  AND usage_events.owner IN ('', excluded.owner)
                """,
                (*_event_row(event), owner, now),
            )
            row = connection.execute(
                """
                SELECT idempotency_key, api_key_id, usage_policy_id,
                       status_code, count,
                       period_start, attachments_json
                FROM usage_events WHERE idempotency_key = ?
                """,
                (event.idempotency_key,),
            ).fetchone()
            if _event_from_row(row) != event:
                raise UsageStoreError(
                    f"journal payload mismatch for {event.idempotency_key}"
                )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return fenced


def _delete_spool(path: Path, event_ids: list[str], owner: str) -> None:
    connection = _connect_spool(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.executemany(
            "DELETE FROM usage_events WHERE idempotency_key = ? AND owner IN ('', ?)",
            [(event_id, owner) for event_id in event_ids],
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _disown_spool(path: Path, event_ids: list[str], owner: str) -> None:
    """Hand this process's undelivered rows back for immediate reclaim."""

    connection = _connect_spool(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.executemany(
            """
            UPDATE usage_events SET owner = '', claimed_at = 0
            WHERE idempotency_key = ? AND owner = ?
            """,
            [(event_id, owner) for event_id in event_ids],
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _dead_letter_spool(
    path: Path,
    event: _UsageEvent,
    detail: str,
    owner: str,
) -> None:
    connection = _connect_spool(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            INSERT INTO usage_dead_letters
                (idempotency_key, payload_json, detail, rejected_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(idempotency_key) DO UPDATE SET
                detail = excluded.detail,
                rejected_at = excluded.rejected_at
            """,
            (
                event.idempotency_key,
                json.dumps(
                    {
                        "item": event.as_payload(),
                        "attachments": event.attachments,
                    },
                    allow_nan=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                detail[:2000],
                datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            ),
        )
        connection.execute(
            "DELETE FROM usage_events WHERE idempotency_key = ? AND owner IN ('', ?)",
            (event.idempotency_key, owner),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _event_from_store_payload(
    event_id: str,
    payload: dict[str, Any],
) -> _UsageEvent:
    item = payload.get("item")
    attachments = payload.get("attachments")
    if not isinstance(item, dict) or not isinstance(attachments, list):
        raise UsageStoreError(
            "the durable usage queue holds a malformed event envelope"
        )
    if item.get("idempotency_key") != event_id:
        raise UsageStoreError(
            "the durable usage queue holds a mismatched idempotency key"
        )
    try:
        attachments_json = json.dumps(
            attachments,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise UsageStoreError(
            "the durable usage queue holds invalid attachment metadata"
        ) from exc
    return _event_from_row(
        (
            event_id,
            item.get("api_key_id"),
            item.get("usage_policy_id"),
            item.get("status_code"),
            item.get("count"),
            item.get("period_start"),
            attachments_json,
        )
    )


def _event_row(event: _UsageEvent) -> tuple[Any, ...]:
    return (
        event.idempotency_key,
        event.api_key_id,
        event.usage_policy_id,
        event.status_code,
        event.count,
        event.period_start,
        json.dumps(
            event.attachments,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
    )


def _event_from_row(row: Any) -> _UsageEvent:
    if not isinstance(row, (tuple, list)) or len(row) != 7:
        raise UsageStoreError("usage journal contains a malformed row")
    (
        event_id,
        api_key_id,
        usage_policy_id,
        status_code,
        count,
        period_start,
        attachments_json,
    ) = row
    if not isinstance(event_id, str) or not event_id:
        raise UsageStoreError("usage journal contains an invalid idempotency_key")
    if not isinstance(api_key_id, str) or not api_key_id:
        raise UsageStoreError("usage journal contains an invalid api_key_id")
    if usage_policy_id is not None:
        if not isinstance(usage_policy_id, str):
            raise UsageStoreError(
                "usage journal contains an invalid usage_policy_id"
            )
        try:
            parsed_policy_id = uuid.UUID(usage_policy_id)
        except ValueError as exc:
            raise UsageStoreError(
                "usage journal contains an invalid usage_policy_id"
            ) from exc
        if parsed_policy_id.int == 0:
            raise UsageStoreError(
                "usage journal contains an invalid usage_policy_id"
            )
        usage_policy_id = str(parsed_policy_id)
    if isinstance(status_code, bool) or not isinstance(status_code, int):
        raise UsageStoreError("usage journal contains an invalid status_code")
    if status_code < 100 or status_code > 599:
        raise UsageStoreError("usage journal status_code is outside 100..599")
    if isinstance(count, bool) or not isinstance(count, int):
        raise UsageStoreError("usage journal contains an invalid count")
    if count < 1 or count > MAX_USAGE_COUNT:
        raise UsageStoreError("usage journal count is outside 1..10000000")
    if not isinstance(period_start, str):
        raise UsageStoreError("usage journal contains an invalid period_start")
    try:
        parsed = datetime.fromisoformat(period_start.replace("Z", "+00:00"))
    except ValueError as exc:
        raise UsageStoreError("usage journal contains an invalid period_start") from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
        or parsed.utcoffset() != timezone.utc.utcoffset(parsed)
        or parsed.minute
        or parsed.second
        or parsed.microsecond
    ):
        raise UsageStoreError("usage journal period_start must be an exact UTC hour")
    if not isinstance(attachments_json, str):
        raise UsageStoreError("usage journal contains invalid attachment metadata")
    try:
        attachments_raw = json.loads(attachments_json)
    except ValueError as exc:
        raise UsageStoreError("usage journal contains invalid attachment JSON") from exc
    if not isinstance(attachments_raw, list) or len(attachments_raw) > count:
        raise UsageStoreError("usage journal contains invalid request attachments")
    try:
        attachments = [
            _normalize_attachment(attachment)
            for attachment in attachments_raw
        ]
    except (TypeError, ValueError) as exc:
        raise UsageStoreError(
            "usage journal contains invalid request attachment metadata"
        ) from exc
    return _UsageEvent(
        idempotency_key=event_id,
        api_key_id=api_key_id,
        usage_policy_id=usage_policy_id,
        status_code=status_code,
        count=count,
        period_start=period_start,
        attachments=attachments,
    )
