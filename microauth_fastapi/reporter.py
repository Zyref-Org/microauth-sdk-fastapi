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

logger = logging.getLogger("microauth")

_DEFAULT_MAX_ITEMS = 10_000
_DEFAULT_BATCH_SIZE = 1000
_SUCCESS_STATUSES = frozenset({"accepted", "duplicate"})
_TERMINAL_ITEM_HTTP_STATUSES = frozenset({400, 402, 409, 422})

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

        self._events: dict[str, _UsageEvent] = {}
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

        if self._store_error is not None:
            raise self._store_error
        if len(self._events) + len(self._reservations) >= self._max_items:
            raise UsageQueueFull(self._max_items)
        token = str(uuid.uuid4())
        self._reservations.add(token)
        return UsageReservation(token)

    def release(self, reservation: UsageReservation) -> None:
        self._reservations.discard(reservation.token)

    def record(
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

        event = _UsageEvent(
            idempotency_key=str(uuid.uuid4()),
            api_key_id=api_key_id,
            usage_policy_id=usage_policy_id,
            status_code=status_code,
            count=1,
            period_start=period_start,
            attachments=[normalized_attachment],
        )
        self._persist_now([event])
        if reservation is not None:
            self._consume_reservation(reservation)
        self._events[event.idempotency_key] = event
        self._pending.append(event.idempotency_key)
        self._schedule_flush()
        return event.idempotency_key

    async def start(self) -> None:
        async with self._start_lock:
            if not self._restored:
                await self._restore()
                self._restored = True
            if self._task is None or self._task.done():
                self._task = asyncio.create_task(
                    self._loop(),
                    name="microauth-usage-reporter",
                )

    async def _loop(self) -> None:
        while True:
            deadline = self._flush_deadline
            if deadline is None:
                await self._wake.wait()
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
            try:
                await self.flush()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("microauth: usage flush failed; stable items remain queued")
                self._defer_pending()

    async def flush_on_response(self, event_id: str | None = None) -> None:
        """Deliver a response's event, coalescing concurrent callers."""

        targets = {event_id} if event_id is not None else set(self._events)
        while any(target in self._events for target in targets):
            task = self._response_flush_task
            if task is None or task.done():
                task = asyncio.create_task(
                    self.flush(),
                    name="microauth-usage-response-flush",
                )
                self._response_flush_task = task
            try:
                await asyncio.shield(task)
            finally:
                if self._response_flush_task is task and task.done():
                    self._response_flush_task = None

    async def flush(self) -> None:
        """Deliver all selected events while retaining only transient failures."""

        async with self._flush_lock:
            selected = list(self._pending)
            if not selected:
                self._flush_deadline = None
                return
            self._pending.clear()
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
            await self._notify(
                self._on_acknowledged,
                _event_attachments(accepted_events),
            )
            await self._delete_persisted(
                [event.idempotency_key for event in accepted_events]
            )
            self._remove_events(
                [event.idempotency_key for event in accepted_events]
            )

        for event_id, detail in plan.rejected.items():
            if event_id in self._events:
                await self._dead_letter(event_id, detail or "usage item rejected")

        retry = [event_id for event_id in plan.retry if event_id in self._events]
        return retry, plan.error

    async def _dead_letter(self, event_id: str, detail: str) -> None:
        event = self._events[event_id]
        await self._notify(self._on_rejected, list(event.attachments))
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
        try:
            await asyncio.wait_for(
                self._drain(),
                timeout=self._shutdown_timeout,
            )
        except Exception as exc:
            await self._cancel_response_flush()
            raise UsageDrainError(self.pending_items, str(exc)) from exc
        await self._cancel_response_flush()
        if self._events or self._reservations:
            raise UsageDrainError(
                len(self._events) + len(self._reservations),
                "queue changed while shutdown was draining",
            )

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
            self._events.pop(event_id, None)

    def _requeue_back(self, event_ids: Iterable[str]) -> None:
        requested = [
            event_id
            for event_id in event_ids
            if event_id in self._events
        ]
        if not requested:
            return
        existing = set(self._pending)
        self._pending.extend(
            event_id for event_id in requested if event_id not in existing
        )

    def _schedule_flush(self) -> None:
        if self._flush_deadline is None:
            self._flush_deadline = time.monotonic() + self._interval
        self._wake.set()

    def _defer_pending(self) -> None:
        if not self._pending:
            self._flush_deadline = None
            return
        now = time.monotonic()
        if self._flush_deadline is None or self._flush_deadline <= now:
            self._flush_deadline = now + self._interval
        self._wake.set()

    async def _restore(self) -> None:
        if self._spool_path is None:
            return
        try:
            events = await asyncio.to_thread(_restore_spool, self._spool_path)
        except UsageStoreError:
            raise
        except Exception as exc:
            raise UsageStoreError(f"could not restore {self._spool_path}: {exc}") from exc
        unseen = [
            event
            for event in events
            if event.idempotency_key not in self._events
        ]
        if len(self._events) + len(unseen) > self._max_items:
            raise UsageQueueFull(self._max_items)
        if unseen:
            await self._notify(self._on_restored, _event_attachments(unseen))
        for event in unseen:
            self._events[event.idempotency_key] = event
            self._pending.append(event.idempotency_key)
        if unseen:
            self._schedule_flush()

    def _persist_now(self, events: list[_UsageEvent]) -> None:
        if self._spool_path is None or not events:
            return
        try:
            _persist_spool(self._spool_path, events, self._max_items)
        except UsageQueueFull:
            raise
        except UsageStoreError as exc:
            self._store_error = exc
            raise
        except Exception as exc:
            error = UsageStoreError(f"could not persist usage journal: {exc}")
            self._store_error = error
            raise error from exc

    async def _delete_persisted(self, event_ids: list[str]) -> None:
        if self._spool_path is None or not event_ids:
            return
        try:
            await asyncio.to_thread(_delete_spool, self._spool_path, event_ids)
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
            attachments_json TEXT NOT NULL
        )
        """
    )


def _restore_spool(path: Path) -> list[_UsageEvent]:
    connection = _connect_spool(path)
    try:
        rows = connection.execute(
            """
            SELECT idempotency_key, api_key_id, usage_policy_id,
                   status_code, count,
                   period_start, attachments_json
            FROM usage_events
            ORDER BY rowid
            """
        ).fetchall()
    finally:
        connection.close()
    return [_event_from_row(row) for row in rows]


def _persist_spool(
    path: Path,
    events: list[_UsageEvent],
    max_items: int,
) -> None:
    connection = _connect_spool(path)
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
            existing_ids.update(
                str(row[0])
                for row in connection.execute(
                    f"SELECT idempotency_key FROM usage_events "
                    f"WHERE idempotency_key IN ({placeholders})",
                    id_chunk,
                )
            )
        if existing_count + len(events) - len(existing_ids) > max_items:
            raise UsageQueueFull(max_items)
        for event in events:
            connection.execute(
                """
                INSERT INTO usage_events
                    (idempotency_key, api_key_id, usage_policy_id,
                     status_code, count,
                     period_start, attachments_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(idempotency_key) DO UPDATE SET
                    count = excluded.count,
                    attachments_json = excluded.attachments_json
                WHERE usage_events.api_key_id = excluded.api_key_id
                  AND usage_events.usage_policy_id IS excluded.usage_policy_id
                  AND usage_events.status_code = excluded.status_code
                  AND usage_events.period_start = excluded.period_start
                  AND excluded.count >= usage_events.count
                """,
                _event_row(event),
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


def _delete_spool(path: Path, event_ids: list[str]) -> None:
    connection = _connect_spool(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.executemany(
            "DELETE FROM usage_events WHERE idempotency_key = ?",
            [(event_id,) for event_id in event_ids],
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _dead_letter_spool(path: Path, event: _UsageEvent, detail: str) -> None:
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
            "DELETE FROM usage_events WHERE idempotency_key = ?",
            (event.idempotency_key,),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


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
