"""MicroAuth for FastAPI.

Quickstart::

    from fastapi import FastAPI, Security
    from microauth_fastapi import MicroAuth, Customer

    app = FastAPI()
    auth = MicroAuth(app)  # tenant secret from MICROAUTH_SECRET_KEY

    @app.get("/forecast")
    async def forecast(customer: Customer = Security(auth)):
        return {"customer": customer.id}

What you get:

* API key auth on the route, advertised in OpenAPI/Swagger automatically.
* Suspension, prepaid-balance, monthly-quota and RPS enforcement, all from
  a locally cached snapshot — the hot path never calls MicroAuth.
* Complete usage reporting: every completed authenticated request is reported
  by final status, while only configured billable statuses consume credit.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import logging
import math
import os
import tempfile
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import Request, Security
from fastapi.security import APIKeyHeader

from .client import APIClient
from .exceptions import (
    AuthUnavailable,
    CustomerSuspended,
    InvalidAPIKey,
    LimitBackendUnavailable,
    MicroAuthAuthorizationError,
    MicroAuthConfigurationError,
    MicroAuthError,
    MicroAuthResponseError,
    PaymentRequired,
    PlatformAllowanceExceeded,
    QuotaExceeded,
    RateLimited,
    SnapshotCacheError,
    SnapshotValidationError,
    UsageQueueFull,
)
from .limiter import (
    DENIED_BALANCE,
    DENIED_PLATFORM,
    DENIED_QUOTA,
    Limiter,
    MemoryLimiter,
    RedisLimiter,
    ReservationDenied,
)
from .models import (
    MAX_SAFE_INTEGER,
    Customer,
    CustomerState,
    Effective,
    KeyRecord,
    LimitReservation,
    PlatformMonthlyAllowance,
    Snapshot,
)
from .reporter import UsageReporter, UsageReservation
from .snapshot_cache import CachedSnapshot, RedisSnapshotCache, SnapshotLease
from .usage_store import RedisUsageStore

logger = logging.getLogger("microauth")

_STATE_ATTR = "microauth_principal"
_FUTURE_SKEW_SECONDS = 60.0


def _build_signature(scheme: APIKeyHeader) -> inspect.Signature:
    """A per-instance ``__call__`` signature so FastAPI wires the request and
    the API key header (and documents the security scheme in OpenAPI)."""
    return inspect.Signature(
        [
            inspect.Parameter("request", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=Request),
            inspect.Parameter(
                "api_key",
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=str | None,
                default=Security(scheme),
            ),
        ],
        return_annotation=Customer,
    )


class MicroAuth:
    """FastAPI dependency + background machinery for one MicroAuth tenant.

    Create exactly one instance per application and reuse it on every route
    (``Security(auth)``). All settings have production-ready defaults; the
    only required input is the tenant secret key.

    Args:
        app: Your FastAPI app. Required before serving requests because the
            installed middleware observes exact final status codes and flushes
            pending usage on shutdown. You may instead call ``install(app)``
            before the first request.
        secret_key: Tenant secret (``mas_...``). Defaults to the
            ``MICROAUTH_SECRET_KEY`` environment variable.
        base_url: MicroAuth API base. Default ``https://api.microauth.com``
            (override with ``MICROAUTH_BASE_URL``).
        header_name: Header your customers send their API key in.
            Default ``X-API-Key``.
        redis_url: Optional Redis URL (``redis://...``). When set, RPS,
            customer quota, potential spend, and platform limits are enforced
            across all workers, snapshots are shared to prevent cold-start
            fan-out, and completed usage is journaled to a durable shared
            queue that survives instance replacement (delivery leases are
            recovered by any worker). Without it, each worker enforces
            independently and journals to local SQLite.
        shared_snapshot_cache: Share snapshots and coordinate refreshes through
            Redis when Redis is configured. Default True.
        sync_interval: Seconds between snapshot refreshes. Default 30.
        report_interval: Usage reports are batched: a flush happens when 500
            events accumulate or this many seconds pass since the last flush,
            whichever comes first. Default 5.
        flush_on_response: On serverless runtimes, evaluate the batching rule
            after the final response frame while the invocation remains
            active, so a frozen timer cannot strand a due batch. Defaults to
            True on Vercel/AWS Lambda and False elsewhere.
        max_snapshot_age: If the snapshot can't be refreshed for this many
            seconds, ``fail_open=False`` returns 503. Default 300.
        max_stale_snapshot_age: Absolute stale-data ceiling, including when
            ``fail_open=True``. Defaults to three times ``max_snapshot_age``.
        fail_open: With a stale snapshot: ``True`` (default) keeps serving
            known keys only until ``max_stale_snapshot_age``.
        enforce_balance: Reject with 402 when a paying customer's prepaid
            balance is exhausted. Default True.
        enforce_quota: Reject with 429 when the customer's monthly quota is
            used up. Default True.
        enforce_rps: Apply per-customer RPS limits. Default True.
        enforce_platform_allowance: Enforce the authoritative platform-wide
            monthly hard cap. Redis makes this exact across workers.
        verify_negative_ttl: Seconds an unknown key is cached as invalid
            (protects MicroAuth from invalid-key floods). Default 30.
        timeout: HTTP timeout for MicroAuth API calls. Default 5s.
        usage_spool_path: SQLite spool used to preserve in-flight item IDs
            across process restarts. Defaults to a tenant-specific temp file.
        persistence_namespace: Stable tenant identifier for Redis and the
            default journal path. Use this when the snapshot does not expose
            ``tenant_id`` and tenant secrets may rotate.
        persist_usage: Disable only for ephemeral/test deployments that
            explicitly accept losing in-flight usage on process exit.
        max_usage_queue: Maximum number of frozen/queued usage items.
        shutdown_timeout: Seconds allowed for the final usage drain.
        http_client: Optional externally owned ``httpx.AsyncClient``.
        redis_client: Optional externally owned ``redis.asyncio`` client.
    """

    def __init__(
        self,
        app: Any = None,
        secret_key: str | None = None,
        *,
        base_url: str | None = None,
        header_name: str = "X-API-Key",
        redis_url: str | None = None,
        shared_snapshot_cache: bool = True,
        sync_interval: float = 30.0,
        report_interval: float = 5.0,
        flush_on_response: bool | None = None,
        max_snapshot_age: float = 300.0,
        max_stale_snapshot_age: float | None = None,
        fail_open: bool = True,
        enforce_balance: bool = True,
        enforce_quota: bool = True,
        enforce_rps: bool = True,
        enforce_platform_allowance: bool = True,
        verify_negative_ttl: float = 30.0,
        timeout: float = 5.0,
        usage_spool_path: str | os.PathLike[str] | None = None,
        persistence_namespace: str | None = None,
        persist_usage: bool = True,
        max_usage_queue: int = 10_000,
        shutdown_timeout: float = 10.0,
        http_client: httpx.AsyncClient | None = None,
        redis_client: Any | None = None,
    ) -> None:
        secret_key = secret_key or os.environ.get("MICROAUTH_SECRET_KEY", "")
        if not secret_key.startswith("mas_"):
            raise MicroAuthConfigurationError(
                "MicroAuth tenant secret key is missing or malformed. Pass "
                "secret_key='mas_...' or set the MICROAUTH_SECRET_KEY env var."
            )
        _validate_positive("sync_interval", sync_interval)
        _validate_positive("report_interval", report_interval)
        _validate_positive("max_snapshot_age", max_snapshot_age)
        _validate_positive("verify_negative_ttl", verify_negative_ttl)
        _validate_positive("timeout", timeout)
        _validate_positive("shutdown_timeout", shutdown_timeout)
        if flush_on_response is not None and not isinstance(
            flush_on_response,
            bool,
        ):
            raise MicroAuthConfigurationError(
                "flush_on_response must be a boolean or None"
            )
        if isinstance(max_usage_queue, bool) or not isinstance(max_usage_queue, int):
            raise MicroAuthConfigurationError("max_usage_queue must be an integer")
        if max_usage_queue < 1 or max_usage_queue > MAX_SAFE_INTEGER:
            raise MicroAuthConfigurationError(
                f"max_usage_queue must be between 1 and {MAX_SAFE_INTEGER}"
            )
        if max_stale_snapshot_age is None:
            max_stale_snapshot_age = max_snapshot_age * 3.0
        _validate_positive("max_stale_snapshot_age", max_stale_snapshot_age)
        if max_stale_snapshot_age < max_snapshot_age:
            raise MicroAuthConfigurationError(
                "max_stale_snapshot_age must be at least max_snapshot_age"
            )
        base_url = base_url or os.environ.get("MICROAUTH_BASE_URL", "https://api.microauth.com")
        redis_url = redis_url or os.environ.get("MICROAUTH_REDIS_URL") or None
        secret_scope = hashlib.sha256(secret_key.encode("utf-8")).hexdigest()[:24]
        if persistence_namespace is not None:
            if not isinstance(persistence_namespace, str) or not persistence_namespace.strip():
                raise MicroAuthConfigurationError(
                    "persistence_namespace must be a non-empty string"
                )
            tenant_scope = _stable_scope(base_url, persistence_namespace)
        else:
            tenant_scope = secret_scope
        if persist_usage:
            configured_spool = usage_spool_path or os.environ.get(
                "MICROAUTH_USAGE_SPOOL_PATH"
            )
            if configured_spool is None:
                configured_spool = (
                    Path(tempfile.gettempdir())
                    / f"microauth-fastapi-{tenant_scope}.sqlite3"
                )
            resolved_spool: str | os.PathLike[str] | None = configured_spool
        else:
            resolved_spool = None

        self.header_name = header_name
        self._client = APIClient(
            base_url,
            secret_key,
            timeout,
            http_client=http_client,
        )
        self._limiter: Limiter = (
            RedisLimiter(redis_url, redis_client=redis_client)
            if redis_url or redis_client is not None
            else MemoryLimiter()
        )
        if not isinstance(shared_snapshot_cache, bool):
            raise MicroAuthConfigurationError(
                "shared_snapshot_cache must be a boolean"
            )
        usage_store = (
            RedisUsageStore(
                self._limiter.redis_client,
                tenant_scope,
                max_items=max_usage_queue,
                lease_ms=max(60_000, math.ceil(report_interval * 4_000)),
            )
            if persist_usage and isinstance(self._limiter, RedisLimiter)
            else None
        )
        self._reporter = UsageReporter(
            self._client,
            report_interval,
            max_items=max_usage_queue,
            shutdown_timeout=shutdown_timeout,
            spool_path=resolved_spool,
            store=usage_store,
            on_acknowledged=self._limiter.acknowledge,
            on_rejected=self._limiter.reject,
            on_restored=self._restore_limit_attachments,
            on_authorization_failure=self._usage_authorization_failed,
        )
        self._tenant_scope = tenant_scope
        self._base_url = base_url
        self._persistence_namespace = persistence_namespace
        self._default_spool = (
            persist_usage
            and usage_spool_path is None
            and os.environ.get("MICROAUTH_USAGE_SPOOL_PATH") is None
        )
        snapshot_refresh_timeout = max(45.0, timeout * 4.0)
        # The snapshot cache scope is credential-bound (unlike the limiter
        # scope): a revoked secret must never inherit snapshots that a
        # different, still-valid credential refreshed and validated.
        self._snapshot_cache = (
            RedisSnapshotCache(
                self._limiter.redis_client,
                f"{tenant_scope}\0{secret_scope}",
                ttl=max_stale_snapshot_age + sync_interval,
                lock_timeout=snapshot_refresh_timeout,
            )
            if shared_snapshot_cache and isinstance(self._limiter, RedisLimiter)
            else None
        )
        self._snapshot_cache_wait = snapshot_refresh_timeout
        self._snapshot = Snapshot()
        self._sync_interval = sync_interval
        self._max_snapshot_age = max_snapshot_age
        self._max_stale_snapshot_age = max_stale_snapshot_age
        self._fail_open = fail_open
        self._enforce_balance = enforce_balance
        self._enforce_quota = enforce_quota
        self._enforce_rps = enforce_rps
        self._enforce_platform_allowance = enforce_platform_allowance
        self._negative_ttl = verify_negative_ttl
        self._flush_on_response = (
            _is_serverless_environment()
            if flush_on_response is None
            else flush_on_response
        )

        self._sync_task: asyncio.Task[None] | None = None
        self._started = False
        self._installed = False
        self._start_lock: asyncio.Lock | None = None
        self._refresh_lock: asyncio.Lock | None = None
        self._policy_refresh_blocked_until = 0.0
        self._stale_recovery_blocked_until = 0.0
        self._request_refresh_task: asyncio.Task[None] | None = None
        self._request_refresh_blocked_until = 0.0
        self._negative: dict[str, float] = {}  # key hash -> monotonic expiry
        self._verifying: dict[str, asyncio.Future[KeyRecord | None]] = {}
        self._authorization_invalid = False

        scheme = APIKeyHeader(
            name=header_name,
            auto_error=False,
            scheme_name="APIKey",
            description="Your API key, issued from the developer portal.",
        )
        self.__signature__ = _build_signature(scheme)

        # `auth.optional` — same checks, but anonymous requests pass with None.
        self.optional = _OptionalAuth(self, scheme)

        if app is not None:
            self.install(app)

    # ------------------------------------------------------------------ setup

    def install(self, app: Any) -> None:
        """Attach the billing middleware and shutdown flush to a FastAPI app."""
        app.add_middleware(_UsageMiddleware, auth=self)
        self._installed = True

    async def startup(self) -> None:
        """Fetch the first snapshot and start background tasks.

        Called automatically on the first request; call it from your own
        lifespan for a warm start if you prefer.
        """
        if self._started:
            return
        if self._start_lock is None:
            self._start_lock = asyncio.Lock()
        async with self._start_lock:
            if self._started:
                return
            try:
                await self._refresh()
            except MicroAuthAuthorizationError as exc:
                self._invalidate_authorization()
                logger.error(
                    "microauth: tenant authorization was rejected during startup (%s)",
                    exc,
                )
            except MicroAuthError as exc:
                logger.error("microauth: initial snapshot failed (%s); continuing degraded", exc)
            await self._reporter.start()
            self._sync_task = asyncio.create_task(self._sync_loop(), name="microauth-snapshot-sync")
            self._started = True
            logger.info(
                "microauth: started (customers=%d keys=%d limiter=%s)",
                len(self._snapshot.customers),
                len(self._snapshot.keys),
                type(self._limiter).__name__,
            )

    async def aclose(self) -> None:
        """Stop background tasks and flush pending usage. Idempotent."""
        close_errors: list[Exception] = []
        for task_attr in ("_sync_task", "_request_refresh_task"):
            task: asyncio.Task[None] | None = getattr(self, task_attr)
            if task is None:
                continue
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.exception("microauth: snapshot sync task stopped with an error")
            setattr(self, task_attr, None)
        try:
            await self._reporter.aclose()
        except Exception as exc:
            close_errors.append(exc)
        try:
            await self._limiter.aclose()
        except Exception as exc:
            close_errors.append(exc)
        try:
            await self._client.aclose()
        except Exception as exc:
            close_errors.append(exc)
        self._started = False
        if close_errors:
            raise close_errors[0]

    async def flush_usage(self) -> None:
        """Deliver all currently queued usage and await acknowledgements."""

        if not self._started:
            await self.startup()
        await self._reporter.flush_on_response()

    # ------------------------------------------------------------ dependency

    async def __call__(self, request: Request, api_key: str | None = None) -> Customer:
        if not api_key:
            api_key = request.headers.get(self.header_name)
        if not api_key:
            raise InvalidAPIKey(self.header_name)
        return await self._authenticate(request, api_key)

    async def _authenticate(self, request: Request, api_key: str) -> Customer:
        if not self._started:
            await self.startup()

        if not self._installed:
            raise MicroAuthConfigurationError(
                "MicroAuth must be installed on the FastAPI app to report "
                "completed request status codes"
            )
        if self._authorization_invalid:
            raise AuthUnavailable()
        snap = self._snapshot
        if self._snapshot_unusable(snap):
            # Frozen serverless workers may never run the background sync
            # loop between invocations; recover from the shared cache or the
            # control plane on-request instead of failing until it thaws.
            snap = await self._recover_unusable_snapshot()
        elif snap.age() > self._sync_interval * 1.5:
            self._kick_request_refresh()

        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        record = snap.keys.get(key_hash)
        if record is None:
            record = await self._verify_unknown(key_hash)
            snap = self._snapshot
        if record is None:
            raise InvalidAPIKey(self.header_name)

        cust = snap.customers.get(record.customer_id)
        if cust is None:
            raise InvalidAPIKey(self.header_name)

        if _customer_policy_expired(cust):
            try:
                await self._refresh_expired_policy(key_hash)
            except MicroAuthAuthorizationError as exc:
                self._invalidate_authorization()
                raise AuthUnavailable() from exc
            except MicroAuthError as exc:
                logger.error(
                    "microauth: usage policy expired and could not be refreshed (%s)",
                    exc,
                )
                raise AuthUnavailable() from exc
            snap = self._snapshot
            record = snap.keys.get(key_hash)
            if record is None:
                raise InvalidAPIKey(self.header_name)
            cust = snap.customers.get(record.customer_id)
            if cust is None:
                raise InvalidAPIKey(self.header_name)
            if _customer_policy_expired(cust):
                raise AuthUnavailable()

        if cust.status != "active":
            raise CustomerSuspended()

        eff = cust.effective
        if self._enforce_rps and not await self._limiter.allow(
            cust.id,
            record.key_id,
            eff.rps,
        ):
            raise RateLimited()

        try:
            usage_reservation = self._reporter.reserve()
        except UsageQueueFull as exc:
            logger.error("microauth: refusing request because %s", exc)
            raise AuthUnavailable() from exc
        except MicroAuthError as exc:
            logger.error("microauth: usage journal is unavailable (%s)", exc)
            raise AuthUnavailable() from exc

        potential_spend = (
            eff.price_per_request_micro
            if snap.billable_statuses
            and eff.billing_model != "none"
            and eff.price_per_request_micro > 0
            else 0
        )
        try:
            limit_reservation = await self._limiter.reserve_request(
                self._tenant_scope,
                cust,
                snap,
                usage_reservation.token,
                potential_spend_micro=potential_spend,
                enforce_balance=self._enforce_balance,
                enforce_quota=self._enforce_quota,
                enforce_platform=self._enforce_platform_allowance,
            )
        except ReservationDenied as exc:
            self._reporter.release(usage_reservation)
            if exc.reason == DENIED_BALANCE:
                raise PaymentRequired() from exc
            if exc.reason == DENIED_QUOTA:
                raise QuotaExceeded() from exc
            if exc.reason == DENIED_PLATFORM:
                raise PlatformAllowanceExceeded() from exc
            raise AuthUnavailable() from exc
        except LimitBackendUnavailable as exc:
            self._reporter.release(usage_reservation)
            raise AuthUnavailable() from exc
        except BaseException:
            self._reporter.release(usage_reservation)
            raise

        allowance = snap.platform_allowance
        principal = Customer(
            id=cust.id,
            key_id=record.key_id,
            status=cust.status,
            billing_model=eff.billing_model,
            rps=eff.rps,
            price_per_request_micro=eff.price_per_request_micro,
            monthly_quota=eff.monthly_quota,
            credit_balance_micro=limit_reservation.credit_remaining_micro,
            platform_monthly_limit=allowance.limit if allowance is not None else None,
            platform_monthly_remaining=(
                limit_reservation.platform_remaining
                if allowance is not None
                else None
            ),
            platform_monthly_period_end=(
                allowance.period_end if allowance is not None else None
            ),
        )

        usage_context = _RequestUsage(
            principal=principal,
            billable_statuses=snap.billable_statuses,
            usage_policy_id=cust.usage_policy_id,
            usage_reservation=usage_reservation,
            limit_reservation=limit_reservation,
            occurred_at=datetime.now(timezone.utc),
        )
        setattr(request.state, _STATE_ATTR, usage_context)
        return principal

    def _snapshot_unusable(self, snap: Snapshot) -> bool:
        age = snap.age()
        return (
            not snap.ready
            or age > self._max_stale_snapshot_age
            or (not self._fail_open and age > self._max_snapshot_age)
        )

    async def _recover_unusable_snapshot(self) -> Snapshot:
        """Refresh inline (throttled) before rejecting a request as stale."""

        if time.monotonic() >= self._stale_recovery_blocked_until:
            try:
                await self._refresh()
            except MicroAuthAuthorizationError as exc:
                self._invalidate_authorization()
                raise AuthUnavailable() from exc
            except Exception as exc:
                # One failed recovery is shared across the burst instead of
                # letting every waiting request retry the control plane.
                self._stale_recovery_blocked_until = time.monotonic() + min(
                    self._sync_interval,
                    5.0,
                )
                logger.error(
                    "microauth: stale snapshot could not be recovered "
                    "on-request (%s)",
                    exc,
                )
        snap = self._snapshot
        if self._snapshot_unusable(snap):
            raise AuthUnavailable()
        return snap

    def _kick_request_refresh(self) -> None:
        """Start one background refresh when the sync loop appears frozen."""

        task = self._request_refresh_task
        if task is not None and not task.done():
            return
        now = time.monotonic()
        if now < self._request_refresh_blocked_until:
            return
        self._request_refresh_blocked_until = now + 1.0
        self._request_refresh_task = asyncio.create_task(
            self._request_refresh(),
            name="microauth-request-refresh",
        )

    async def _request_refresh(self) -> None:
        try:
            await self._refresh()
        except MicroAuthAuthorizationError as exc:
            self._invalidate_authorization()
            logger.error(
                "microauth: tenant authorization was rejected (%s)",
                exc,
            )
        except Exception as exc:
            logger.warning(
                "microauth: request-driven snapshot refresh failed (%s)",
                exc,
            )

    # ----------------------------------------------------------- key lookups

    async def _verify_unknown(self, key_hash: str) -> KeyRecord | None:
        """Resolve a key that isn't in the snapshot (e.g. created seconds
        ago). Deduplicates concurrent lookups and caches misses."""
        now = time.monotonic()
        expiry = self._negative.get(key_hash)
        if expiry is not None:
            if expiry > now:
                return None
            del self._negative[key_hash]

        pending = self._verifying.get(key_hash)
        if pending is not None:
            return await asyncio.shield(pending)

        fut: asyncio.Future[KeyRecord | None] = asyncio.get_running_loop().create_future()
        self._verifying[key_hash] = fut
        try:
            result = await self._do_verify(key_hash)
            fut.set_result(result)
            return result
        except Exception as exc:
            fut.set_exception(exc)
            # Consume the exception if nobody else awaited this future.
            fut.exception()
            raise
        finally:
            del self._verifying[key_hash]

    async def _do_verify(self, key_hash: str) -> KeyRecord | None:
        try:
            data = await self._client.verify_key(key_hash)
            valid = data.get("valid")
            if not isinstance(valid, bool):
                raise MicroAuthResponseError(
                    "key verification response has invalid valid status"
                )
            if not valid:
                # Cache the miss briefly so invalid-key floods don't reach
                # MicroAuth.
                self._prune_negative()
                self._negative[key_hash] = (
                    time.monotonic() + self._negative_ttl
                )
                return None

            key_id = _required_uuid(data.get("key_id"), "verify.key_id")
            raw_customer = data.get("customer")
            if not isinstance(raw_customer, dict):
                raise MicroAuthResponseError(
                    "key verification response has invalid customer"
                )
            customer = _parse_customer(raw_customer, "verify.customer")
            billable_statuses = _parse_billable_statuses(
                data.get("billable_status_codes")
            )
        except MicroAuthAuthorizationError as exc:
            self._invalidate_authorization()
            raise AuthUnavailable() from exc
        except MicroAuthError as exc:
            logger.warning("microauth: key verification unavailable (%s)", exc)
            raise AuthUnavailable() from exc

        record = KeyRecord(key_id=key_id, customer_id=customer.id)
        self._snapshot.keys[key_hash] = record
        if record.customer_id not in self._snapshot.customers:
            self._snapshot.customers[record.customer_id] = customer
        self._snapshot.billable_statuses = billable_statuses
        return record

    def _prune_negative(self) -> None:
        if len(self._negative) < 10_000:
            return
        now = time.monotonic()
        self._negative = {h: exp for h, exp in self._negative.items() if exp > now}

    # -------------------------------------------------------------- syncing

    async def _sync_loop(self) -> None:
        while True:
            await asyncio.sleep(self._sync_interval)
            try:
                await self._refresh()
            except asyncio.CancelledError:
                raise
            except MicroAuthAuthorizationError as exc:
                self._invalidate_authorization()
                logger.error(
                    "microauth: tenant authorization was rejected (%s)",
                    exc,
                )
            except Exception as exc:
                age = self._snapshot.age()
                level = logging.ERROR if age > self._max_snapshot_age else logging.WARNING
                logger.log(level, "microauth: snapshot refresh failed (%s); data is %.0fs old", exc, age)

    async def _refresh(self) -> None:
        if self._refresh_lock is None:
            self._refresh_lock = asyncio.Lock()
        async with self._refresh_lock:
            await self._refresh_unlocked()

    async def _refresh_expired_policy(self, key_hash: str) -> None:
        if self._refresh_lock is None:
            self._refresh_lock = asyncio.Lock()
        async with self._refresh_lock:
            current = self._snapshot
            record = current.keys.get(key_hash)
            customer = (
                current.customers.get(record.customer_id)
                if record is not None
                else None
            )
            # Another request or the background loop may already have replaced
            # the expiring snapshot while this request waited for the lock.
            if customer is None or not _customer_policy_expired(customer):
                return
            if time.monotonic() < self._policy_refresh_blocked_until:
                raise AuthUnavailable()

            def policy_valid(snapshot: Snapshot) -> bool:
                # Another instance's published snapshot is acceptable when it
                # carries a live policy for this customer; only one leader
                # needs to reach the control plane at policy expiry.
                if snapshot.age() > self._max_stale_snapshot_age:
                    return False
                snapshot_record = snapshot.keys.get(key_hash)
                if snapshot_record is None:
                    return False
                snapshot_customer = snapshot.customers.get(
                    snapshot_record.customer_id
                )
                return snapshot_customer is not None and not _customer_policy_expired(
                    snapshot_customer
                )

            try:
                await self._refresh_unlocked(accept=policy_valid)
            except Exception:
                # Share a failed refresh across a burst of waiting requests
                # instead of serially retrying the control plane for each one.
                self._policy_refresh_blocked_until = time.monotonic() + min(
                    self._sync_interval,
                    5.0,
                )
                raise

    async def _refresh_unlocked(
        self,
        *,
        accept: Callable[[Snapshot], bool] | None = None,
    ) -> None:
        if self._authorization_invalid:
            # Only a direct authenticated control-plane success may clear an
            # authoritative credential rejection; cached data must not.
            await self._refresh_from_control_plane()
            return
        if self._snapshot_cache is not None:
            await self._refresh_shared_snapshot(
                accept=accept
                or (lambda snapshot: snapshot.age() < self._sync_interval),
            )
            return
        await self._refresh_from_control_plane()

    async def _refresh_shared_snapshot(
        self,
        *,
        accept: Callable[[Snapshot], bool],
    ) -> None:
        cache = self._snapshot_cache
        if cache is None:  # pragma: no cover - guarded by caller
            await self._refresh_from_control_plane()
            return

        cached: CachedSnapshot | None = None
        try:
            cached = await cache.load()
        except SnapshotCacheError as exc:
            logger.warning(
                "microauth: shared snapshot cache unavailable (%s); "
                "refreshing directly",
                exc,
            )
            await self._refresh_from_control_plane()
            return
        except MicroAuthResponseError as exc:
            logger.error(
                "microauth: ignored an invalid shared snapshot envelope (%s)",
                exc,
            )

        if cached is not None:
            try:
                snapshot = _parse_cached_snapshot(cached)
                if accept(snapshot):
                    await self._apply_snapshot(snapshot)
                    return
            except MicroAuthResponseError as exc:
                # Keep the marker so followers wait for the lock owner to
                # replace this exact poison entry rather than returning it.
                logger.error(
                    "microauth: ignored an invalid shared snapshot (%s)",
                    exc,
                )

        try:
            lease = await cache.acquire_refresh_lock()
        except SnapshotCacheError as exc:
            logger.warning(
                "microauth: shared snapshot refresh coordination unavailable "
                "(%s); refreshing directly",
                exc,
            )
            await self._refresh_from_control_plane()
            return
        if lease is not None:
            # The previous owner can publish between our first read and lock
            # acquisition. Recheck before reaching the control plane.
            try:
                latest = await cache.load()
                if latest is not None:
                    snapshot = _parse_cached_snapshot(latest)
                    if accept(snapshot):
                        await self._apply_snapshot(snapshot)
                        try:
                            await cache.release_refresh_lock(lease)
                        except SnapshotCacheError:
                            logger.exception(
                                "microauth: shared snapshot refresh lock "
                                "release failed"
                            )
                        return
            except MicroAuthResponseError as exc:
                logger.error(
                    "microauth: replacing an invalid shared snapshot (%s)",
                    exc,
                )
            except SnapshotCacheError:
                logger.exception(
                    "microauth: shared snapshot recheck failed; refreshing"
                )
            await self._refresh_with_snapshot_lease(cache, lease)
            return

        try:
            updated = await cache.wait_for_update(
                cached.marker if cached is not None else None,
                timeout=self._snapshot_cache_wait,
            )
        except SnapshotCacheError as exc:
            logger.warning(
                "microauth: shared snapshot wait failed (%s); refreshing directly",
                exc,
            )
            await self._refresh_from_control_plane()
            return
        if updated is not None:
            try:
                # A fresh publication is applied even when it does not satisfy
                # the caller's requirement; the caller re-evaluates afterwards.
                await self._apply_snapshot(_parse_cached_snapshot(updated))
                return
            except MicroAuthResponseError as exc:
                logger.error(
                    "microauth: shared snapshot update was invalid (%s)",
                    exc,
                )

        # The previous owner may have crashed or lost its lease. Only the next
        # lock winner retries; other followers continue with bounded fallback.
        try:
            retry_lease = await cache.acquire_refresh_lock()
        except SnapshotCacheError:
            logger.exception(
                "microauth: shared snapshot retry coordination failed"
            )
            retry_lease = None
        if retry_lease is not None:
            await self._refresh_with_snapshot_lease(cache, retry_lease)
            return
        try:
            recovered = await cache.wait_for_update(
                cached.marker if cached is not None else None,
                timeout=self._snapshot_cache_wait,
            )
        except SnapshotCacheError:
            logger.exception(
                "microauth: shared snapshot recovery wait failed"
            )
            recovered = None
        if recovered is not None:
            try:
                await self._apply_snapshot(_parse_cached_snapshot(recovered))
                return
            except MicroAuthResponseError as exc:
                logger.error(
                    "microauth: recovered shared snapshot was invalid (%s)",
                    exc,
                )

        # A healthy lock holder should publish before its lease expires. Keep
        # an already usable local/shared snapshot instead of creating a
        # cold-start thundering herd when the control plane is slow.
        fallback = (
            _parse_cached_snapshot(cached)
            if cached is not None
            else self._snapshot
        )
        if fallback.ready and fallback.age() <= self._max_stale_snapshot_age:
            await self._apply_snapshot(fallback)
            return
        raise SnapshotCacheError(
            "timed out waiting for the shared snapshot refresh"
        )

    async def _refresh_with_snapshot_lease(
        self,
        cache: RedisSnapshotCache,
        lease: SnapshotLease,
    ) -> None:
        heartbeat = asyncio.create_task(
            cache.maintain_refresh_lock(lease),
            name="microauth-snapshot-lock-heartbeat",
        )
        try:
            await self._refresh_from_control_plane(cache_lease=lease)
        except BaseException:
            # The refresh failed while this worker owned the repair duty;
            # quarantine a malformed cache value so followers are not pinned
            # to a poison entry until the next successful publication.
            try:
                await cache.discard_corrupt()
            except SnapshotCacheError:
                logger.exception(
                    "microauth: corrupt shared snapshot could not be discarded"
                )
            raise
        finally:
            heartbeat.cancel()
            try:
                await heartbeat
            except asyncio.CancelledError:
                pass
            except SnapshotCacheError:
                logger.exception(
                    "microauth: shared snapshot refresh lock renewal failed"
                )
            try:
                await cache.release_refresh_lock(lease)
            except SnapshotCacheError:
                logger.exception(
                    "microauth: shared snapshot refresh lock release failed"
                )

    async def _refresh_from_control_plane(
        self,
        *,
        cache_lease: SnapshotLease | None = None,
    ) -> None:
        refresh_started_at = time.time()
        try:
            data = await self._client.snapshot()
        except MicroAuthAuthorizationError:
            self._invalidate_authorization()
            raise
        snap = _parse_snapshot(
            data,
            refresh_started_at=refresh_started_at,
        )
        if cache_lease is not None and self._snapshot_cache is not None:
            try:
                assert snap.generated_at is not None  # enforced by the parser
                fetched_generated_ms = int(snap.generated_at.timestamp() * 1000)
                stored = await self._snapshot_cache.store_if_owner(
                    data,
                    cache_lease,
                    refresh_started_at=refresh_started_at,
                    generated_at_ms=fetched_generated_ms,
                )
                if stored is None:
                    replace_unusable = False
                    try:
                        current = await self._snapshot_cache.load()
                        if current is not None:
                            current_snapshot = _parse_cached_snapshot(current)
                            if (
                                current_snapshot.generated_at is not None
                                and snap.generated_at is not None
                                and current_snapshot.generated_at
                                >= snap.generated_at
                            ):
                                snap = current_snapshot
                            else:
                                logger.warning(
                                    "microauth: snapshot publication was "
                                    "fenced off; a newer owner has refreshed "
                                    "the shared cache"
                                )
                        else:
                            replace_unusable = True
                    except MicroAuthResponseError:
                        # The entry blocking publication cannot be used by
                        # anyone; its recorded generation must not pin the
                        # cache to a poisoned value.
                        replace_unusable = True
                    if replace_unusable:
                        logger.warning(
                            "microauth: force-replacing an unusable shared "
                            "snapshot entry"
                        )
                        await self._snapshot_cache.store_if_owner(
                            data,
                            cache_lease,
                            refresh_started_at=refresh_started_at,
                            generated_at_ms=fetched_generated_ms,
                            force=True,
                        )
            except SnapshotCacheError:
                logger.exception(
                    "microauth: fetched snapshot could not be shared"
                )
            except MicroAuthResponseError:
                logger.exception(
                    "microauth: newer shared snapshot could not be validated"
                )
        await self._apply_snapshot(snap, from_control_plane=True)

    async def _apply_snapshot(
        self,
        snap: Snapshot,
        *,
        from_control_plane: bool = False,
    ) -> None:
        if from_control_plane:
            # Only a successful authenticated control-plane exchange may clear
            # an authoritative 401/403; hydrating shared cache data proves
            # nothing about this process's credential.
            self._authorization_invalid = False
        current = self._snapshot
        if (
            current.ready
            and current.generated_at is not None
            and snap.generated_at is not None
            and snap.generated_at < current.generated_at
        ):
            # Never let older cached data replace a newer local snapshot.
            return
        self._apply_stable_namespace(snap)
        await self._limiter.sync_snapshot(self._tenant_scope, snap)
        self._snapshot = snap
        self._policy_refresh_blocked_until = 0.0

    # -------------------------------------------------------------- billing

    async def _finish_request(
        self,
        context: _RequestUsage,
        status_code: int,
    ) -> str | None:
        if context.finished:
            return context.recorded_event_id
        context.finished = True
        billable = status_code in context.billable_statuses
        recorded_event_id: str | None = None
        if context.usage_reservation is not None:
            attachment = context.limit_reservation.attachment(
                billable=billable,
            )
            try:
                recorded_event_id = await self._reporter.record(
                    context.principal.key_id,
                    status_code,
                    usage_policy_id=context.usage_policy_id,
                    reservation=context.usage_reservation,
                    occurred_at=context.occurred_at,
                    attachment=attachment,
                )
                context.recorded_event_id = recorded_event_id
            except Exception:
                self._reporter.release(context.usage_reservation)
                context.usage_reservation = None
                try:
                    # The event was never journaled, so no acknowledgement can
                    # ever release a billable hold. Finalize as non-billable to
                    # return the reserved spend instead of leaking it until the
                    # reservation TTL expires.
                    await self._limiter.finalize_request(
                        context.limit_reservation,
                        billable=False,
                    )
                except LimitBackendUnavailable:
                    logger.exception(
                        "microauth: request journaling and reservation finalization failed"
                    )
                raise
            context.usage_reservation = None
            if not billable:
                # A billable finalize is a no-op by design: the reserve call
                # already established the monetary hold and its TTL, and the
                # acknowledgement after delivery releases it. Skipping it
                # saves one Redis round trip on every billable response.
                try:
                    await self._limiter.finalize_request(
                        context.limit_reservation,
                        billable=False,
                    )
                except LimitBackendUnavailable:
                    logger.exception(
                        "microauth: could not finalize a request reservation"
                    )
        return recorded_event_id

    async def _flush_after_response(self, event_id: str | None) -> None:
        if not self._flush_on_response or event_id is None:
            return
        try:
            # Only deliver when the batching rule calls for it (a full batch,
            # or the report interval elapsed since the last flush). Otherwise
            # the event stays durably queued and ships with a later batch.
            await self._reporter.flush_on_response(event_id, only_if_due=True)
        except Exception:
            logger.exception(
                "microauth: post-response serverless usage flush failed; "
                "stable items remain queued"
            )

    async def _restore_limit_attachments(
        self,
        attachments: list[dict[str, Any]],
    ) -> None:
        await self._limiter.restore(attachments, self._snapshot)

    async def _usage_authorization_failed(
        self,
        error: MicroAuthAuthorizationError,
    ) -> None:
        self._invalidate_authorization()
        logger.error(
            "microauth: usage reporting authorization was rejected (%s)",
            error,
        )

    def _invalidate_authorization(self) -> None:
        self._authorization_invalid = True
        self._negative.clear()

    def _apply_stable_namespace(self, snapshot: Snapshot) -> None:
        if self._persistence_namespace is not None or snapshot.tenant_id is None:
            return
        stable_scope = _stable_scope(self._base_url, snapshot.tenant_id)
        if stable_scope == self._tenant_scope:
            return
        if self._default_spool:
            stable_path = (
                Path(tempfile.gettempdir())
                / f"microauth-fastapi-{stable_scope}.sqlite3"
            )
            if not self._reporter.set_spool_path(stable_path):
                logger.warning(
                    "microauth: stable tenant namespace arrived after journal "
                    "restoration; configure usage_spool_path to survive secret rotation"
                )
                return
        self._tenant_scope = stable_scope


@dataclass(slots=True)
class _RequestUsage:
    principal: Customer
    billable_statuses: frozenset[int]
    usage_policy_id: str | None
    usage_reservation: UsageReservation | None
    limit_reservation: LimitReservation
    occurred_at: datetime
    finished: bool = False
    recorded_event_id: str | None = None


def _customer_policy_expired(customer: CustomerState) -> bool:
    return (
        customer.policy_valid_until is not None
        and customer.policy_valid_until <= datetime.now(timezone.utc)
    )


def _parse_cached_snapshot(cached: CachedSnapshot) -> Snapshot:
    """Validate a shared-cache payload, preserving the origin refresh cutoff.

    The envelope's ``refresh_started_at`` is the moment the publishing leader
    started reading balances from the control plane. Reconciling acknowledged
    monetary reservations against a later cache-read time could release holds
    for charges the cached balance has never seen.
    """

    return _parse_snapshot(
        cached.payload,
        refresh_started_at=cached.refresh_started_at,
    )


def _parse_snapshot(
    data: dict[str, Any],
    *,
    refresh_started_at: float | None = None,
) -> Snapshot:
    generated_at = _parse_timestamp(data.get("generated_at"), "generated_at")
    now = datetime.now(timezone.utc)
    if generated_at.timestamp() > now.timestamp() + _FUTURE_SKEW_SECONDS:
        raise SnapshotValidationError(
            "generated_at is unreasonably far in the future"
        )

    statuses = _parse_billable_statuses(data.get("billable_status_codes"))

    raw_customers = data.get("customers")
    if not isinstance(raw_customers, list):
        raise SnapshotValidationError("customers must be an array")
    customers: dict[str, CustomerState] = {}
    for index, raw_customer in enumerate(raw_customers):
        if not isinstance(raw_customer, dict):
            raise SnapshotValidationError(
                f"customers[{index}] must be an object"
            )
        customer = _parse_customer(raw_customer, f"customers[{index}]")
        if customer.id in customers:
            raise SnapshotValidationError(
                f"customers contains duplicate id {customer.id!r}"
            )
        customers[customer.id] = customer

    raw_keys = data.get("keys")
    if not isinstance(raw_keys, list):
        raise SnapshotValidationError("keys must be an array")
    keys: dict[str, KeyRecord] = {}
    for index, raw_key in enumerate(raw_keys):
        if not isinstance(raw_key, dict):
            raise SnapshotValidationError(f"keys[{index}] must be an object")
        key_hash = _required_string(
            raw_key.get("key_hash"),
            f"keys[{index}].key_hash",
        )
        if len(key_hash) != 64 or any(
            character not in "0123456789abcdef" for character in key_hash
        ):
            raise SnapshotValidationError(
                f"keys[{index}].key_hash must be lowercase SHA-256 hex"
            )
        if key_hash in keys:
            raise SnapshotValidationError(
                f"keys contains duplicate key_hash {key_hash!r}"
            )
        key_id = _required_uuid(raw_key.get("id"), f"keys[{index}].id")
        customer_id = _required_string(
            raw_key.get("customer_id"),
            f"keys[{index}].customer_id",
        )
        if customer_id not in customers:
            raise SnapshotValidationError(
                f"keys[{index}] references unknown customer {customer_id!r}"
            )
        keys[key_hash] = KeyRecord(
            key_id=key_id,
            customer_id=customer_id,
        )

    allowance = _parse_platform_allowance(data, generated_at)
    tenant_id_raw = data.get("tenant_id")
    tenant_id = (
        None
        if tenant_id_raw is None
        else _required_string(tenant_id_raw, "tenant_id")
    )
    fetched_at = time.monotonic()
    source_age = max(0.0, now.timestamp() - generated_at.timestamp())
    return Snapshot(
        billable_statuses=statuses,
        keys=keys,
        customers=customers,
        platform_allowance=allowance,
        generated_at=generated_at,
        tenant_id=tenant_id,
        fetched_at=fetched_at,
        refresh_started_at=(
            time.time()
            if refresh_started_at is None
            else refresh_started_at
        ),
        source_age_at_fetch=source_age,
    )


def _parse_billable_statuses(raw_statuses: Any) -> frozenset[int]:
    if not isinstance(raw_statuses, list):
        raise SnapshotValidationError("billable_status_codes must be an array")
    statuses: list[int] = []
    for index, raw_status in enumerate(raw_statuses):
        status = _safe_int(
            raw_status,
            f"billable_status_codes[{index}]",
            minimum=100,
            maximum=599,
        )
        statuses.append(status)
    if len(statuses) != len(set(statuses)):
        raise SnapshotValidationError("billable_status_codes contains duplicates")
    return frozenset(statuses)


def _parse_customer(c: dict[str, Any], field: str) -> CustomerState:
    status = _required_string(c.get("status"), f"{field}.status")
    if status not in {"active", "suspended"}:
        raise SnapshotValidationError(
            f"{field}.status must be 'active' or 'suspended'"
        )
    raw_effective = c.get("effective")
    if not isinstance(raw_effective, dict):
        raise SnapshotValidationError(f"{field}.effective must be an object")
    monthly_quota_raw = raw_effective.get("monthly_quota")
    monthly_quota = (
        None
        if monthly_quota_raw is None
        else _safe_int(
            monthly_quota_raw,
            f"{field}.effective.monthly_quota",
            minimum=0,
        )
    )
    raw_policy_id = c.get("usage_policy_id")
    raw_policy_valid_until = c.get("policy_valid_until")
    if (raw_policy_id is None) != (raw_policy_valid_until is None):
        raise SnapshotValidationError(
            f"{field}.usage_policy_id and policy_valid_until must be provided together"
        )
    usage_policy_id = (
        None
        if raw_policy_id is None
        else _required_uuid(raw_policy_id, f"{field}.usage_policy_id")
    )
    policy_valid_until = (
        None
        if raw_policy_valid_until is None
        else _parse_timestamp(
            raw_policy_valid_until,
            f"{field}.policy_valid_until",
        )
    )
    return CustomerState(
        id=_required_string(c.get("id"), f"{field}.id"),
        status=status,
        credit_balance_micro=_safe_int(
            c.get("credit_balance_micro"),
            f"{field}.credit_balance_micro",
            minimum=-MAX_SAFE_INTEGER,
        ),
        month_requests=_safe_int(
            c.get("month_requests"),
            f"{field}.month_requests",
            minimum=0,
        ),
        effective=Effective(
            rps=_safe_int(
                raw_effective.get("rps"),
                f"{field}.effective.rps",
                minimum=0,
            ),
            price_per_request_micro=_safe_int(
                raw_effective.get("price_per_request_micro"),
                f"{field}.effective.price_per_request_micro",
                minimum=0,
            ),
            monthly_quota=monthly_quota,
            billing_model=_required_string(
                raw_effective.get("billing_model"),
                f"{field}.effective.billing_model",
            ),
            source=_required_string(
                raw_effective.get("source"),
                f"{field}.effective.source",
                allow_empty=True,
            ),
        ),
        usage_policy_id=usage_policy_id,
        policy_valid_until=policy_valid_until,
    )


def _parse_platform_allowance(
    raw: dict[str, Any],
    generated_at: datetime,
) -> PlatformMonthlyAllowance:
    limit = _safe_int(
        raw.get("platform_monthly_limit"),
        "platform_monthly_limit",
        minimum=0,
    )
    used = _safe_int(
        raw.get("platform_monthly_used"),
        "platform_monthly_used",
        minimum=0,
    )
    remaining = _safe_int(
        raw.get("platform_monthly_remaining"),
        "platform_monthly_remaining",
        minimum=0,
    )
    expected_remaining = max(0, limit - used)
    if remaining != expected_remaining:
        raise SnapshotValidationError(
            "platform_monthly_remaining must equal max(0, limit - used)"
        )
    period_end = _parse_timestamp(
        raw.get("platform_period_end"),
        "platform_period_end",
    )
    if period_end <= generated_at:
        raise SnapshotValidationError(
            "platform_period_end must follow generated_at"
        )
    hard_cap = raw.get("platform_hard_cap")
    if not isinstance(hard_cap, bool):
        raise SnapshotValidationError(
            "platform_hard_cap must be a boolean"
        )
    return PlatformMonthlyAllowance(
        limit=limit,
        used=used,
        remaining=remaining,
        period_end=period_end,
        hard_cap=hard_cap,
    )


def _parse_timestamp(raw: Any, field: str) -> datetime:
    if not isinstance(raw, str) or len(raw) > 64:
        raise SnapshotValidationError(f"{field} must be an ISO 8601 timestamp")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SnapshotValidationError(
            f"{field} must be an ISO 8601 timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SnapshotValidationError(f"{field} must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _safe_int(
    raw: Any,
    field: str,
    *,
    minimum: int = 0,
    maximum: int = MAX_SAFE_INTEGER,
) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise SnapshotValidationError(f"{field} must be an integer")
    if raw < minimum or raw > maximum:
        raise SnapshotValidationError(
            f"{field} must be between {minimum} and {maximum}"
        )
    return raw


def _required_string(
    raw: Any,
    field: str,
    *,
    allow_empty: bool = False,
) -> str:
    if not isinstance(raw, str) or len(raw) > 512:
        raise SnapshotValidationError(f"{field} must be a string")
    if not allow_empty and not raw:
        raise SnapshotValidationError(f"{field} must not be empty")
    return raw


def _required_uuid(raw: Any, field: str) -> str:
    value = _required_string(raw, field)
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise SnapshotValidationError(f"{field} must be a UUID") from exc
    if parsed.int == 0:
        raise SnapshotValidationError(f"{field} must be a non-zero UUID")
    return str(parsed)


def _validate_positive(field: str, value: Any) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) <= 0
    ):
        raise MicroAuthConfigurationError(f"{field} must be a positive finite number")


def _is_serverless_environment() -> bool:
    return bool(
        os.environ.get("VERCEL")
        or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
    )


def _stable_scope(base_url: str, namespace: str) -> str:
    identity = f"{base_url.rstrip('/')}\0{namespace.strip()}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]


class _OptionalAuth:
    """``Security(auth.optional)`` — returns None instead of 401 when no key
    is presented. Requests with a key still go through every check."""

    def __init__(self, auth: MicroAuth, scheme: APIKeyHeader) -> None:
        self._auth = auth
        sig = _build_signature(scheme)
        self.__signature__ = sig.replace(return_annotation=Customer | None)

    async def __call__(self, request: Request, api_key: str | None = None) -> Customer | None:
        if not api_key:
            api_key = request.headers.get(self._auth.header_name)
        if not api_key:
            return None
        return await self._auth._authenticate(request, api_key)


class _UsageMiddleware:
    """Observe final response status and flush usage during app shutdown."""

    def __init__(self, app: Any, auth: MicroAuth) -> None:
        self.app = app
        self.auth = auth

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(scope, receive, send)
            return
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        status_holder = {"status": 500}
        response_event_id: str | None = None
        response_flushed = False

        async def finish_request() -> None:
            nonlocal response_event_id
            state = scope.get("state")
            context = None
            if state is not None:
                context = (
                    state.get(_STATE_ATTR)
                    if isinstance(state, dict)
                    else getattr(state, _STATE_ATTR, None)
                )
            if context is not None:
                event_id = await self.auth._finish_request(
                    context,
                    status_holder["status"],
                )
                if event_id is not None:
                    response_event_id = event_id

        async def flush_response_usage() -> None:
            nonlocal response_flushed
            if response_flushed:
                return
            response_flushed = True
            task = asyncio.create_task(
                self.auth._flush_after_response(response_event_id),
                name="microauth-post-response-flush",
            )
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                # Preserve the request cancellation, but do not let it cancel
                # a journaled financial event halfway through delivery.
                try:
                    await task
                finally:
                    raise

        async def send_wrapper(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
            elif (
                message["type"] == "http.response.body"
                and not message.get("more_body", False)
            ):
                # Journal the completed request before releasing the final
                # body frame. A process crash cannot leave a response that
                # the caller observed as complete but usage never recorded.
                await finish_request()
                await send(message)
                await flush_response_usage()
                return
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            await finish_request()
            await flush_response_usage()

    async def _lifespan(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        async def send_wrapper(message: dict[str, Any]) -> None:
            if message["type"] == "lifespan.shutdown.complete":
                try:
                    await self.auth.aclose()
                except Exception as exc:
                    await send(
                        {
                            "type": "lifespan.shutdown.failed",
                            "message": str(exc),
                        }
                    )
                    return
            await send(message)

        await self.app(scope, receive, send_wrapper)
