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
* Metered billing: responses whose status code is billable (configured by
  you in MicroAuth) are counted and reported in the background.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import logging
import os
import time
from typing import Any, Optional

from fastapi import Request, Security
from fastapi.security import APIKeyHeader

from .client import APIClient
from .exceptions import (
    AuthUnavailable,
    CustomerSuspended,
    InvalidAPIKey,
    MicroAuthAPIError,
    PaymentRequired,
    QuotaExceeded,
    RateLimited,
)
from .limiter import Limiter, MemoryLimiter, RedisLimiter
from .models import Customer, CustomerState, Effective, KeyRecord, Snapshot
from .reporter import UsageReporter

logger = logging.getLogger("microauth")

_STATE_ATTR = "microauth_principal"


def _build_signature(scheme: APIKeyHeader) -> inspect.Signature:
    """A per-instance ``__call__`` signature so FastAPI wires the request and
    the API key header (and documents the security scheme in OpenAPI)."""
    return inspect.Signature(
        [
            inspect.Parameter("request", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=Request),
            inspect.Parameter(
                "api_key",
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=Optional[str],
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
        app: Your FastAPI app. Strongly recommended — it installs the tiny
            middleware that observes response status codes for billing and
            flushes pending usage on shutdown. Without it, every authenticated
            request is billed regardless of response status.
        secret_key: Tenant secret (``mas_...``). Defaults to the
            ``MICROAUTH_SECRET_KEY`` environment variable.
        base_url: MicroAuth API base. Default ``https://api.microauth.com``
            (override with ``MICROAUTH_BASE_URL``).
        header_name: Header your customers send their API key in.
            Default ``X-API-Key``.
        redis_url: Optional Redis URL (``redis://...``). When set, RPS limits
            are enforced exactly across all workers/machines. Without it,
            each worker enforces limits independently. Defaults to the
            ``MICROAUTH_REDIS_URL`` environment variable.
        sync_interval: Seconds between snapshot refreshes. Default 30.
        report_interval: Seconds between usage report flushes. Default 15.
        max_snapshot_age: If the snapshot can't be refreshed for this many
            seconds, behavior follows ``fail_open``. Default 300.
        fail_open: With a stale snapshot: ``True`` (default) keeps serving
            known keys with the last known data; ``False`` returns 503.
        enforce_balance: Reject with 402 when a paying customer's prepaid
            balance is exhausted. Default True.
        enforce_quota: Reject with 429 when the customer's monthly quota is
            used up. Default True.
        enforce_rps: Apply per-customer RPS limits. Default True.
        verify_negative_ttl: Seconds an unknown key is cached as invalid
            (protects MicroAuth from invalid-key floods). Default 30.
        timeout: HTTP timeout for MicroAuth API calls. Default 5s.
    """

    def __init__(
        self,
        app: Any = None,
        secret_key: str | None = None,
        *,
        base_url: str | None = None,
        header_name: str = "X-API-Key",
        redis_url: str | None = None,
        sync_interval: float = 30.0,
        report_interval: float = 15.0,
        max_snapshot_age: float = 300.0,
        fail_open: bool = True,
        enforce_balance: bool = True,
        enforce_quota: bool = True,
        enforce_rps: bool = True,
        verify_negative_ttl: float = 30.0,
        timeout: float = 5.0,
    ) -> None:
        secret_key = secret_key or os.environ.get("MICROAUTH_SECRET_KEY", "")
        if not secret_key.startswith("mas_"):
            raise ValueError(
                "MicroAuth tenant secret key is missing or malformed. Pass "
                "secret_key='mas_...' or set the MICROAUTH_SECRET_KEY env var."
            )
        base_url = base_url or os.environ.get("MICROAUTH_BASE_URL", "https://api.microauth.com")
        redis_url = redis_url or os.environ.get("MICROAUTH_REDIS_URL") or None

        self.header_name = header_name
        self._client = APIClient(base_url, secret_key, timeout)
        self._reporter = UsageReporter(self._client, report_interval)
        self._limiter: Limiter = RedisLimiter(redis_url) if redis_url else MemoryLimiter()
        self._snapshot = Snapshot()
        self._sync_interval = sync_interval
        self._max_snapshot_age = max_snapshot_age
        self._fail_open = fail_open
        self._enforce_balance = enforce_balance
        self._enforce_quota = enforce_quota
        self._enforce_rps = enforce_rps
        self._negative_ttl = verify_negative_ttl

        self._sync_task: asyncio.Task[None] | None = None
        self._started = False
        self._start_lock: asyncio.Lock | None = None
        self._negative: dict[str, float] = {}  # key hash -> monotonic expiry
        self._verifying: dict[str, asyncio.Future[KeyRecord | None]] = {}

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
            except MicroAuthAPIError as exc:
                # Keys can still resolve via on-demand verification.
                logger.error("microauth: initial snapshot failed (%s); continuing degraded", exc)
            self._sync_task = asyncio.create_task(self._sync_loop(), name="microauth-snapshot-sync")
            self._reporter.start()
            self._started = True
            logger.info(
                "microauth: started (customers=%d keys=%d limiter=%s)",
                len(self._snapshot.customers),
                len(self._snapshot.keys),
                type(self._limiter).__name__,
            )

    async def aclose(self) -> None:
        """Stop background tasks and flush pending usage. Idempotent."""
        if self._sync_task is not None:
            self._sync_task.cancel()
            try:
                await self._sync_task
            except (asyncio.CancelledError, Exception):
                pass
            self._sync_task = None
        await self._reporter.aclose()
        await self._limiter.aclose()
        await self._client.aclose()
        self._started = False

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

        snap = self._snapshot
        if not self._fail_open and snap.age() > self._max_snapshot_age:
            raise AuthUnavailable()

        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        record = snap.keys.get(key_hash) or await self._verify_unknown(key_hash)
        if record is None:
            raise InvalidAPIKey(self.header_name)

        cust = self._snapshot.customers.get(record.customer_id)
        if cust is None:
            raise InvalidAPIKey(self.header_name)

        if cust.status != "active":
            raise CustomerSuspended()

        eff = cust.effective
        metered = eff.billing_model != "none" and eff.price_per_request_micro > 0

        if self._enforce_balance and metered:
            projected = cust.credit_balance_micro - cust.local_spend_micro
            if projected < eff.price_per_request_micro:
                raise PaymentRequired()

        if self._enforce_quota and eff.monthly_quota:
            if cust.month_requests + cust.local_requests >= eff.monthly_quota:
                raise QuotaExceeded()

        if self._enforce_rps and not await self._limiter.allow(cust.id, eff.rps):
            raise RateLimited()

        principal = Customer(
            id=cust.id,
            key_id=record.key_id,
            status=cust.status,
            billing_model=eff.billing_model,
            rps=eff.rps,
            price_per_request_micro=eff.price_per_request_micro,
            monthly_quota=eff.monthly_quota,
            credit_balance_micro=cust.credit_balance_micro - cust.local_spend_micro,
        )
        # The middleware picks this up after the response to record usage.
        setattr(request.state, _STATE_ATTR, principal)
        return principal

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
        except MicroAuthAPIError as exc:
            logger.warning("microauth: key verification unavailable (%s)", exc)
            if self._fail_open:
                return None  # unknown key: reject the request, keep serving
            raise AuthUnavailable() from exc

        if not data.get("valid"):
            # Cache the miss briefly so invalid-key floods don't reach MicroAuth.
            self._prune_negative()
            self._negative[key_hash] = time.monotonic() + self._negative_ttl
            return None

        record = KeyRecord(key_id=data["key_id"], customer_id=data["customer"]["id"])
        self._snapshot.keys[key_hash] = record
        if record.customer_id not in self._snapshot.customers:
            self._snapshot.customers[record.customer_id] = _parse_customer(data["customer"])
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
            except Exception as exc:
                age = self._snapshot.age()
                level = logging.ERROR if age > self._max_snapshot_age else logging.WARNING
                logger.log(level, "microauth: snapshot refresh failed (%s); data is %.0fs old", exc, age)

    async def _refresh(self) -> None:
        data = await self._client.snapshot()
        snap = Snapshot(
            billable_statuses=frozenset(int(c) for c in data.get("billable_status_codes") or [200]),
            keys={k["key_hash"]: KeyRecord(key_id=k["id"], customer_id=k["customer_id"]) for k in data.get("keys") or []},
            customers={c["id"]: _parse_customer(c) for c in data.get("customers") or []},
            fetched_at=time.monotonic(),
        )
        self._snapshot = snap  # atomic swap; in-flight requests keep the old one

    # -------------------------------------------------------------- billing

    def _record_usage(self, principal: Customer, status_code: int) -> None:
        if status_code not in self._snapshot.billable_statuses:
            return
        self._reporter.record(principal.key_id)
        cust = self._snapshot.customers.get(principal.id)
        if cust is not None:
            cust.local_requests += 1
            if cust.effective.billing_model != "none":
                cust.local_spend_micro += cust.effective.price_per_request_micro


def _parse_customer(c: dict[str, Any]) -> CustomerState:
    eff = c.get("effective") or {}
    return CustomerState(
        id=c["id"],
        status=c.get("status", "active"),
        credit_balance_micro=int(c.get("credit_balance_micro", 0)),
        month_requests=int(c.get("month_requests", 0)),
        effective=Effective(
            rps=int(eff.get("rps", 0)),
            price_per_request_micro=int(eff.get("price_per_request_micro", 0)),
            monthly_quota=eff.get("monthly_quota"),
            billing_model=eff.get("billing_model", "none"),
            source=eff.get("source", ""),
        ),
    )


class _OptionalAuth:
    """``Security(auth.optional)`` — returns None instead of 401 when no key
    is presented. Requests with a key still go through every check."""

    def __init__(self, auth: MicroAuth, scheme: APIKeyHeader) -> None:
        self._auth = auth
        sig = _build_signature(scheme)
        self.__signature__ = sig.replace(return_annotation=Optional[Customer])

    async def __call__(self, request: Request, api_key: str | None = None) -> Customer | None:
        if not api_key:
            api_key = request.headers.get(self._auth.header_name)
        if not api_key:
            return None
        return await self._auth._authenticate(request, api_key)


class _UsageMiddleware:
    """Pure-ASGI middleware: observes the response status for billing and
    flushes usage when the server shuts down. Adds no measurable latency —
    a dict lookup and an integer increment per request."""

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

        async def send_wrapper(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            state = scope.get("state")
            principal = None
            if state is not None:
                principal = state.get(_STATE_ATTR) if isinstance(state, dict) else getattr(state, _STATE_ATTR, None)
            if principal is not None:
                self.auth._record_usage(principal, status_holder["status"])

    async def _lifespan(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        async def receive_wrapper() -> dict[str, Any]:
            message = await receive()
            if message["type"] == "lifespan.shutdown":
                await self.auth.aclose()
            return message

        await self.app(scope, receive_wrapper, send)
