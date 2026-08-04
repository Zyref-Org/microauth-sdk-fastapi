"""Atomic request reservations for memory and Redis deployments."""

from __future__ import annotations

import hashlib
import logging
import math
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from .exceptions import LimitBackendUnavailable
from .models import (
    MAX_SAFE_INTEGER,
    CustomerState,
    LimitReservation,
    PlatformMonthlyAllowance,
    Snapshot,
)

logger = logging.getLogger("microauth")

DENIED_BALANCE = "balance"
DENIED_QUOTA = "quota"
DENIED_PLATFORM = "platform"

_RPS_SCRIPT = """
local marker = "microauth-rps-v2"
local count = redis.call("INCR", KEYS[1])
if count == 1 then
    redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
return count
"""

_RESERVE_SCRIPT = """
local marker = "microauth-request-reserve-v2"
local customer_floor = tonumber(redis.call("HGET", KEYS[1], "floor") or ARGV[1])
local customer_count = tonumber(redis.call("HGET", KEYS[1], "count") or customer_floor)
local incoming_customer_floor = tonumber(ARGV[1])
if incoming_customer_floor > customer_floor then
    customer_floor = incoming_customer_floor
end
if customer_count < customer_floor then
    customer_count = customer_floor
end

local snapshot_version = tonumber(ARGV[3])
local stored_version = tonumber(redis.call("HGET", KEYS[2], "version") or "-1")
local balance = tonumber(redis.call("HGET", KEYS[2], "balance") or ARGV[2])
local reserved = tonumber(redis.call("HGET", KEYS[2], "reserved") or "0")

local acknowledged = redis.call("ZRANGEBYSCORE", KEYS[5], "-inf", ARGV[13])
for _, token in ipairs(acknowledged) do
    local amount = tonumber(redis.call("HGET", KEYS[4], token) or "0")
    reserved = math.max(0, reserved - amount)
    redis.call("HDEL", KEYS[4], token)
    redis.call("ZREM", KEYS[5], token)
end

if snapshot_version > stored_version then
    balance = tonumber(ARGV[2])
    stored_version = snapshot_version
end

local platform_floor = tonumber(redis.call("HGET", KEYS[3], "floor") or ARGV[5])
local platform_count = tonumber(redis.call("HGET", KEYS[3], "count") or platform_floor)
local incoming_platform_floor = tonumber(ARGV[5])
if incoming_platform_floor > platform_floor then
    platform_floor = incoming_platform_floor
end
if platform_count < platform_floor then
    platform_count = platform_floor
end

local quota = tonumber(ARGV[4])
local platform_limit = tonumber(ARGV[6])
local spend = tonumber(ARGV[8])
local maximum = tonumber(ARGV[15])
local reason = 0
if tonumber(ARGV[9]) == 1 and quota >= 0 and customer_count >= quota then
    reason = 2
elseif tonumber(ARGV[10]) == 1 and spend > 0 and balance - reserved < spend then
    reason = 1
elseif tonumber(ARGV[11]) == 1 and tonumber(ARGV[7]) == 1
       and platform_count >= platform_limit then
    reason = 3
elseif customer_count >= maximum or platform_count >= maximum
       or spend > maximum - reserved then
    reason = 4
elseif redis.call("HEXISTS", KEYS[4], ARGV[12]) == 1 then
    reason = 5
end

if reason == 0 then
    customer_count = customer_count + 1
    platform_count = platform_count + 1
    reserved = reserved + spend
    redis.call("HSET", KEYS[4], ARGV[12], spend)
end

redis.call(
    "HSET",
    KEYS[1],
    "floor", customer_floor,
    "count", customer_count
)
redis.call(
    "HSET",
    KEYS[2],
    "balance", balance,
    "reserved", reserved,
    "version", stored_version
)
redis.call(
    "HSET",
    KEYS[3],
    "floor", platform_floor,
    "count", platform_count
)
for index = 1, 5 do
    redis.call("PEXPIRE", KEYS[index], ARGV[14])
end

local quota_remaining = -1
if quota >= 0 then
    quota_remaining = math.max(0, quota - customer_count)
end
local platform_remaining = math.max(0, platform_limit - platform_count)
return {
    reason,
    math.max(0, balance - reserved),
    quota_remaining,
    platform_remaining
}
"""

_FINALIZE_SCRIPT = """
local marker = "microauth-request-finalize-v2"
local amount = tonumber(redis.call("HGET", KEYS[2], ARGV[1]) or "0")
local reserved = tonumber(redis.call("HGET", KEYS[1], "reserved") or "0")
if tonumber(ARGV[2]) == 0 then
    reserved = math.max(0, reserved - amount)
    redis.call("HSET", KEYS[2], ARGV[1], 0)
    redis.call("HSET", KEYS[1], "reserved", reserved)
end
for index = 1, 3 do
    redis.call("PEXPIRE", KEYS[index], ARGV[3])
end
return reserved
"""

_ACKNOWLEDGE_SCRIPT = """
local marker = "microauth-request-acknowledge-v2"
if redis.call("HEXISTS", KEYS[1], ARGV[1]) == 1 then
    redis.call("ZADD", KEYS[2], ARGV[2], ARGV[1])
end
redis.call("PEXPIRE", KEYS[1], ARGV[3])
redis.call("PEXPIRE", KEYS[2], ARGV[3])
return 1
"""

_RESTORE_SCRIPT = """
local marker = "microauth-request-restore-v2"
if redis.call("HEXISTS", KEYS[4], ARGV[8]) == 1 then
    return 0
end

local customer_floor = tonumber(redis.call("HGET", KEYS[1], "floor") or ARGV[1])
local customer_count = tonumber(redis.call("HGET", KEYS[1], "count") or customer_floor)
if tonumber(ARGV[1]) > customer_floor then
    customer_floor = tonumber(ARGV[1])
end
if customer_count < customer_floor then
    customer_count = customer_floor
end

local stored_version = tonumber(redis.call("HGET", KEYS[2], "version") or "-1")
local balance = tonumber(redis.call("HGET", KEYS[2], "balance") or ARGV[2])
local reserved = tonumber(redis.call("HGET", KEYS[2], "reserved") or "0")
if tonumber(ARGV[3]) > stored_version then
    balance = tonumber(ARGV[2])
    stored_version = tonumber(ARGV[3])
end

local platform_floor = tonumber(redis.call("HGET", KEYS[3], "floor") or ARGV[4])
local platform_count = tonumber(redis.call("HGET", KEYS[3], "count") or platform_floor)
if tonumber(ARGV[4]) > platform_floor then
    platform_floor = tonumber(ARGV[4])
end
if platform_count < platform_floor then
    platform_count = platform_floor
end

local spend = tonumber(ARGV[7])
local maximum = tonumber(ARGV[10])
if customer_count >= maximum or platform_count >= maximum
   or spend > maximum - reserved then
    return -1
end
customer_count = customer_count + 1
platform_count = platform_count + 1
reserved = reserved + spend
redis.call("HSET", KEYS[4], ARGV[8], spend)
redis.call("HSET", KEYS[1], "floor", customer_floor, "count", customer_count)
redis.call(
    "HSET",
    KEYS[2],
    "balance", balance,
    "reserved", reserved,
    "version", stored_version
)
redis.call("HSET", KEYS[3], "floor", platform_floor, "count", platform_count)
for index = 1, 5 do
    redis.call("PEXPIRE", KEYS[index], ARGV[9])
end
return 1
"""


class ReservationDenied(Exception):
    """An atomic reservation could not satisfy an enforced limit."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class Limiter(Protocol):
    distributed: bool

    async def allow(self, customer_id: str, credential_id: str, rps: int) -> bool: ...

    async def sync_snapshot(
        self,
        tenant_scope: str,
        snapshot: Snapshot,
    ) -> None: ...

    async def reserve_request(
        self,
        tenant_scope: str,
        customer: CustomerState,
        snapshot: Snapshot,
        token: str,
        *,
        potential_spend_micro: int,
        enforce_balance: bool,
        enforce_quota: bool,
        enforce_platform: bool,
    ) -> LimitReservation: ...

    async def finalize_request(
        self,
        reservation: LimitReservation,
        *,
        billable: bool,
    ) -> None: ...

    async def acknowledge(self, attachments: list[dict[str, Any]]) -> None: ...

    async def reject(self, attachments: list[dict[str, Any]]) -> None: ...

    async def restore(
        self,
        attachments: list[dict[str, Any]],
        snapshot: Snapshot,
    ) -> None: ...

    async def aclose(self) -> None: ...


@dataclass(slots=True)
class _Window:
    epoch: int
    count: int


@dataclass(slots=True)
class _Counter:
    floor: int
    count: int
    period_end: float


@dataclass(slots=True)
class _Balance:
    value: int
    reserved: int
    snapshot_version: float
    last_seen: float
    reservations: dict[str, int] = field(default_factory=dict)
    acknowledged: dict[str, float] = field(default_factory=dict)


class MemoryLimiter:
    """A process-local implementation with one lock for atomic decisions."""

    distributed = False

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._windows: dict[tuple[str, str], _Window] = {}
        self._quotas: dict[tuple[str, str, str], _Counter] = {}
        self._platform: dict[tuple[str, str], _Counter] = {}
        self._balances: dict[tuple[str, str], _Balance] = {}
        self._last_gc = time.monotonic()

    async def allow(self, customer_id: str, credential_id: str, rps: int) -> bool:
        if rps <= 0:
            return True
        epoch = int(time.time())
        key = (customer_id, credential_id)
        with self._lock:
            window = self._windows.get(key)
            if window is None or window.epoch != epoch:
                window = self._windows[key] = _Window(epoch=epoch, count=0)
            window.count += 1
            self._maybe_gc_locked()
            return window.count <= rps

    async def sync_snapshot(
        self,
        tenant_scope: str,
        snapshot: Snapshot,
    ) -> None:
        allowance = _required_allowance(snapshot)
        snapshot_version = _snapshot_version(snapshot)
        with self._lock:
            platform = self._platform_state(tenant_scope, allowance)
            platform.floor = max(platform.floor, allowance.used)
            platform.count = max(platform.count, platform.floor)
            for customer in snapshot.customers.values():
                quota = self._quota_state(tenant_scope, customer, allowance)
                quota.floor = max(quota.floor, customer.month_requests)
                quota.count = max(quota.count, quota.floor)
                balance = self._balance_state(
                    tenant_scope,
                    customer,
                    snapshot_version,
                )
                self._apply_balance_snapshot(
                    balance,
                    customer.credit_balance_micro,
                    snapshot_version,
                    snapshot.refresh_started_at,
                )
            self._maybe_gc_locked()

    async def reserve_request(
        self,
        tenant_scope: str,
        customer: CustomerState,
        snapshot: Snapshot,
        token: str,
        *,
        potential_spend_micro: int,
        enforce_balance: bool,
        enforce_quota: bool,
        enforce_platform: bool,
    ) -> LimitReservation:
        allowance = _required_allowance(snapshot)
        snapshot_version = _snapshot_version(snapshot)
        if potential_spend_micro < 0 or potential_spend_micro > MAX_SAFE_INTEGER:
            raise LimitBackendUnavailable("potential request spend is outside the safe range")
        with self._lock:
            quota = self._quota_state(tenant_scope, customer, allowance)
            quota.floor = max(quota.floor, customer.month_requests)
            quota.count = max(quota.count, quota.floor)
            platform = self._platform_state(tenant_scope, allowance)
            platform.floor = max(platform.floor, allowance.used)
            platform.count = max(platform.count, platform.floor)
            balance = self._balance_state(
                tenant_scope,
                customer,
                snapshot_version,
            )
            self._apply_balance_snapshot(
                balance,
                customer.credit_balance_micro,
                snapshot_version,
                snapshot.refresh_started_at,
            )

            monthly_quota = customer.effective.monthly_quota
            if (
                enforce_quota
                and monthly_quota is not None
                and quota.count >= monthly_quota
            ):
                raise ReservationDenied(DENIED_QUOTA)
            if (
                enforce_balance
                and potential_spend_micro > 0
                and balance.value - balance.reserved < potential_spend_micro
            ):
                raise ReservationDenied(DENIED_BALANCE)
            if (
                enforce_platform
                and allowance.hard_cap
                and platform.count >= allowance.limit
            ):
                raise ReservationDenied(DENIED_PLATFORM)
            if (
                quota.count >= MAX_SAFE_INTEGER
                or platform.count >= MAX_SAFE_INTEGER
                or potential_spend_micro > MAX_SAFE_INTEGER - balance.reserved
            ):
                raise LimitBackendUnavailable("local request counters exceeded the safe range")
            if token in balance.reservations:
                raise LimitBackendUnavailable("duplicate request reservation token")

            quota.count += 1
            platform.count += 1
            balance.reserved += potential_spend_micro
            balance.reservations[token] = potential_spend_micro
            quota_remaining = (
                None
                if monthly_quota is None
                else max(0, monthly_quota - quota.count)
            )
            return LimitReservation(
                token=token,
                tenant_scope=tenant_scope,
                customer_id=customer.id,
                period_key=allowance.period_key,
                period_end=allowance.period_end,
                spend_micro=potential_spend_micro,
                credit_remaining_micro=max(0, balance.value - balance.reserved),
                quota_remaining=quota_remaining,
                platform_remaining=max(0, allowance.limit - platform.count),
            )

    async def finalize_request(
        self,
        reservation: LimitReservation,
        *,
        billable: bool,
    ) -> None:
        if billable:
            return
        with self._lock:
            balance = self._balances.get(
                (reservation.tenant_scope, reservation.customer_id)
            )
            if balance is None:
                return
            amount = balance.reservations.get(reservation.token)
            if amount is None:
                return
            balance.reserved = max(0, balance.reserved - amount)
            balance.reservations[reservation.token] = 0

    async def acknowledge(self, attachments: list[dict[str, Any]]) -> None:
        acknowledged_at = time.time()
        with self._lock:
            for raw in attachments:
                attachment = _parse_attachment(raw)
                balance = self._balances.get(
                    (attachment.tenant_scope, attachment.customer_id)
                )
                if balance is not None and attachment.token in balance.reservations:
                    balance.acknowledged[attachment.token] = acknowledged_at

    async def reject(self, attachments: list[dict[str, Any]]) -> None:
        with self._lock:
            for raw in attachments:
                attachment = _parse_attachment(raw)
                balance = self._balances.get(
                    (attachment.tenant_scope, attachment.customer_id)
                )
                if balance is None:
                    continue
                amount = balance.reservations.get(attachment.token)
                if amount is not None:
                    balance.reserved = max(0, balance.reserved - amount)
                    balance.reservations[attachment.token] = 0

    async def restore(
        self,
        attachments: list[dict[str, Any]],
        snapshot: Snapshot,
    ) -> None:
        allowance = _required_allowance(snapshot)
        snapshot_version = _snapshot_version(snapshot)
        with self._lock:
            for raw in attachments:
                attachment = _parse_attachment(raw)
                customer = snapshot.customers.get(attachment.customer_id)
                customer_floor = customer.month_requests if customer is not None else 0
                credit_balance = (
                    customer.credit_balance_micro if customer is not None else 0
                )
                quota_key = (
                    attachment.tenant_scope,
                    attachment.period_key,
                    attachment.customer_id,
                )
                quota = self._quotas.get(quota_key)
                if quota is None:
                    quota = self._quotas[quota_key] = _Counter(
                        floor=customer_floor,
                        count=customer_floor,
                        period_end=attachment.period_end.timestamp(),
                    )
                platform_key = (
                    attachment.tenant_scope,
                    attachment.period_key,
                )
                platform = self._platform.get(platform_key)
                if platform is None:
                    platform_floor = (
                        allowance.used
                        if attachment.period_key == allowance.period_key
                        else 0
                    )
                    platform = self._platform[platform_key] = _Counter(
                        floor=platform_floor,
                        count=platform_floor,
                        period_end=attachment.period_end.timestamp(),
                    )
                balance_key = (
                    attachment.tenant_scope,
                    attachment.customer_id,
                )
                balance = self._balances.get(balance_key)
                if balance is None:
                    balance = self._balances[balance_key] = _Balance(
                        value=credit_balance,
                        reserved=0,
                        snapshot_version=snapshot_version,
                        last_seen=time.time(),
                    )
                if attachment.token in balance.reservations:
                    continue
                quota.count += 1
                platform.count += 1
                balance.reservations[attachment.token] = attachment.spend_micro
                balance.reserved += attachment.spend_micro

    def _quota_state(
        self,
        tenant_scope: str,
        customer: CustomerState,
        allowance: PlatformMonthlyAllowance,
    ) -> _Counter:
        key = (tenant_scope, allowance.period_key, customer.id)
        state = self._quotas.get(key)
        if state is None:
            state = self._quotas[key] = _Counter(
                floor=customer.month_requests,
                count=customer.month_requests,
                period_end=allowance.period_end.timestamp(),
            )
        return state

    def _platform_state(
        self,
        tenant_scope: str,
        allowance: PlatformMonthlyAllowance,
    ) -> _Counter:
        key = (tenant_scope, allowance.period_key)
        state = self._platform.get(key)
        if state is None:
            state = self._platform[key] = _Counter(
                floor=allowance.used,
                count=allowance.used,
                period_end=allowance.period_end.timestamp(),
            )
        return state

    def _balance_state(
        self,
        tenant_scope: str,
        customer: CustomerState,
        snapshot_version: float,
    ) -> _Balance:
        key = (tenant_scope, customer.id)
        state = self._balances.get(key)
        if state is None:
            state = self._balances[key] = _Balance(
                value=customer.credit_balance_micro,
                reserved=0,
                snapshot_version=snapshot_version,
                last_seen=time.time(),
            )
        else:
            state.last_seen = time.time()
        return state

    @staticmethod
    def _apply_balance_snapshot(
        balance: _Balance,
        authoritative_balance: int,
        snapshot_version: float,
        refresh_started_at: float,
    ) -> None:
        acknowledged = [
            token
            for token, acknowledged_at in balance.acknowledged.items()
            if acknowledged_at <= refresh_started_at
        ]
        for token in acknowledged:
            amount = balance.reservations.pop(token, 0)
            balance.reserved = max(0, balance.reserved - amount)
            del balance.acknowledged[token]
        if snapshot_version > balance.snapshot_version:
            balance.value = authoritative_balance
            balance.snapshot_version = snapshot_version

    def _maybe_gc_locked(self) -> None:
        now = time.monotonic()
        if now - self._last_gc < 600:
            return
        self._last_gc = now
        epoch = int(time.time())
        self._windows = {
            key: window
            for key, window in self._windows.items()
            if epoch - window.epoch <= 600
        }
        wall_time = time.time()
        self._quotas = {
            key: counter
            for key, counter in self._quotas.items()
            if counter.period_end + 86_400 >= wall_time
        }
        self._platform = {
            key: counter
            for key, counter in self._platform.items()
            if counter.period_end + 86_400 >= wall_time
        }
        self._balances = {
            key: balance
            for key, balance in self._balances.items()
            if balance.reservations
            or balance.last_seen + 46 * 86_400 >= wall_time
        }

    async def aclose(self) -> None:
        return None


class RedisLimiter:
    """A Redis implementation that shares reservations across workers."""

    distributed = True

    def __init__(
        self,
        url: str | None = None,
        key_prefix: str = "ma",
        *,
        redis_client: Any | None = None,
    ) -> None:
        self._owns_redis = redis_client is None
        if redis_client is None:
            if not url:
                raise ValueError("url is required when redis_client is not provided")
            try:
                import redis.asyncio as aioredis
            except ImportError as exc:  # pragma: no cover
                raise RuntimeError(
                    "Redis was configured but the redis package is not installed. "
                    "Install with: pip install 'microauth-fastapi[redis]'"
                ) from exc
            redis_client = aioredis.from_url(
                url,
                socket_timeout=1.0,
                socket_connect_timeout=1.0,
            )
        self._redis = redis_client
        self._prefix = key_prefix.rstrip(":")
        self._down_until = 0.0

    async def allow(self, customer_id: str, credential_id: str, rps: int) -> bool:
        if rps <= 0:
            return True
        now = time.monotonic()
        if now < self._down_until:
            return True
        identity = hashlib.sha256(
            f"{customer_id}\0{credential_id}".encode()
        ).hexdigest()[:32]
        key = f"{self._prefix}:rps:{identity}:{int(time.time())}"
        try:
            count = int(await self._redis.eval(_RPS_SCRIPT, 1, key, 3000))
        except Exception:
            self._down_until = now + 2.0
            logger.warning("microauth: Redis RPS limiter unavailable; failing open")
            return True
        return count <= rps

    async def sync_snapshot(
        self,
        tenant_scope: str,
        snapshot: Snapshot,
    ) -> None:
        # Authoritative floors are merged by the same Lua operation that
        # reserves the next request. No Redis round trip is needed here.
        _required_allowance(snapshot)

    async def reserve_request(
        self,
        tenant_scope: str,
        customer: CustomerState,
        snapshot: Snapshot,
        token: str,
        *,
        potential_spend_micro: int,
        enforce_balance: bool,
        enforce_quota: bool,
        enforce_platform: bool,
    ) -> LimitReservation:
        allowance = _required_allowance(snapshot)
        if potential_spend_micro < 0 or potential_spend_micro > MAX_SAFE_INTEGER:
            raise LimitBackendUnavailable("potential request spend is outside the safe range")
        keys = self._keys(
            tenant_scope,
            allowance.period_key,
            customer.id,
        )
        ttl_ms = _state_ttl_ms(allowance.period_end)
        quota = customer.effective.monthly_quota
        try:
            result = await self._redis.eval(
                _RESERVE_SCRIPT,
                5,
                keys.customer,
                keys.balance,
                keys.platform,
                keys.reservations,
                keys.acknowledgements,
                customer.month_requests,
                customer.credit_balance_micro,
                _snapshot_version_ms(snapshot),
                -1 if quota is None else quota,
                allowance.used,
                allowance.limit,
                int(allowance.hard_cap),
                potential_spend_micro,
                int(enforce_quota),
                int(enforce_balance),
                int(enforce_platform),
                token,
                _milliseconds(snapshot.refresh_started_at),
                ttl_ms,
                MAX_SAFE_INTEGER,
            )
            values = [int(value) for value in result]
        except Exception as exc:
            raise LimitBackendUnavailable(
                "Redis is unavailable; request limits cannot be reserved atomically"
            ) from exc
        if len(values) != 4:
            raise LimitBackendUnavailable("Redis returned an invalid reservation decision")
        reason, credit_remaining, quota_remaining, platform_remaining = values
        if reason == 1:
            raise ReservationDenied(DENIED_BALANCE)
        if reason == 2:
            raise ReservationDenied(DENIED_QUOTA)
        if reason == 3:
            raise ReservationDenied(DENIED_PLATFORM)
        if reason != 0:
            raise LimitBackendUnavailable("Redis could not create a safe reservation")
        return LimitReservation(
            token=token,
            tenant_scope=tenant_scope,
            customer_id=customer.id,
            period_key=allowance.period_key,
            period_end=allowance.period_end,
            spend_micro=potential_spend_micro,
            customer_key=keys.customer,
            balance_key=keys.balance,
            platform_key=keys.platform,
            reservation_key=keys.reservations,
            acknowledgement_key=keys.acknowledgements,
            credit_remaining_micro=credit_remaining,
            quota_remaining=None if quota_remaining < 0 else quota_remaining,
            platform_remaining=platform_remaining,
        )

    async def finalize_request(
        self,
        reservation: LimitReservation,
        *,
        billable: bool,
    ) -> None:
        try:
            await self._redis.eval(
                _FINALIZE_SCRIPT,
                3,
                reservation.balance_key,
                reservation.reservation_key,
                reservation.acknowledgement_key,
                reservation.token,
                int(billable),
                _state_ttl_ms(reservation.period_end),
            )
        except Exception as exc:
            raise LimitBackendUnavailable(
                "Redis could not finalize the request reservation"
            ) from exc

    async def acknowledge(self, attachments: list[dict[str, Any]]) -> None:
        acknowledged_at = _milliseconds(time.time())
        try:
            for raw in attachments:
                attachment = _parse_attachment(raw)
                keys = self._attachment_keys(attachment)
                await self._redis.eval(
                    _ACKNOWLEDGE_SCRIPT,
                    2,
                    keys.reservations,
                    keys.acknowledgements,
                    attachment.token,
                    acknowledged_at,
                    _state_ttl_ms(attachment.period_end),
                )
        except Exception as exc:
            raise LimitBackendUnavailable(
                "Redis could not acknowledge usage reservations"
            ) from exc

    async def reject(self, attachments: list[dict[str, Any]]) -> None:
        try:
            for raw in attachments:
                attachment = _parse_attachment(raw)
                keys = self._attachment_keys(attachment)
                await self._redis.eval(
                    _FINALIZE_SCRIPT,
                    3,
                    keys.balance,
                    keys.reservations,
                    keys.acknowledgements,
                    attachment.token,
                    0,
                    _state_ttl_ms(attachment.period_end),
                )
        except Exception as exc:
            raise LimitBackendUnavailable(
                "Redis could not release a rejected monetary reservation"
            ) from exc

    async def restore(
        self,
        attachments: list[dict[str, Any]],
        snapshot: Snapshot,
    ) -> None:
        allowance = _required_allowance(snapshot)
        try:
            for raw in attachments:
                attachment = _parse_attachment(raw)
                keys = self._attachment_keys(attachment)
                customer = snapshot.customers.get(attachment.customer_id)
                customer_floor = (
                    customer.month_requests
                    if customer is not None
                    and attachment.period_key == allowance.period_key
                    else 0
                )
                credit_balance = (
                    customer.credit_balance_micro if customer is not None else 0
                )
                platform_floor = (
                    allowance.used
                    if attachment.period_key == allowance.period_key
                    else 0
                )
                restored = int(await self._redis.eval(
                    _RESTORE_SCRIPT,
                    5,
                    keys.customer,
                    keys.balance,
                    keys.platform,
                    keys.reservations,
                    keys.acknowledgements,
                    customer_floor,
                    credit_balance,
                    _snapshot_version_ms(snapshot),
                    platform_floor,
                    allowance.limit,
                    int(allowance.hard_cap),
                    attachment.spend_micro,
                    attachment.token,
                    _state_ttl_ms(attachment.period_end),
                    MAX_SAFE_INTEGER,
                ))
                if restored < 0:
                    raise LimitBackendUnavailable(
                        "restored request counters exceeded the safe range"
                    )
        except Exception as exc:
            raise LimitBackendUnavailable(
                "Redis could not restore durable usage reservations"
            ) from exc

    async def aclose(self) -> None:
        if not self._owns_redis:
            return
        try:
            await self._redis.aclose()
        except Exception:  # pragma: no cover
            logger.exception("microauth: failed to close internally owned Redis client")

    def _keys(
        self,
        tenant_scope: str,
        period_key: str,
        customer_id: str,
    ) -> _RedisKeys:
        tag = hashlib.sha256(tenant_scope.encode()).hexdigest()[:32]
        customer_hash = hashlib.sha256(customer_id.encode()).hexdigest()[:32]
        root = f"{self._prefix}:{{{tag}}}"
        return _RedisKeys(
            customer=f"{root}:quota:{period_key}:{customer_hash}",
            balance=f"{root}:balance:{customer_hash}",
            platform=f"{root}:platform:{period_key}",
            reservations=f"{root}:reservations:{customer_hash}",
            acknowledgements=f"{root}:acks:{customer_hash}",
        )

    def _attachment_keys(self, attachment: _Attachment) -> _RedisKeys:
        generated = self._keys(
            attachment.tenant_scope,
            attachment.period_key,
            attachment.customer_id,
        )
        return _RedisKeys(
            customer=attachment.customer_key or generated.customer,
            balance=attachment.balance_key or generated.balance,
            platform=attachment.platform_key or generated.platform,
            reservations=attachment.reservation_key or generated.reservations,
            acknowledgements=(
                attachment.acknowledgement_key
                or generated.acknowledgements
            ),
        )


@dataclass(frozen=True, slots=True)
class _RedisKeys:
    customer: str
    balance: str
    platform: str
    reservations: str
    acknowledgements: str


@dataclass(frozen=True, slots=True)
class _Attachment:
    token: str
    tenant_scope: str
    customer_id: str
    period_key: str
    period_end: datetime
    spend_micro: int
    customer_key: str
    balance_key: str
    platform_key: str
    reservation_key: str
    acknowledgement_key: str


def _parse_attachment(raw: dict[str, Any]) -> _Attachment:
    try:
        period_end_raw = raw["period_end"]
        if not isinstance(period_end_raw, str):
            raise TypeError
        period_end = datetime.fromisoformat(period_end_raw.replace("Z", "+00:00"))
        if period_end.tzinfo is None or period_end.utcoffset() is None:
            raise ValueError
        spend_micro = raw["spend_micro"]
        if (
            isinstance(spend_micro, bool)
            or not isinstance(spend_micro, int)
            or spend_micro < 0
            or spend_micro > MAX_SAFE_INTEGER
        ):
            raise ValueError
        required = {
            field: raw[field]
            for field in ("token", "tenant_scope", "customer_id", "period_key")
        }
        if any(not isinstance(value, str) or not value for value in required.values()):
            raise ValueError
        optional: dict[str, str] = {}
        for field_name in (
            "customer_key",
            "balance_key",
            "platform_key",
            "reservation_key",
            "acknowledgement_key",
        ):
            value = raw.get(field_name, "")
            if not isinstance(value, str):
                raise TypeError
            optional[field_name] = value
    except (KeyError, TypeError, ValueError) as exc:
        raise LimitBackendUnavailable("usage journal has invalid limit metadata") from exc
    return _Attachment(
        token=required["token"],
        tenant_scope=required["tenant_scope"],
        customer_id=required["customer_id"],
        period_key=required["period_key"],
        period_end=period_end.astimezone(timezone.utc),
        spend_micro=spend_micro,
        customer_key=optional["customer_key"],
        balance_key=optional["balance_key"],
        platform_key=optional["platform_key"],
        reservation_key=optional["reservation_key"],
        acknowledgement_key=optional["acknowledgement_key"],
    )


def _required_allowance(snapshot: Snapshot) -> PlatformMonthlyAllowance:
    allowance = snapshot.platform_allowance
    if allowance is None:
        raise LimitBackendUnavailable("snapshot has no platform allowance")
    return allowance


def _snapshot_version(snapshot: Snapshot) -> float:
    if snapshot.generated_at is None:
        raise LimitBackendUnavailable("snapshot has no generation timestamp")
    return snapshot.generated_at.timestamp()


def _snapshot_version_ms(snapshot: Snapshot) -> int:
    return _milliseconds(_snapshot_version(snapshot))


def _milliseconds(value: float) -> int:
    if not math.isfinite(value):
        raise LimitBackendUnavailable("limiter timestamp is not finite")
    return int(value * 1000)


def _state_ttl_ms(period_end: datetime) -> int:
    # Retain counters through the longest calendar month and long enough for
    # the API's 45-day delayed-usage window. Redis accepts 64-bit PEXPIRE
    # values, so this must not be clamped to a signed 32-bit duration.
    seconds_until_end = period_end.timestamp() - time.time()
    seconds = max(1.0, seconds_until_end + 46 * 86_400)
    return math.ceil(seconds * 1000)
