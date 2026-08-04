"""Data structures shared across the SDK."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# Redis Lua and common JSON consumers represent integers exactly only through
# this bound. Snapshot monetary and counter values are rejected above it
# instead of silently rounding an authorization decision.
MAX_SAFE_INTEGER = (1 << 53) - 1

# The Go ingestion endpoint applies this stricter bound to each usage item.
MAX_USAGE_COUNT = 10_000_000


@dataclass(frozen=True, slots=True)
class Effective:
    """Resolved limits for a customer (custom override > plan > PAYG)."""

    rps: int
    price_per_request_micro: int
    monthly_quota: int | None
    billing_model: str
    source: str


@dataclass(frozen=True, slots=True)
class CustomerState:
    """Authoritative snapshot state for one portal customer."""

    id: str
    status: str
    credit_balance_micro: int
    month_requests: int
    effective: Effective
    usage_policy_id: str | None = None
    policy_valid_until: datetime | None = None


@dataclass(frozen=True, slots=True)
class PlatformMonthlyAllowance:
    """The flat platform allowance fields returned by the Go API."""

    limit: int
    used: int
    remaining: int
    period_end: datetime
    hard_cap: bool

    @property
    def period_key(self) -> str:
        return str(int(self.period_end.timestamp()))


@dataclass(frozen=True, slots=True)
class KeyRecord:
    key_id: str
    customer_id: str


@dataclass(slots=True)
class Snapshot:
    """One immutable-ish view of the tenant's customers and keys."""

    billable_statuses: frozenset[int] = frozenset({200})
    keys: dict[str, KeyRecord] = field(default_factory=dict)
    customers: dict[str, CustomerState] = field(default_factory=dict)
    platform_allowance: PlatformMonthlyAllowance | None = None
    generated_at: datetime | None = None
    tenant_id: str | None = None
    fetched_at: float = 0.0
    refresh_started_at: float = 0.0
    source_age_at_fetch: float = 0.0

    @property
    def ready(self) -> bool:
        return self.fetched_at > 0.0 and self.generated_at is not None

    def age(self) -> float:
        if not self.ready:
            return float("inf")
        return max(0.0, self.source_age_at_fetch + time.monotonic() - self.fetched_at)


@dataclass(frozen=True, slots=True)
class LimitReservation:
    """A pre-handler reservation that can survive journal recovery."""

    token: str
    tenant_scope: str
    customer_id: str
    period_key: str
    period_end: datetime
    spend_micro: int
    customer_key: str = ""
    balance_key: str = ""
    platform_key: str = ""
    reservation_key: str = ""
    acknowledgement_key: str = ""
    credit_remaining_micro: int = 0
    quota_remaining: int | None = None
    platform_remaining: int | None = None

    def attachment(self, *, billable: bool) -> dict[str, Any]:
        """Return the durable subset needed to recover limiter state."""

        return {
            "token": self.token,
            "tenant_scope": self.tenant_scope,
            "customer_id": self.customer_id,
            "period_key": self.period_key,
            "period_end": self.period_end.isoformat().replace("+00:00", "Z"),
            "spend_micro": self.spend_micro if billable else 0,
            "customer_key": self.customer_key,
            "balance_key": self.balance_key,
            "platform_key": self.platform_key,
            "reservation_key": self.reservation_key,
            "acknowledgement_key": self.acknowledgement_key,
        }


@dataclass(frozen=True, slots=True)
class Customer:
    """The principal handed to an endpoint by ``Security(auth)``."""

    id: str
    key_id: str
    status: str
    billing_model: str
    rps: int
    price_per_request_micro: int
    monthly_quota: int | None
    credit_balance_micro: int
    platform_monthly_limit: int | None = None
    platform_monthly_remaining: int | None = None
    platform_monthly_period_end: datetime | None = None
