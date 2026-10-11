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

# The usage endpoint accepts at most this many requests in one item.
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
    # The price policy requests are admitted under. Usage carries it back so
    # late reports are charged at the price that was enforced.
    usage_policy_id: str
    policy_valid_until: datetime
    # Grows with every committed balance change, so two observations of one
    # customer's balance can always be ordered exactly.
    balance_seq: int


@dataclass(frozen=True, slots=True)
class CustomerBalance:
    """A committed balance returned with a usage acknowledgement."""

    customer_id: str
    credit_balance_micro: int
    balance_seq: int


@dataclass(frozen=True, slots=True)
class PlatformMonthlyAllowance:
    """Your MicroAuth plan's monthly request allowance."""

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
    """One immutable-ish view of the API's customers and keys."""

    billable_statuses: frozenset[int] = frozenset({200})
    keys: dict[str, KeyRecord] = field(default_factory=dict)
    customers: dict[str, CustomerState] = field(default_factory=dict)
    platform_allowance: PlatformMonthlyAllowance | None = None
    generated_at: datetime | None = None
    tenant_id: str = ""
    tenant_name: str = ""
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


@dataclass(frozen=True, slots=True)
class UsageReceipt:
    """MicroAuth's record of one delivered usage item.

    An item counts ``count`` requests that share an API key, usage policy,
    status code and UTC hour. ``outcome`` is ``accepted`` when this delivery
    recorded it and ``duplicate`` when MicroAuth had already recorded it,
    for example after a retry whose first answer was lost. Either way the
    customer was charged exactly once, ``charged_micro``.
    """

    idempotency_key: str
    outcome: str
    customer_id: str | None
    api_key_id: str
    usage_policy_id: str
    status_code: int
    count: int
    period_start: datetime
    # What MicroAuth charged, in micro-USD. None only if the API omitted it.
    charged_micro: int | None
    # What the SDK expected from the prices it enforced when it admitted the
    # requests. None when this process did not admit all of them itself.
    expected_charge_micro: int | None
    recorded_at: datetime | None
    delivered_at: datetime

    @property
    def charge_matches(self) -> bool | None:
        """Whether MicroAuth charged what the SDK expected, when both are known."""

        if self.charged_micro is None or self.expected_charge_micro is None:
            return None
        return self.charged_micro == self.expected_charge_micro


@dataclass(frozen=True, slots=True)
class UsageRejection:
    """A usage item MicroAuth refused for good, with the reason.

    Rejected items are never charged. They are kept as dead letters in the
    journal (and in Redis, when configured) for inspection with
    ``python -m microauth_fastapi usage``.
    """

    idempotency_key: str
    api_key_id: str
    usage_policy_id: str
    status_code: int
    count: int
    period_start: datetime
    http_status: int | None
    detail: str
    rejected_at: datetime


@dataclass(frozen=True, slots=True)
class UsageStats:
    """Delivery health of this process's usage reporting.

    Counters cover the life of the process. Export them to your metrics
    system and alert on ``rejected_items``, ``charge_mismatches``,
    ``consecutive_failures`` and an ``oldest_queued_at`` that keeps aging.
    """

    # Where queued usage survives a crash: "redis", "journal" or "memory".
    durability: str
    journal_dir: str | None
    queued_items: int
    queued_requests: int
    oldest_queued_at: datetime | None
    # Items MicroAuth has recorded, including duplicates it had recorded
    # before (after a retry whose first answer was lost).
    delivered_items: int
    delivered_requests: int
    duplicate_items: int
    rejected_items: int
    rejected_requests: int
    # The sum of charged_micro over every receipt this process received.
    charged_micro: int
    charge_mismatches: int
    last_delivery_at: datetime | None
    consecutive_failures: int
    last_error: str | None
    last_error_at: datetime | None
    # Seconds to add to this host's clock to read MicroAuth's.
    clock_offset_seconds: float
    hook_failures: int
