"""Data structures shared across the SDK."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Effective:
    """Resolved limits for a customer (custom override > plan > PAYG)."""

    rps: int
    price_per_request_micro: int
    monthly_quota: int | None
    billing_model: str  # "none" | "payg" | "plan" | ...
    source: str


@dataclass(slots=True)
class CustomerState:
    """Snapshot state for one customer (a portal workspace/team)."""

    id: str
    status: str  # "active" | "suspended"
    credit_balance_micro: int
    month_requests: int
    effective: Effective

    # Local, unreported activity since this snapshot was taken. Used to keep
    # balance/quota enforcement honest between syncs. Reset on every refresh.
    local_requests: int = 0
    local_spend_micro: int = 0


@dataclass(frozen=True, slots=True)
class KeyRecord:
    key_id: str
    customer_id: str


@dataclass(slots=True)
class Snapshot:
    """One immutable-ish view of the tenant's customers and keys."""

    billable_statuses: frozenset[int] = frozenset({200})
    keys: dict[str, KeyRecord] = field(default_factory=dict)  # sha256 hex -> record
    customers: dict[str, CustomerState] = field(default_factory=dict)
    fetched_at: float = 0.0  # time.monotonic()

    def age(self) -> float:
        return time.monotonic() - self.fetched_at


@dataclass(frozen=True, slots=True)
class Customer:
    """The principal handed to your endpoint by ``Security(auth)``.

    Everything you might want for per-customer logic without extra lookups.
    """

    id: str
    key_id: str
    status: str
    billing_model: str
    rps: int
    price_per_request_micro: int
    monthly_quota: int | None
    credit_balance_micro: int
