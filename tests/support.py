"""Shared builders for the SDK tests."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from microauth_fastapi.models import CustomerState, Effective
from microauth_fastapi.reporter import UsageReporter

SECRET = "mas_" + "T3stSecret" * 4
TENANT_ID = "0f6b2d4e-8a1c-4e3f-9b5d-7c2e1a4f6b80"
POLICY_ID = "99999999-9999-4999-8999-999999999999"
POLICY_VALID_UNTIL = datetime(2099, 1, 1, tzinfo=timezone.utc)
POLICY_VALID_UNTIL_ISO = "2099-01-01T00:00:00Z"


def customer_state(
    customer_id: str = "customer-1",
    *,
    status: str = "active",
    balance: int = 100,
    month_requests: int = 0,
    rps: int = 10,
    price: int = 10,
    quota: int | None = 100,
    billing_model: str = "payg",
    source: str = "plan",
    usage_policy_id: str = POLICY_ID,
    policy_valid_until: datetime = POLICY_VALID_UNTIL,
    balance_seq: int = 0,
) -> CustomerState:
    return CustomerState(
        id=customer_id,
        status=status,
        credit_balance_micro=balance,
        month_requests=month_requests,
        effective=Effective(
            rps=rps,
            price_per_request_micro=price,
            monthly_quota=quota,
            billing_model=billing_model,
            source=source,
        ),
        usage_policy_id=usage_policy_id,
        policy_valid_until=policy_valid_until,
        balance_seq=balance_seq,
    )


class Reporter(UsageReporter):
    """A reporter whose ``record`` defaults the usage policy.

    Every real request carries the policy it was admitted under; tests that
    are about something else would only repeat the same id on every call.
    """

    async def record(  # type: ignore[override]
        self,
        api_key_id: str,
        status_code: int,
        *,
        usage_policy_id: str = POLICY_ID,
        **kwargs: Any,
    ) -> str:
        return await super().record(
            api_key_id,
            status_code,
            usage_policy_id=usage_policy_id,
            **kwargs,
        )
