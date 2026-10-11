"""The SDK must parse exactly what the Go API emits.

The fixtures in ``tests/contract`` are written by the platform's
``TestSDKContractFixtures`` from the real response structs and copied here
verbatim, so a field rename on either side fails a test.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from microauth_fastapi.models import CustomerBalance
from microauth_fastapi.reporter import _parse_acknowledgements
from microauth_fastapi.sdk import _parse_customer, _parse_snapshot

CONTRACT_DIR = Path(__file__).parent / "contract"
PLATFORM_CONTRACT_DIR = (
    Path(__file__).resolve().parents[3]
    / "app"
    / "internal"
    / "server"
    / "testdata"
    / "sdk-contract"
)
GENERATED_AT = 1_791_711_000.123456  # the fixtures' generated_at


def load(name: str) -> dict[str, Any]:
    data = json.loads((CONTRACT_DIR / name).read_text())
    assert isinstance(data, dict)
    return data


def test_snapshot_fixture_parses_with_every_customer_status() -> None:
    snapshot = _parse_snapshot(load("snapshot.json"), now=GENERATED_AT + 1)

    assert snapshot.tenant_id == "0f6b2d4e-8a1c-4e3f-9b5d-7c2e1a4f6b80"
    assert snapshot.tenant_name == "Weather API"
    statuses = {customer.status for customer in snapshot.customers.values()}
    assert statuses == {"active", "pending", "suspended"}
    seqs = {customer.status: customer.balance_seq for customer in snapshot.customers.values()}
    assert seqs == {"active": 7, "pending": 1, "suspended": 12}
    assert snapshot.billable_statuses == frozenset(range(200, 207))
    assert snapshot.platform_allowance is not None
    assert snapshot.platform_allowance.remaining == 996_400
    assert len(snapshot.keys) == 2
    assert snapshot.generated_at is not None
    assert snapshot.generated_at.microsecond == 123_456
    assert snapshot.source_age_at_fetch == pytest.approx(1.0, abs=0.01)


def test_subscription_customers_without_a_quota_are_unlimited() -> None:
    snapshot = _parse_snapshot(load("snapshot.json"), now=GENERATED_AT)
    subscribed = next(
        customer
        for customer in snapshot.customers.values()
        if customer.effective.billing_model == "subscription"
    )
    assert subscribed.effective.monthly_quota is None
    assert subscribed.usage_policy_id == "8c3b2e4a-1d9f-4a5c-8b37-4e6f8a0c2d35"


@pytest.mark.parametrize(
    "field",
    ["tenant_id", "generated_at", "billable_status_codes", "customers", "keys"],
)
def test_snapshot_without_a_required_field_is_refused(field: str) -> None:
    from microauth_fastapi.exceptions import SnapshotValidationError

    data = load("snapshot.json")
    del data[field]
    with pytest.raises(SnapshotValidationError):
        _parse_snapshot(data, now=GENERATED_AT)


@pytest.mark.parametrize(
    "field",
    ["balance_seq", "usage_policy_id", "policy_valid_until", "status", "effective"],
)
def test_customer_without_a_required_field_is_refused(field: str) -> None:
    from microauth_fastapi.exceptions import SnapshotValidationError

    data = load("snapshot.json")
    del data["customers"][0][field]
    with pytest.raises(SnapshotValidationError):
        _parse_snapshot(data, now=GENERATED_AT)


def test_snapshot_from_the_future_is_refused() -> None:
    from microauth_fastapi.exceptions import SnapshotValidationError

    with pytest.raises(SnapshotValidationError, match="future"):
        _parse_snapshot(load("snapshot.json"), now=GENERATED_AT - 120)


def test_verify_fixture_carries_a_full_customer() -> None:
    verified = load("verify.json")
    assert verified["valid"] is True
    customer = _parse_customer(verified["customer"], "verify.customer")
    assert customer.usage_policy_id == "6a1f0c2e-9b7d-4e3a-8f15-2c4d6e8a0b13"
    assert customer.balance_seq == 7
    assert load("verify_invalid.json") == {"valid": False}


def test_usage_fixture_maps_every_result_and_receipt() -> None:
    response = load("usage_response.json")
    ids = [result["idempotency_key"] for result in response["results"]]

    plan = _parse_acknowledgements(response, ids)

    assert plan.error is None
    assert plan.accepted == ids[:3]
    assert plan.retry == []
    assert {key: (r.http_status, r.detail) for key, r in plan.rejected.items()} == {
        ids[3]: (422, "period_start is outside the usage policy's validity"),
        ids[4]: (409, "idempotency_key was already used for a different request"),
    }
    first, free, duplicate = (plan.receipts[key] for key in ids[:3])
    assert (first.outcome, first.charged_micro) == ("accepted", 42_000)
    assert first.customer_id == "2b7c1f8e-5d34-4a9b-8c21-6e0f3d9a7b55"
    assert first.recorded_at is not None
    assert first.recorded_at.microsecond == 250_000
    assert (free.outcome, free.charged_micro) == ("accepted", 0)
    assert (duplicate.outcome, duplicate.charged_micro) == ("duplicate", 42_000)
    assert duplicate.recorded_at is not None and duplicate.recorded_at < first.recorded_at
    assert plan.balances == [
        CustomerBalance(
            customer_id="2b7c1f8e-5d34-4a9b-8c21-6e0f3d9a7b55",
            credit_balance_micro=4_958_000,
            balance_seq=8,
        )
    ]


@pytest.mark.parametrize(
    "receipt",
    [
        {"charged_micro": "42000"},
        {"charged_micro": -1},
        {"charged_micro": True},
        {"recorded_at": "yesterday"},
        {"customer_id": 7},
    ],
)
def test_an_unreadable_receipt_field_never_blocks_acknowledgement(
    receipt: dict[str, Any],
) -> None:
    response = load("usage_response.json")
    response["results"][0].update(receipt)
    ids = [result["idempotency_key"] for result in response["results"]]
    plan = _parse_acknowledgements(response, ids)
    assert plan.error is None
    assert ids[0] in plan.accepted
    field, _ = next(iter(receipt.items()))
    parsed = plan.receipts[ids[0]]
    assert getattr(parsed, field) is None


@pytest.mark.parametrize(
    "customers",
    [
        None,
        "nope",
        [{"id": "c", "credit_balance_micro": 1}],
        [{"id": "c", "credit_balance_micro": True, "balance_seq": 1}],
        [{"id": "c", "credit_balance_micro": 1, "balance_seq": -1}],
    ],
)
def test_malformed_committed_balances_fall_back_safely(customers: Any) -> None:
    response = load("usage_response.json")
    response["customers"] = customers
    ids = [result["idempotency_key"] for result in response["results"]]
    plan = _parse_acknowledgements(response, ids)
    assert plan.error is None
    assert plan.balances == []


@pytest.mark.skipif(
    not PLATFORM_CONTRACT_DIR.is_dir(),
    reason="the platform repository is not checked out next to the SDK",
)
@pytest.mark.parametrize(
    "name",
    ["snapshot.json", "usage_response.json", "verify.json", "verify_invalid.json"],
)
def test_fixtures_match_the_platform(name: str) -> None:
    assert (CONTRACT_DIR / name).read_bytes() == (PLATFORM_CONTRACT_DIR / name).read_bytes()
