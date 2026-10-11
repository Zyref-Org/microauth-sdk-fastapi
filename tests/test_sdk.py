from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, HTTPException, Response, Security
from support import SECRET, TENANT_ID

from microauth_fastapi import (
    Customer,
    MicroAuth,
    MicroAuthAuthorizationError,
    MicroAuthConfigurationError,
    SnapshotValidationError,
)
from microauth_fastapi.client import APIClient
from microauth_fastapi.exceptions import MicroAuthAPIError
from microauth_fastapi.models import MAX_SAFE_INTEGER
from microauth_fastapi.sdk import _STATE_ATTR, _parse_snapshot, _UsageMiddleware

API_KEY = "map_test_credential"
KEY_HASH = hashlib.sha256(API_KEY.encode()).hexdigest()
KEY_ID = "11111111-1111-4111-8111-111111111111"
POLICY_ID = "22222222-2222-4222-8222-222222222222"


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def snapshot_payload(
    *,
    statuses: list[int] | None = None,
    platform_limit: int = 1_000_000,
    platform_used: int = 0,
    platform_hard_cap: bool = True,
    generated_at: datetime | None = None,
    balance: int = 1_000_000,
    month_requests: int = 0,
    quota: int | None = None,
    price: int = 0,
    billing_model: str = "none",
    rps: int = 0,
    tenant_id: str = TENANT_ID,
) -> dict[str, Any]:
    generated_at = generated_at or datetime.now(timezone.utc)
    period_end = datetime(
        generated_at.year + int(generated_at.month == 12),
        1 if generated_at.month == 12 else generated_at.month + 1,
        1,
        tzinfo=timezone.utc,
    )
    payload: dict[str, Any] = {
        "tenant_id": tenant_id,
        "tenant_name": "Weather API",
        "generated_at": iso(generated_at),
        "billable_status_codes": [200] if statuses is None else statuses,
        "platform_monthly_limit": platform_limit,
        "platform_monthly_used": platform_used,
        "platform_monthly_remaining": max(0, platform_limit - platform_used),
        "platform_period_end": iso(period_end),
        "platform_hard_cap": platform_hard_cap,
        "customers": [
            {
                "id": "customer-1",
                "status": "active",
                "credit_balance_micro": balance,
                "balance_seq": 0,
                "month_requests": month_requests,
                "usage_policy_id": POLICY_ID,
                "policy_valid_until": iso(generated_at + timedelta(hours=24)),
                "effective": {
                    "rps": rps,
                    "price_per_request_micro": price,
                    "monthly_quota": quota,
                    "billing_model": billing_model,
                    "source": "plan",
                },
            }
        ],
        "keys": [
            {
                "id": KEY_ID,
                "customer_id": "customer-1",
                "key_hash": KEY_HASH,
            }
        ],
    }
    return payload


class ControlPlane:
    def __init__(
        self,
        snapshot: dict[str, Any],
        *,
        snapshot_status: int = 200,
    ) -> None:
        self.snapshot = snapshot
        self.snapshot_status = snapshot_status
        self.usage_calls: list[dict[str, Any]] = []
        self.snapshot_calls = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/sdk/v1/snapshot":
            self.snapshot_calls += 1
            if self.snapshot_status >= 400:
                return httpx.Response(self.snapshot_status, text="snapshot failed")
            return httpx.Response(200, json=self.snapshot)
        if request.url.path == "/sdk/v1/usage":
            body = json.loads(request.content)
            self.usage_calls.append(body)
            return httpx.Response(
                200,
                json={
                    "accepted": len(body["items"]),
                    "results": [self.receipt(item) for item in body["items"]],
                },
            )
        raise AssertionError(f"unexpected control-plane path {request.url.path}")

    def receipt(self, item: dict[str, Any]) -> dict[str, Any]:
        # The platform's charging rule: count times price, for billable
        # statuses under a priced billing model.
        customer = self.snapshot["customers"][0]
        effective = customer["effective"]
        billable = (
            item["status_code"] in self.snapshot["billable_status_codes"]
            and effective["billing_model"] != "none"
        )
        price = effective["price_per_request_micro"] if billable else 0
        return {
            "idempotency_key": item["idempotency_key"],
            "status": "accepted",
            "customer_id": customer["id"],
            "charged_micro": item["count"] * price,
            "recorded_at": iso(datetime.now(timezone.utc)),
        }


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


def test_snapshot_parser_matches_flat_go_contract() -> None:
    valid = snapshot_payload(
        statuses=[201, 207],
        platform_limit=10,
        platform_used=3,
    )
    parsed = _parse_snapshot(valid)
    assert parsed.billable_statuses == frozenset({201, 207})
    assert parsed.platform_allowance is not None
    assert parsed.platform_allowance.limit == 10
    assert parsed.platform_allowance.used == 3
    assert parsed.platform_allowance.remaining == 7
    assert parsed.platform_allowance.hard_cap is True

    over_limit = snapshot_payload(platform_limit=2, platform_used=3)
    assert _parse_snapshot(over_limit).platform_allowance.remaining == 0  # type: ignore[union-attr]

    old_shape = deepcopy(valid)
    for field in (
        "platform_monthly_limit",
        "platform_monthly_used",
        "platform_monthly_remaining",
        "platform_period_end",
        "platform_hard_cap",
    ):
        del old_shape[field]
    old_shape["platform_monthly_allowance"] = {
        "limit": 10,
        "used": 3,
        "remaining": 7,
    }
    with pytest.raises(SnapshotValidationError):
        _parse_snapshot(old_shape)


def test_snapshot_rejects_unsafe_or_inconsistent_values() -> None:
    valid = snapshot_payload(platform_limit=10)
    invalid_status = deepcopy(valid)
    invalid_status["billable_status_codes"] = [True]
    with pytest.raises(SnapshotValidationError):
        _parse_snapshot(invalid_status)

    unsafe_count = deepcopy(valid)
    unsafe_count["customers"][0]["month_requests"] = MAX_SAFE_INTEGER + 1
    with pytest.raises(SnapshotValidationError):
        _parse_snapshot(unsafe_count)

    inconsistent = deepcopy(valid)
    inconsistent["platform_monthly_remaining"] = 9
    with pytest.raises(SnapshotValidationError):
        _parse_snapshot(inconsistent)

    naive_timestamp = deepcopy(valid)
    naive_timestamp["platform_period_end"] = "2026-09-01T00:00:00"
    with pytest.raises(SnapshotValidationError):
        _parse_snapshot(naive_timestamp)

    invalid_hard_cap = deepcopy(valid)
    invalid_hard_cap["platform_hard_cap"] = 1
    with pytest.raises(SnapshotValidationError):
        _parse_snapshot(invalid_hard_cap)


def test_every_completed_authenticated_status_is_reported() -> None:
    plane = ControlPlane(snapshot_payload(statuses=[299]))

    async def exercise() -> None:
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        app = FastAPI()
        auth = MicroAuth(
            app,
            secret_key=SECRET,
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
        )
        await auth._apply_snapshot(_parse_snapshot(plane.snapshot))
        auth._started = True

        @app.get("/custom", status_code=299)
        async def custom(customer: Customer = Security(auth)) -> Response:
            return Response(status_code=299)

        @app.get("/missing")
        async def missing(customer: Customer = Security(auth)) -> None:
            raise HTTPException(404, "not found")

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as caller:
            assert (await caller.get("/custom", headers={"X-API-Key": API_KEY})).status_code == 299
            assert (await caller.get("/missing", headers={"X-API-Key": API_KEY})).status_code == 404
            spec = (await caller.get("/openapi.json")).json()
            assert spec["components"]["securitySchemes"]["APIKey"]["name"] == "X-API-Key"

        await auth._reporter.flush()
        await auth.aclose()
        await control.aclose()

    run(exercise())
    items = plane.usage_calls[0]["items"]
    assert {item["status_code"] for item in items} == {299, 404}
    assert all(
        set(item)
        == {
            "idempotency_key",
            "api_key_id",
            "status_code",
            "count",
            "period_start",
            "usage_policy_id",
        }
        for item in items
    )
    assert all(item["api_key_id"] == KEY_ID for item in items)
    assert all(item["usage_policy_id"] == POLICY_ID for item in items)


def test_vercel_flushes_after_the_response_only_when_the_batch_is_due(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VERCEL", "1")
    plane = ControlPlane(snapshot_payload())

    async def exercise() -> None:
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        app = FastAPI()
        auth = MicroAuth(
            app,
            secret_key=SECRET,
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
        )
        await auth._apply_snapshot(_parse_snapshot(plane.snapshot))
        auth._started = True

        @app.get("/protected")
        async def protected(customer: Customer = Security(auth)) -> dict[str, bool]:
            return {"ok": True}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as caller:
            response = await caller.get(
                "/protected",
                headers={"X-API-Key": API_KEY},
            )
            assert response.status_code == 200
            # One event is far below the 500 batch and the report interval
            # has not elapsed: it stays queued instead of shipping alone.
            assert plane.usage_calls == []
            assert auth._reporter.pending_items == 1

            # Simulate the report interval elapsing since the last flush;
            # the next response-bound check delivers the whole batch.
            auth._reporter._last_flush -= auth._reporter._interval + 1
            response = await caller.get(
                "/protected",
                headers={"X-API-Key": API_KEY},
            )
            assert response.status_code == 200
            assert len(plane.usage_calls) == 1
            # Both requests merged into one counted item covering the batch.
            assert len(plane.usage_calls[0]["items"]) == 1
            assert plane.usage_calls[0]["items"][0]["count"] == 2
            assert auth._reporter.pending_items == 0

        await auth.aclose()
        await control.aclose()

    run(exercise())


def test_trailing_flush_delivers_the_last_batch_without_further_traffic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VERCEL", "1")
    plane = ControlPlane(snapshot_payload())

    async def exercise() -> None:
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        app = FastAPI()
        auth = MicroAuth(
            app,
            secret_key=SECRET,
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
            report_interval=0.2,
            trailing_flush=True,
        )
        await auth._apply_snapshot(_parse_snapshot(plane.snapshot))
        auth._started = True

        @app.get("/protected")
        async def protected(customer: Customer = Security(auth)) -> dict[str, bool]:
            return {"ok": True}

        # Anchor the batching rule so none of the burst is due at response
        # time; only the trailing waiter can deliver it.
        auth._reporter._last_flush = time.monotonic()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as caller:
            responses = await asyncio.gather(
                *(caller.get("/protected", headers={"X-API-Key": API_KEY}) for _ in range(3))
            )
        assert [response.status_code for response in responses] == [200, 200, 200]
        # The burst was below the batch size and inside the interval, yet it
        # was delivered before the (still-active) invocations completed - no
        # further traffic was needed, and the waiter coalesced the burst into
        # one usage call.
        assert len(plane.usage_calls) == 1
        assert plane.usage_calls[0]["items"][0]["count"] == 3
        assert auth._reporter.pending_items == 0

        await auth.aclose()
        await control.aclose()

    run(exercise())


def test_trailing_flush_is_inert_off_serverless(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME", raising=False)
    auth = MicroAuth(
        secret_key=SECRET,
        persist_usage=False,
        trailing_flush=True,
    )
    # The background timer delivers batches here; the response path stays
    # untouched so callers never inherit a post-response hold.
    assert auth._trailing_flush is False
    assert auth._flush_on_response is False


def test_nonbillable_outcomes_release_money_but_consume_quota() -> None:
    plane = ControlPlane(
        snapshot_payload(
            statuses=[201],
            balance=10,
            price=10,
            billing_model="payg",
            quota=2,
        )
    )
    handled = 0

    async def exercise() -> None:
        nonlocal handled
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        app = FastAPI()
        auth = MicroAuth(
            app,
            secret_key=SECRET,
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
        )
        await auth._apply_snapshot(_parse_snapshot(plane.snapshot))
        auth._started = True

        @app.get("/nonbillable")
        async def nonbillable(customer: Customer = Security(auth)) -> dict[str, bool]:
            nonlocal handled
            handled += 1
            return {"ok": True}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as caller:
            responses = [
                await caller.get(
                    "/nonbillable",
                    headers={"X-API-Key": API_KEY},
                )
                for _ in range(3)
            ]
        assert [response.status_code for response in responses] == [200, 200, 429]
        assert responses[2].json()["detail"] == "Monthly request quota exceeded"
        await auth._reporter.flush()
        await auth.aclose()
        await control.aclose()

    run(exercise())
    assert handled == 2
    # Both served requests share one identity and merge into one counted item.
    assert len(plane.usage_calls[0]["items"]) == 1
    item = plane.usage_calls[0]["items"][0]
    assert item["status_code"] == 200
    assert item["count"] == 2


def test_nonbillable_outcome_does_not_release_platform_allowance() -> None:
    plane = ControlPlane(
        snapshot_payload(
            statuses=[201],
            platform_limit=1,
            quota=10,
        )
    )

    async def exercise() -> None:
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        app = FastAPI()
        auth = MicroAuth(
            app,
            secret_key=SECRET,
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
        )
        await auth._apply_snapshot(_parse_snapshot(plane.snapshot))
        auth._started = True

        @app.get("/nonbillable")
        async def nonbillable(customer: Customer = Security(auth)) -> dict[str, bool]:
            return {"ok": True}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as caller:
            first = await caller.get(
                "/nonbillable",
                headers={"X-API-Key": API_KEY},
            )
            second = await caller.get(
                "/nonbillable",
                headers={"X-API-Key": API_KEY},
            )
        assert first.status_code == 200
        assert second.status_code == 429
        assert second.json()["detail"] == ("Platform monthly request allowance exhausted")
        await auth._reporter.flush()
        await auth.aclose()
        await control.aclose()

    run(exercise())


def test_150_concurrent_requests_report_as_one_counted_item() -> None:
    plane = ControlPlane(
        snapshot_payload(
            statuses=[200],
            balance=1_000_000,
            price=10,
            billing_model="payg",
            quota=None,
        )
    )

    async def exercise() -> None:
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        app = FastAPI()
        auth = MicroAuth(
            app,
            secret_key=SECRET,
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
        )
        await auth._apply_snapshot(_parse_snapshot(plane.snapshot))
        auth._started = True

        @app.get("/protected")
        async def protected(customer: Customer = Security(auth)) -> dict[str, bool]:
            await asyncio.sleep(0)
            return {"ok": True}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as caller:
            responses = await asyncio.gather(
                *(
                    caller.get(
                        "/protected",
                        headers={"X-API-Key": API_KEY},
                    )
                    for _ in range(150)
                )
            )
        assert all(response.status_code == 200 for response in responses)
        assert auth._reporter.pending_requests == 150
        await auth._reporter.flush()
        assert auth._reporter.pending_items == 0
        await auth.aclose()
        await control.aclose()

    run(exercise())
    # A 150-request billable burst is one usage call with one counted item:
    # one receipt and one processing pass on the API, not 150.
    assert len(plane.usage_calls) == 1
    items = plane.usage_calls[0]["items"]
    assert len(items) == 1
    assert items[0]["count"] == 150
    assert items[0]["status_code"] == 200


def test_concurrent_requests_cannot_oversubscribe_customer_quota() -> None:
    plane = ControlPlane(snapshot_payload(quota=10, platform_limit=100))
    handled = 0

    async def exercise() -> list[int]:
        nonlocal handled
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        app = FastAPI()
        auth = MicroAuth(
            app,
            secret_key=SECRET,
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
        )
        await auth._apply_snapshot(_parse_snapshot(plane.snapshot))
        auth._started = True

        @app.get("/protected")
        async def protected(customer: Customer = Security(auth)) -> dict[str, bool]:
            nonlocal handled
            await asyncio.sleep(0)
            handled += 1
            return {"ok": True}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as caller:
            responses = await asyncio.gather(
                *(
                    caller.get(
                        "/protected",
                        headers={"X-API-Key": API_KEY},
                    )
                    for _ in range(100)
                )
            )
        await auth._reporter.flush()
        await auth.aclose()
        await control.aclose()
        return [response.status_code for response in responses]

    statuses = run(exercise())
    assert statuses.count(200) == 10
    assert statuses.count(429) == 90
    assert handled == 10


def test_snapshot_refresh_preserves_unacknowledged_local_usage() -> None:
    initial = snapshot_payload(
        statuses=[200],
        quota=2,
        platform_limit=2,
        balance=20,
        price=10,
        billing_model="payg",
    )
    plane = ControlPlane(initial)

    async def exercise() -> None:
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        app = FastAPI()
        auth = MicroAuth(
            app,
            secret_key=SECRET,
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
        )
        await auth._apply_snapshot(_parse_snapshot(initial))
        auth._started = True

        @app.get("/protected")
        async def protected(customer: Customer = Security(auth)) -> dict[str, bool]:
            return {"ok": True}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as caller:
            first = await caller.get(
                "/protected",
                headers={"X-API-Key": API_KEY},
            )
            assert first.status_code == 200
            unchanged = snapshot_payload(
                statuses=[200],
                quota=2,
                platform_limit=2,
                balance=20,
                price=10,
                billing_model="payg",
                generated_at=datetime.now(timezone.utc) + timedelta(seconds=1),
            )
            refreshed = _parse_snapshot(unchanged)
            await auth._limiter.sync_snapshot(auth._tenant_scope, refreshed)
            auth._snapshot = refreshed
            second = await caller.get(
                "/protected",
                headers={"X-API-Key": API_KEY},
            )
            third = await caller.get(
                "/protected",
                headers={"X-API-Key": API_KEY},
            )
        assert [first.status_code, second.status_code, third.status_code] == [
            200,
            200,
            429,
        ]
        await auth._reporter.flush()
        await auth.aclose()
        await control.aclose()

    run(exercise())


@pytest.mark.parametrize("status", [401, 403])
def test_authoritative_control_plane_denial_invalidates_cached_auth(status: int) -> None:
    plane = ControlPlane(snapshot_payload(), snapshot_status=status)

    async def exercise() -> None:
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        app = FastAPI()
        auth = MicroAuth(
            app,
            secret_key=SECRET,
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
        )
        await auth._apply_snapshot(_parse_snapshot(snapshot_payload()))
        auth._started = True
        with pytest.raises(MicroAuthAuthorizationError):
            await auth._refresh()

        @app.get("/protected")
        async def protected(customer: Customer = Security(auth)) -> dict[str, bool]:
            return {"ok": True}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as caller:
            response = await caller.get(
                "/protected",
                headers={"X-API-Key": API_KEY},
            )
        assert response.status_code == 503
        await auth.aclose()
        await control.aclose()

    run(exercise())
    assert plane.snapshot_calls == 1


def test_transient_snapshot_outage_keeps_fresh_cached_auth() -> None:
    plane = ControlPlane(snapshot_payload(), snapshot_status=503)

    async def exercise() -> None:
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        app = FastAPI()
        auth = MicroAuth(
            app,
            secret_key=SECRET,
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
        )
        await auth._apply_snapshot(_parse_snapshot(snapshot_payload(statuses=[])))
        auth._started = True
        with pytest.raises(MicroAuthAPIError):
            await auth._refresh()

        @app.get("/protected")
        async def protected(customer: Customer = Security(auth)) -> dict[str, bool]:
            return {"ok": True}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as caller:
            response = await caller.get(
                "/protected",
                headers={"X-API-Key": API_KEY},
            )
        assert response.status_code == 200
        plane.snapshot_status = 200
        await auth._reporter.flush()
        await auth.aclose()
        await control.aclose()

    run(exercise())
    assert plane.snapshot_calls == 3


def test_expired_usage_policy_refreshes_before_authorizing() -> None:
    expired = snapshot_payload(statuses=[])
    expired["customers"][0]["policy_valid_until"] = iso(
        datetime.now(timezone.utc) - timedelta(seconds=1)
    )
    plane = ControlPlane(snapshot_payload(statuses=[]))

    async def exercise() -> None:
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        app = FastAPI()
        auth = MicroAuth(
            app,
            secret_key=SECRET,
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
        )
        await auth._apply_snapshot(_parse_snapshot(expired))
        auth._started = True

        @app.get("/protected")
        async def protected(customer: Customer = Security(auth)) -> dict[str, bool]:
            return {"ok": True}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as caller:
            response = await caller.get(
                "/protected",
                headers={"X-API-Key": API_KEY},
            )
        assert response.status_code == 200
        await auth.aclose()
        await control.aclose()

    run(exercise())
    assert plane.snapshot_calls == 1


def test_expired_usage_policy_fails_closed_when_refresh_is_unavailable() -> None:
    expired = snapshot_payload(statuses=[])
    expired["customers"][0]["policy_valid_until"] = iso(
        datetime.now(timezone.utc) - timedelta(seconds=1)
    )
    plane = ControlPlane(snapshot_payload(statuses=[]), snapshot_status=503)

    async def exercise() -> None:
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        app = FastAPI()
        auth = MicroAuth(
            app,
            secret_key=SECRET,
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
        )
        await auth._apply_snapshot(_parse_snapshot(expired))
        auth._started = True

        @app.get("/protected")
        async def protected(customer: Customer = Security(auth)) -> dict[str, bool]:
            return {"ok": True}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as caller:
            responses = await asyncio.gather(
                *(
                    caller.get(
                        "/protected",
                        headers={"X-API-Key": API_KEY},
                    )
                    for _ in range(10)
                )
            )
        assert {response.status_code for response in responses} == {503}
        await auth.aclose()
        await control.aclose()

    run(exercise())
    assert plane.snapshot_calls == 3


def test_fail_open_has_an_absolute_stale_snapshot_bound() -> None:
    async def request_with_age(age: float) -> int:
        generated_at = datetime.now(timezone.utc) - timedelta(seconds=age)
        plane = ControlPlane(snapshot_payload(statuses=[], generated_at=generated_at))
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        app = FastAPI()
        auth = MicroAuth(
            app,
            secret_key=SECRET,
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
            max_snapshot_age=1,
            max_stale_snapshot_age=10,
            fail_open=True,
        )
        await auth._apply_snapshot(_parse_snapshot(plane.snapshot))
        auth._started = True

        @app.get("/protected")
        async def protected(customer: Customer = Security(auth)) -> dict[str, bool]:
            return {"ok": True}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as caller:
            response = await caller.get(
                "/protected",
                headers={"X-API-Key": API_KEY},
            )
        if response.status_code == 200:
            await auth._reporter.flush()
        await auth.aclose()
        await control.aclose()
        return response.status_code

    assert run(request_with_age(5)) == 200
    assert run(request_with_age(15)) == 503


OTHER_TENANT_ID = "1a7c3e5f-9b2d-4f4a-8c6e-8d3f2b5a7c91"


async def bind(
    secret: str,
    payload: dict[str, Any],
    **options: Any,
) -> tuple[MicroAuth, httpx.AsyncClient]:
    control = httpx.AsyncClient(transport=httpx.MockTransport(ControlPlane(payload)))
    auth = MicroAuth(secret_key=secret, http_client=control, **options)
    await auth._refresh()
    return auth, control


def test_queued_usage_belongs_to_the_api_not_the_secret(tmp_path: Path) -> None:
    async def placement(secret: str, tenant_id: str) -> tuple[str, Path | None]:
        auth, control = await bind(
            secret,
            snapshot_payload(tenant_id=tenant_id),
            journal_dir=tmp_path,
        )
        result = auth._tenant_scope, auth._reporter.journal_dir
        await auth.aclose()
        await control.aclose()
        return result

    rotated = "mas_" + "Rotated0" * 5
    original = run(placement(SECRET, TENANT_ID))
    # Rotating the secret keeps the same journal and Redis queue, so usage
    # queued before the rotation is still delivered after it.
    assert run(placement(rotated, TENANT_ID)) == original
    # Another API never shares (or adopts) this API's queued usage.
    other = run(placement(SECRET, OTHER_TENANT_ID))
    assert other[0] != original[0]
    assert other[1] != original[1]
    assert original[1] is not None and original[1].parent == tmp_path


def test_journal_directory_is_labelled_with_the_api_it_belongs_to(
    tmp_path: Path,
) -> None:
    from microauth_fastapi.journal import read_api_metadata

    async def exercise() -> Path | None:
        auth, control = await bind(SECRET, snapshot_payload(), journal_dir=tmp_path)
        directory = auth._reporter.journal_dir
        await auth.aclose()
        await control.aclose()
        return directory

    directory = run(exercise())
    assert directory is not None
    assert read_api_metadata(directory) == {
        "base_url": "https://api.microauth.com",
        "tenant_id": TENANT_ID,
        "tenant_name": "Weather API",
    }


def test_a_snapshot_for_a_different_api_is_refused() -> None:
    async def exercise() -> None:
        auth, control = await bind(SECRET, snapshot_payload(), persist_usage=False)
        assert auth.tenant_id == TENANT_ID
        assert auth.tenant_name == "Weather API"
        foreign = _parse_snapshot(snapshot_payload(tenant_id=OTHER_TENANT_ID))
        with pytest.raises(SnapshotValidationError, match="different MicroAuth API"):
            await auth._apply_snapshot(foreign)
        # The bound API's snapshot stays in place.
        assert auth._snapshot is not None
        assert auth._snapshot.tenant_id == TENANT_ID
        await auth.aclose()
        await control.aclose()

    run(exercise())


class Lifespan:
    """Runs an ASGI app's lifespan the way a server does."""

    def __init__(self, app: Any) -> None:
        self._app = app
        self._inbox: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._outbox: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._task: asyncio.Task[None] | None = None

    async def __aenter__(self) -> None:
        scope = {"type": "lifespan", "asgi": {"version": "3.0"}, "state": {}}
        self._task = asyncio.create_task(self._app(scope, self._inbox.get, self._outbox.put))
        await self._inbox.put({"type": "lifespan.startup"})
        assert (await self._outbox.get())["type"] == "lifespan.startup.complete"

    async def __aexit__(self, *exc_info: object) -> None:
        await self._inbox.put({"type": "lifespan.shutdown"})
        assert (await self._outbox.get())["type"] == "lifespan.shutdown.complete"
        assert self._task is not None
        await self._task


def test_the_sdk_is_ready_before_the_first_request(tmp_path: Path) -> None:
    plane = ControlPlane(snapshot_payload())

    async def exercise() -> None:
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        app = FastAPI()
        auth = MicroAuth(app, secret_key=SECRET, http_client=control, journal_dir=tmp_path)
        async with Lifespan(app):
            assert plane.snapshot_calls == 1
            assert auth.tenant_id == TENANT_ID
            assert auth.usage_stats().durability == "journal"
        await control.aclose()

    run(exercise())


def test_a_restarted_app_recovers_a_crashed_process_usage_without_traffic(
    tmp_path: Path,
) -> None:
    from microauth_fastapi.journal import JournalOp, WalJournal
    from microauth_fastapi.sdk import _stable_scope

    crashed = WalJournal(
        tmp_path / _stable_scope("https://api.microauth.com", TENANT_ID),
        max_items=100,
        grace_seconds=120,
    )
    hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    item = {
        "idempotency_key": "crashed-0001",
        "api_key_id": KEY_ID,
        "usage_policy_id": POLICY_ID,
        "status_code": 200,
        "count": 3,
        "period_start": iso(hour),
    }
    crashed.apply([JournalOp(op="create", event={"item": item, "attachments": []})], None)
    # The process was killed ten minutes ago, with no chance to hand it back.
    stale = time.time() - 600
    os.utime(crashed.path, (stale, stale))
    plane = ControlPlane(snapshot_payload())

    async def exercise() -> None:
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        app = FastAPI()
        auth = MicroAuth(
            app,
            secret_key=SECRET,
            http_client=control,
            journal_dir=tmp_path,
            report_interval=0.05,
        )
        async with Lifespan(app):
            for _ in range(250):
                if plane.usage_calls:
                    break
                await asyncio.sleep(0.02)
            assert plane.usage_calls, "the recovered usage waited for traffic"
        await control.aclose()
        stats = auth.usage_stats()
        assert stats.delivered_requests == 3
        assert stats.queued_items == 0

    run(exercise())
    (call,) = plane.usage_calls
    assert [(i["idempotency_key"], i["count"]) for i in call["items"]] == [("crashed-0001", 3)]


def test_api_client_classifies_auth_separately_without_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import microauth_fastapi.client as client_module

    monkeypatch.setattr(client_module, "_BACKOFF", 0)
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(401, text="invalid tenant secret")

    async def exercise() -> None:
        external = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        client = APIClient(
            "https://api.microauth.test",
            SECRET,
            1,
            http_client=external,
        )
        with pytest.raises(MicroAuthAuthorizationError):
            await client.snapshot()
        await client.aclose()
        assert external.is_closed is False
        await external.aclose()

    run(exercise())
    assert calls == 1


@pytest.mark.parametrize("status", [429, 503])
def test_api_client_retries_transient_control_plane_statuses(
    status: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import microauth_fastapi.client as client_module

    monkeypatch.setattr(client_module, "_BACKOFF", 0)
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(status, text="retry")

    async def exercise() -> None:
        external = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        client = APIClient(
            "https://api.microauth.test",
            SECRET,
            1,
            http_client=external,
        )
        with pytest.raises(MicroAuthAPIError) as caught:
            await client.snapshot()
        assert caught.value.status_code == status
        await external.aclose()

    run(exercise())
    assert calls == 3


def test_external_resources_are_not_closed() -> None:
    class ExternalRedis:
        def __init__(self) -> None:
            self.closed = False

        async def aclose(self) -> None:
            self.closed = True

    async def exercise() -> None:
        external_http = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json={}))
        )
        external_redis = ExternalRedis()
        auth = MicroAuth(
            secret_key=SECRET,
            http_client=external_http,
            redis_client=external_redis,
            persist_usage=False,
        )
        await auth.aclose()
        assert external_http.is_closed is False
        assert external_redis.closed is False
        await external_http.aclose()

    run(exercise())


@pytest.mark.parametrize(
    "secret",
    ["wrong", "mas_test", "mas_" + "a" * 31, "mas_" + "a" * 39 + "-", "MAS_" + "a" * 40],
)
def test_malformed_secrets_are_refused_before_any_request(secret: str) -> None:
    with pytest.raises(MicroAuthConfigurationError, match="Connect tab"):
        MicroAuth(secret_key=secret, persist_usage=False)


def test_configuration_errors_are_typed(tmp_path: Path) -> None:
    with pytest.raises(MicroAuthConfigurationError):
        MicroAuth(
            secret_key=SECRET,
            max_snapshot_age=10,
            max_stale_snapshot_age=5,
            persist_usage=False,
        )
    not_a_directory = tmp_path / "journal"
    not_a_directory.write_text("")
    with pytest.raises(MicroAuthConfigurationError, match="journal"):
        MicroAuth(secret_key=SECRET, journal_dir=not_a_directory)
    with pytest.raises(MicroAuthConfigurationError, match="on_receipts"):
        MicroAuth(secret_key=SECRET, persist_usage=False, on_receipts="print")  # type: ignore[arg-type]


def test_dependency_only_use_is_rejected_without_status_middleware() -> None:
    async def exercise() -> None:
        app = FastAPI()
        auth = MicroAuth(
            secret_key=SECRET,
            persist_usage=False,
            enforce_rps=False,
        )
        await auth._apply_snapshot(_parse_snapshot(snapshot_payload()))
        auth._started = True

        @app.get("/protected")
        async def protected(customer: Customer = Security(auth)) -> dict[str, bool]:
            return {"ok": True}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as caller:
            with pytest.raises(MicroAuthConfigurationError):
                await caller.get(
                    "/protected",
                    headers={"X-API-Key": API_KEY},
                )
        await auth.aclose()

    run(exercise())


def test_cancelled_finalization_releases_reservations() -> None:
    from microauth_fastapi.models import LimitReservation
    from microauth_fastapi.sdk import _RequestUsage

    released: list[Any] = []
    finalized: list[bool] = []
    record_started = asyncio.Event()

    class HangingReporter:
        async def record(self, *args: Any, **kwargs: Any) -> str:
            record_started.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        def release(self, reservation: Any) -> None:
            released.append(reservation)

    class RecordingLimiter:
        async def finalize_request(
            self,
            reservation: LimitReservation,
            *,
            billable: bool,
        ) -> None:
            finalized.append(billable)

    async def exercise() -> None:
        auth = MicroAuth(
            secret_key=SECRET,
            persist_usage=False,
            enforce_rps=False,
        )
        auth._reporter = HangingReporter()  # type: ignore[assignment]
        auth._limiter = RecordingLimiter()  # type: ignore[assignment]
        context = _RequestUsage(
            principal=Customer(
                id="customer-1",
                key_id=KEY_ID,
                status="active",
                billing_model="payg",
                rps=0,
                price_per_request_micro=25,
                monthly_quota=None,
                credit_balance_micro=1_000_000,
            ),
            billable_statuses=frozenset({200}),
            usage_policy_id=POLICY_ID,
            usage_reservation=object(),  # type: ignore[arg-type]
            limit_reservation=LimitReservation(
                token="token-1",
                tenant_scope="tenant-1",
                customer_id="customer-1",
                period_key="2026-08",
                period_end=datetime.now(timezone.utc) + timedelta(days=1),
                spend_micro=25,
            ),
            occurred_at=datetime.now(timezone.utc),
        )
        # Servers cancel the ASGI task on client disconnects and timeouts;
        # the cancellation lands inside the durable record await.
        task = asyncio.create_task(auth._finish_request(context, 200))
        await record_started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        # Let the shielded cleanup task run to completion.
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    run(exercise())
    # The queue reservation and the monetary hold were both returned; neither
    # can leak capacity or prepaid credit until a TTL.
    assert len(released) == 1
    assert finalized == [False]


def test_journal_failure_releases_the_billable_monetary_reservation() -> None:
    from microauth_fastapi.models import LimitReservation
    from microauth_fastapi.sdk import _RequestUsage

    finalize_calls: list[bool] = []

    class RecordingLimiter:
        async def finalize_request(
            self,
            reservation: LimitReservation,
            *,
            billable: bool,
        ) -> None:
            del reservation
            finalize_calls.append(billable)

    class FailingReporter:
        async def record(self, *args: Any, **kwargs: Any) -> str:
            raise RuntimeError("journal write failed")

        def release(self, reservation: Any) -> None:
            del reservation

    async def exercise() -> None:
        auth = MicroAuth(
            secret_key=SECRET,
            persist_usage=False,
            enforce_rps=False,
        )
        auth._reporter = FailingReporter()  # type: ignore[assignment]
        auth._limiter = RecordingLimiter()  # type: ignore[assignment]
        context = _RequestUsage(
            principal=Customer(
                id="customer-1",
                key_id=KEY_ID,
                status="active",
                billing_model="payg",
                rps=0,
                price_per_request_micro=25,
                monthly_quota=None,
                credit_balance_micro=1_000_000,
            ),
            billable_statuses=frozenset({200}),
            usage_policy_id=POLICY_ID,
            usage_reservation=object(),  # type: ignore[arg-type]
            limit_reservation=LimitReservation(
                token="token-1",
                tenant_scope="tenant-1",
                customer_id="customer-1",
                period_key="2026-08",
                period_end=datetime.now(timezone.utc) + timedelta(days=1),
                spend_micro=25,
            ),
            occurred_at=datetime.now(timezone.utc),
        )
        with pytest.raises(RuntimeError, match="journal write failed"):
            await auth._finish_request(context, 200)
        assert context.usage_reservation is None

    run(exercise())
    # The event was never journaled, so the monetary hold must be returned
    # rather than left waiting for an acknowledgement that cannot happen.
    assert finalize_calls == [False]


def test_usage_is_finalized_before_final_response_body() -> None:
    order: list[str] = []
    context = {"finished": False}

    class FakeAuth:
        async def _finish_request(
            self,
            value: dict[str, bool],
            status: int,
        ) -> str | None:
            if value["finished"]:
                return None
            value["finished"] = True
            order.append(f"finish-{status}")
            return "event-1"

        async def _flush_after_response(self, event_id: str | None) -> None:
            order.append(f"flush-{event_id}")

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 207, "headers": []})
        await send({"type": "http.response.body", "body": b"done"})

    async def exercise() -> None:
        middleware = _UsageMiddleware(inner, FakeAuth())

        async def receive() -> dict[str, Any]:
            return {"type": "http.disconnect"}

        async def send(message: dict[str, Any]) -> None:
            order.append(message["type"])

        await middleware(
            {
                "type": "http",
                "state": {_STATE_ATTR: context},
            },
            receive,
            send,
        )

    run(exercise())
    assert order == [
        "http.response.start",
        "finish-207",
        "http.response.body",
        "flush-event-1",
    ]


def test_usage_flush_falls_back_when_the_app_raises() -> None:
    order: list[str] = []
    context = {"finished": False}

    class FakeAuth:
        async def _finish_request(
            self,
            value: dict[str, bool],
            status: int,
        ) -> str | None:
            if value["finished"]:
                return None
            value["finished"] = True
            order.append(f"finish-{status}")
            return "event-error"

        async def _flush_after_response(self, event_id: str | None) -> None:
            order.append(f"flush-{event_id}")

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        raise RuntimeError("application failed")

    async def exercise() -> None:
        middleware = _UsageMiddleware(inner, FakeAuth())

        async def receive() -> dict[str, Any]:
            return {"type": "http.disconnect"}

        async def send(message: dict[str, Any]) -> None:
            raise AssertionError("the failing app must not send a response")

        with pytest.raises(RuntimeError, match="application failed"):
            await middleware(
                {
                    "type": "http",
                    "state": {_STATE_ATTR: context},
                },
                receive,
                send,
            )

    run(exercise())
    assert order == ["finish-500", "flush-event-error"]


def test_request_cancellation_does_not_cancel_post_response_delivery() -> None:
    context = {"finished": False}
    flush_started = asyncio.Event()
    allow_flush = asyncio.Event()
    flush_completed = False

    class FakeAuth:
        async def _finish_request(
            self,
            value: dict[str, bool],
            status: int,
        ) -> str | None:
            if value["finished"]:
                return None
            value["finished"] = True
            return "event-cancelled"

        async def _flush_after_response(self, event_id: str | None) -> None:
            nonlocal flush_completed
            assert event_id == "event-cancelled"
            flush_started.set()
            await allow_flush.wait()
            flush_completed = True

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"done"})

    async def exercise() -> None:
        middleware = _UsageMiddleware(inner, FakeAuth())

        async def receive() -> dict[str, Any]:
            return {"type": "http.disconnect"}

        async def send(message: dict[str, Any]) -> None:
            return None

        request = asyncio.create_task(
            middleware(
                {
                    "type": "http",
                    "state": {_STATE_ATTR: context},
                },
                receive,
                send,
            )
        )
        await flush_started.wait()
        request.cancel()
        await asyncio.sleep(0)
        assert not request.done()
        allow_flush.set()
        with pytest.raises(asyncio.CancelledError):
            await request

    run(exercise())
    assert flush_completed


def test_cancellation_after_journaling_recovers_the_event_for_fallback() -> None:
    context: dict[str, Any] = {"finished": False, "event_id": None}
    finalize_started = asyncio.Event()
    flush_completed = False

    class FakeAuth:
        async def _finish_request(
            self,
            value: dict[str, Any],
            status: int,
        ) -> str | None:
            if value["finished"]:
                return value["event_id"]
            value["finished"] = True
            value["event_id"] = "event-journaled"
            finalize_started.set()
            await asyncio.Event().wait()
            return value["event_id"]

        async def _flush_after_response(self, event_id: str | None) -> None:
            nonlocal flush_completed
            assert event_id == "event-journaled"
            flush_completed = True

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"done"})

    async def exercise() -> None:
        middleware = _UsageMiddleware(inner, FakeAuth())

        async def receive() -> dict[str, Any]:
            return {"type": "http.disconnect"}

        async def send(message: dict[str, Any]) -> None:
            return None

        request = asyncio.create_task(
            middleware(
                {
                    "type": "http",
                    "state": {_STATE_ATTR: context},
                },
                receive,
                send,
            )
        )
        await finalize_started.wait()
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request

    run(exercise())
    assert flush_completed


@pytest.mark.parametrize(
    ("status", "detail"),
    [
        ("pending", "This account is waiting for approval"),
        ("suspended", "This account is suspended"),
        ("closed", "This account is suspended"),
    ],
)
def test_customers_that_are_not_active_are_denied_with_their_reason(
    status: str,
    detail: str,
) -> None:
    other_key = f"map_{status}_customer"
    payload = snapshot_payload()
    payload["customers"].append(
        {
            **deepcopy(payload["customers"][0]),
            "id": "customer-2",
            "status": status,
        }
    )
    payload["keys"].append(
        {
            "id": "33333333-3333-4333-8333-333333333333",
            "customer_id": "customer-2",
            "key_hash": hashlib.sha256(other_key.encode()).hexdigest(),
        }
    )
    plane = ControlPlane(payload)

    async def exercise() -> None:
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        app = FastAPI()
        auth = MicroAuth(
            app,
            secret_key=SECRET,
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
        )
        await auth._apply_snapshot(_parse_snapshot(payload))
        auth._started = True

        @app.get("/protected")
        async def protected(customer: Customer = Security(auth)) -> dict[str, str]:
            return {"customer": customer.id}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as caller:
            active = await caller.get("/protected", headers={"X-API-Key": API_KEY})
            denied = await caller.get("/protected", headers={"X-API-Key": other_key})
        assert active.status_code == 200
        assert denied.status_code == 403
        assert denied.json()["detail"] == detail
        await auth.aclose()
        await control.aclose()

    run(exercise())


def test_api_client_sends_user_agent_and_revalidates_snapshots() -> None:
    from microauth_fastapi import __version__
    from microauth_fastapi.client import GENERATED_AT_HEADER

    body = snapshot_payload()
    later = iso(datetime.now(timezone.utc) + timedelta(seconds=5))
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.headers.get("If-None-Match") == '"snap-1"':
            return httpx.Response(304, headers={GENERATED_AT_HEADER: later})
        return httpx.Response(200, json=body, headers={"ETag": '"snap-1"'})

    async def exercise() -> None:
        external = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        client = APIClient("https://api.microauth.test", SECRET, 1, http_client=external)
        first = await client.snapshot()
        second = await client.snapshot()
        assert first == body
        assert second["generated_at"] == later
        assert second["customers"] == body["customers"]
        # The cached body is never handed out by reference.
        second["generated_at"] = "mutated"
        third = await client.snapshot()
        assert third["generated_at"] == later

        client.forget_snapshot()
        await client.snapshot()
        await external.aclose()

    run(exercise())
    assert seen[0].headers["User-Agent"].startswith(f"microauth-fastapi/{__version__} ")
    assert "If-None-Match" not in seen[0].headers
    assert seen[1].headers["If-None-Match"] == '"snap-1"'
    assert "If-None-Match" not in seen[3].headers


def test_verified_keys_never_mutate_a_published_snapshot() -> None:
    new_key = "map_verified_later"
    new_hash = hashlib.sha256(new_key.encode()).hexdigest()
    payload = snapshot_payload()
    verify_customer = {
        **deepcopy(payload["customers"][0]),
        "id": "customer-new",
        "balance_seq": 3,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/sdk/v1/keys/verify":
            return httpx.Response(
                200,
                json={
                    "valid": True,
                    "key_id": "44444444-4444-4444-8444-444444444444",
                    "customer": verify_customer,
                    "billable_status_codes": [200],
                },
            )
        return ControlPlane(payload)(request)

    async def exercise() -> None:
        control = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        auth = MicroAuth(
            FastAPI(),
            secret_key=SECRET,
            http_client=control,
            persist_usage=False,
        )
        published = _parse_snapshot(payload)
        published_keys = dict(published.keys)
        await auth._apply_snapshot(published)
        auth._started = True

        record = await auth._do_verify(new_hash)

        assert record is not None
        assert published.keys == published_keys
        assert "customer-new" not in published.customers
        assert auth._snapshot is not published
        assert auth._snapshot.keys[new_hash] == record
        assert auth._snapshot.customers["customer-new"].balance_seq == 3
        await auth.aclose()
        await control.aclose()

    run(exercise())
