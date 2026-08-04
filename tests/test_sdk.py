from __future__ import annotations

import asyncio
import hashlib
import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, HTTPException, Response, Security

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
    tenant_id: str | None = None,
) -> dict[str, Any]:
    generated_at = generated_at or datetime.now(timezone.utc)
    period_end = datetime(
        generated_at.year + int(generated_at.month == 12),
        1 if generated_at.month == 12 else generated_at.month + 1,
        1,
        tzinfo=timezone.utc,
    )
    payload: dict[str, Any] = {
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
    if tenant_id is not None:
        payload["tenant_id"] = tenant_id
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
                    "results": [
                        {
                            "idempotency_key": item["idempotency_key"],
                            "status": "accepted",
                        }
                        for item in body["items"]
                    ],
                },
            )
        raise AssertionError(f"unexpected control-plane path {request.url.path}")


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
            secret_key="mas_test",
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
        )
        auth._snapshot = _parse_snapshot(plane.snapshot)
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
            assert (
                await caller.get("/custom", headers={"X-API-Key": API_KEY})
            ).status_code == 299
            assert (
                await caller.get("/missing", headers={"X-API-Key": API_KEY})
            ).status_code == 404
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
            secret_key="mas_test",
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
        )
        auth._snapshot = _parse_snapshot(plane.snapshot)
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
    assert len(plane.usage_calls[0]["items"]) == 2
    assert all(
        item["status_code"] == 200 and item["count"] == 1
        for item in plane.usage_calls[0]["items"]
    )


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
            secret_key="mas_test",
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
        )
        auth._snapshot = _parse_snapshot(plane.snapshot)
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
        assert second.json()["detail"] == (
            "Platform monthly request allowance exhausted"
        )
        await auth._reporter.flush()
        await auth.aclose()
        await control.aclose()

    run(exercise())


def test_concurrent_requests_cannot_oversubscribe_customer_quota() -> None:
    plane = ControlPlane(snapshot_payload(quota=10, platform_limit=100))
    handled = 0

    async def exercise() -> list[int]:
        nonlocal handled
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        app = FastAPI()
        auth = MicroAuth(
            app,
            secret_key="mas_test",
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
        )
        auth._snapshot = _parse_snapshot(plane.snapshot)
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
            secret_key="mas_test",
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
        )
        auth._snapshot = _parse_snapshot(initial)
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
            secret_key="mas_test",
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
        )
        auth._snapshot = _parse_snapshot(snapshot_payload())
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
            secret_key="mas_test",
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
        )
        auth._snapshot = _parse_snapshot(snapshot_payload(statuses=[]))
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
            secret_key="mas_test",
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
        )
        auth._snapshot = _parse_snapshot(expired)
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
            secret_key="mas_test",
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
        )
        auth._snapshot = _parse_snapshot(expired)
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
            secret_key="mas_test",
            http_client=control,
            persist_usage=False,
            enforce_rps=False,
            max_snapshot_age=1,
            max_stale_snapshot_age=10,
            fail_open=True,
        )
        auth._snapshot = _parse_snapshot(plane.snapshot)
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


def test_stable_tenant_identifier_survives_secret_rotation() -> None:
    payload = snapshot_payload(tenant_id="tenant-stable-id")

    async def scope(secret: str) -> str:
        plane = ControlPlane(payload)
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        auth = MicroAuth(
            secret_key=secret,
            http_client=control,
            persist_usage=False,
        )
        await auth._refresh()
        result = auth._tenant_scope
        await auth.aclose()
        await control.aclose()
        return result

    assert run(scope("mas_old")) == run(scope("mas_rotated"))


def test_stable_tenant_identifier_selects_same_default_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import microauth_fastapi.sdk as sdk_module

    monkeypatch.setattr(sdk_module.tempfile, "gettempdir", lambda: str(tmp_path))
    payload = snapshot_payload(tenant_id="tenant-stable-id")

    async def journal(secret: str) -> Path | None:
        plane = ControlPlane(payload)
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        auth = MicroAuth(
            secret_key=secret,
            http_client=control,
            persist_usage=True,
        )
        await auth._refresh()
        result = auth._reporter.spool_path
        await auth.aclose()
        await control.aclose()
        return result

    assert run(journal("mas_old")) == run(journal("mas_rotated"))


def test_explicit_persistence_namespace_is_stable_without_api_field() -> None:
    first = MicroAuth(
        secret_key="mas_old",
        persistence_namespace="tenant-stable-id",
        persist_usage=False,
    )
    second = MicroAuth(
        secret_key="mas_new",
        persistence_namespace="tenant-stable-id",
        persist_usage=False,
    )
    assert first._tenant_scope == second._tenant_scope
    run(first.aclose())
    run(second.aclose())


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
            "mas_test",
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
            "mas_test",
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
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={})
            )
        )
        external_redis = ExternalRedis()
        auth = MicroAuth(
            secret_key="mas_test",
            http_client=external_http,
            redis_client=external_redis,
            persist_usage=False,
        )
        await auth.aclose()
        assert external_http.is_closed is False
        assert external_redis.closed is False
        await external_http.aclose()

    run(exercise())


def test_configuration_errors_are_typed(tmp_path: Path) -> None:
    with pytest.raises(MicroAuthConfigurationError):
        MicroAuth(secret_key="wrong", persist_usage=False)
    with pytest.raises(MicroAuthConfigurationError):
        MicroAuth(
            secret_key="mas_test",
            max_snapshot_age=10,
            max_stale_snapshot_age=5,
            persist_usage=False,
        )
    with pytest.raises(MicroAuthConfigurationError):
        MicroAuth(
            secret_key="mas_test",
            persistence_namespace="",
            usage_spool_path=tmp_path / "usage.sqlite3",
        )


def test_dependency_only_use_is_rejected_without_status_middleware() -> None:
    async def exercise() -> None:
        app = FastAPI()
        auth = MicroAuth(
            secret_key="mas_test",
            persist_usage=False,
            enforce_rps=False,
        )
        auth._snapshot = _parse_snapshot(snapshot_payload())
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


def test_usage_is_finalized_before_final_response_body() -> None:
    order: list[str] = []
    context = {"finished": False}

    class FakeAuth:
        async def _finish_request(self, value: dict[str, bool], status: int) -> None:
            if value["finished"]:
                return
            value["finished"] = True
            order.append(f"finish-{status}")

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
    ]
