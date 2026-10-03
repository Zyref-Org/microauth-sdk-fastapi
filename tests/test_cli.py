from __future__ import annotations

import io
from typing import Any

import httpx
import pytest
from test_sdk import API_KEY, snapshot_payload

import microauth_fastapi.__main__ as cli
from microauth_fastapi.client import APIClient


def install_plane(
    monkeypatch: pytest.MonkeyPatch,
    handler: Any,
) -> None:
    def factory(base_url: str, secret: str, timeout: float) -> APIClient:
        return APIClient(
            base_url,
            secret,
            timeout,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )

    monkeypatch.setattr(cli, "APIClient", factory)
    monkeypatch.delenv("MICROAUTH_REDIS_URL", raising=False)


def run_check(*args: str) -> tuple[int, str]:
    out = io.StringIO()
    code = cli.main(["check", "--secret-key", "mas_test_1234", *args], out=out)
    return code, out.getvalue()


def test_check_reports_a_healthy_integration_and_explains_a_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = snapshot_payload(price=1_000, billing_model="payg", balance=5_000, quota=100)
    install_plane(monkeypatch, lambda request: httpx.Response(200, json=payload))

    code, output = run_check("--key", API_KEY)

    assert code == 0, output
    assert "snapshot loaded: 1 customer(s), 1 key(s)" in output
    assert "price per billable request: $0.001" in output
    assert "a request with this key would be allowed" in output
    assert "Everything looks good" in output


def test_check_explains_why_a_key_would_get_402(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = snapshot_payload(price=1_000, billing_model="payg", balance=0)
    install_plane(monkeypatch, lambda request: httpx.Response(200, json=payload))

    code, output = run_check("--key", API_KEY)

    assert code == 1
    assert "requests get 402" in output


def test_check_reports_a_rejected_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    install_plane(monkeypatch, lambda request: httpx.Response(401, text="bad secret"))

    code, output = run_check()

    assert code == 1
    assert "rejected this secret" in output


def test_check_requires_a_tenant_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MICROAUTH_SECRET_KEY", raising=False)
    out = io.StringIO()
    assert cli.main(["check"], out=out) == 1
    assert "MICROAUTH_SECRET_KEY is missing" in out.getvalue()
