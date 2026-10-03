from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import httpx
import pytest
from test_sdk import API_KEY, snapshot_payload

import microauth_fastapi.__main__ as cli
from microauth_fastapi import _env
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
    payload["tenant_name"] = "Weather API"
    install_plane(monkeypatch, lambda request: httpx.Response(200, json=payload))

    code, output = run_check("--key", API_KEY)

    assert code == 0, output
    assert "connected to Weather API" in output
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


def test_check_requires_a_tenant_secret(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MICROAUTH_SECRET_KEY", raising=False)
    out = io.StringIO()
    assert cli.main(["check"], out=out) == 1
    assert "MICROAUTH_SECRET_KEY is missing" in out.getvalue()


def test_check_reads_the_secret_from_a_dotenv_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / ".env").write_text(
        "# copied from the dashboard\nMICROAUTH_SECRET_KEY=mas_from_dotenv_9876\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MICROAUTH_SECRET_KEY", raising=False)
    monkeypatch.delenv("MICROAUTH_BASE_URL", raising=False)
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["authorization"])
        return httpx.Response(200, json=snapshot_payload())

    install_plane(monkeypatch, handler)
    out = io.StringIO()

    assert cli.main(["check"], out=out) == 0, out.getvalue()
    assert "mas_...9876 (from .env)" in out.getvalue()
    assert seen == ["Bearer mas_from_dotenv_9876"]


def test_dotenv_parsing_matches_what_people_paste() -> None:
    lines = [
        "OTHER_SECRET=ignored",
        "export MICROAUTH_SECRET_KEY='mas_quoted'",
        'MICROAUTH_BASE_URL="http://127.0.0.1:8080"',
        "MICROAUTH_REDIS_URL=redis://localhost:6379/0  # shared limits",
        "MICROAUTH_USAGE_SPOOL_PATH=  # paste the full key that starts with mas_",
        "not a line",
    ]
    values = _env._parse("\n".join(lines))
    assert values == {
        "MICROAUTH_SECRET_KEY": "mas_quoted",
        "MICROAUTH_BASE_URL": "http://127.0.0.1:8080",
        "MICROAUTH_REDIS_URL": "redis://localhost:6379/0",
        "MICROAUTH_USAGE_SPOOL_PATH": "",
    }


def test_the_real_environment_wins_over_dotenv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / ".env").write_text("MICROAUTH_SECRET_KEY=mas_file\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MICROAUTH_SECRET_KEY", "mas_env")
    assert _env.getenv("MICROAUTH_SECRET_KEY") == "mas_env"
    assert not _env.from_dotenv("MICROAUTH_SECRET_KEY")
    monkeypatch.delenv("MICROAUTH_SECRET_KEY")
    assert _env.getenv("MICROAUTH_SECRET_KEY") == "mas_file"
    assert _env.from_dotenv("MICROAUTH_SECRET_KEY")
