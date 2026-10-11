from __future__ import annotations

import io
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
from support import POLICY_ID, SECRET, TENANT_ID
from test_sdk import API_KEY, KEY_ID, iso, snapshot_payload

import microauth_fastapi.__main__ as cli
from microauth_fastapi import _env
from microauth_fastapi.client import GENERATED_AT_HEADER, APIClient
from microauth_fastapi.journal import JournalOp, WalJournal, write_api_metadata
from microauth_fastapi.sdk import _stable_scope

BASE_URL = "https://api.microauth.com"
CURRENT_HOUR = iso(datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0))


def install_plane(
    monkeypatch: pytest.MonkeyPatch,
    handler: Any,
) -> None:
    def factory(base_url: str, secret: str, timeout: float, **options: Any) -> APIClient:
        return APIClient(
            base_url,
            secret,
            timeout,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            **options,
        )

    monkeypatch.setattr(cli, "APIClient", factory)


def serve(payload: dict[str, Any]) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=payload,
            headers={GENERATED_AT_HEADER: payload["generated_at"]},
        )

    return handler


def run_cli(*args: str) -> tuple[int, str]:
    out = io.StringIO()
    code = cli.main(list(args), out=out)
    return code, out.getvalue()


def run_check(*args: str) -> tuple[int, str]:
    return run_cli("check", "--secret-key", SECRET, *args)


def queued_event(key: str, count: int = 1) -> dict[str, Any]:
    return {
        "item": {
            "idempotency_key": key,
            "api_key_id": KEY_ID,
            "usage_policy_id": POLICY_ID,
            "status_code": 200,
            "count": count,
            "period_start": CURRENT_HOUR,
            "unit_charge_micro": 1_000,
            "queued_at": datetime.now(timezone.utc).timestamp() - 90,
        },
        "attachments": [],
    }


def seed_journal(base: Path, *, tenant_id: str = TENANT_ID, name: str = "Weather API") -> Path:
    directory = base / _stable_scope(BASE_URL, tenant_id)
    write_api_metadata(
        directory,
        {"base_url": BASE_URL, "tenant_id": tenant_id, "tenant_name": name},
    )
    journal = WalJournal(directory, max_items=100, grace_seconds=60)
    journal.apply(
        [
            JournalOp(op="create", event=queued_event("queued-1", count=3)),
            JournalOp(
                op="dead",
                event_id="refused-1",
                event=queued_event("refused-1", count=2),
                detail="period_start is outside the usage policy's validity",
                http_status=422,
                rejected_at=datetime.now(timezone.utc).timestamp(),
            ),
        ],
        None,
    )
    return directory


# ------------------------------------------------------------------- check


def test_check_reports_a_healthy_integration_and_explains_a_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload = snapshot_payload(price=1_000, billing_model="payg", balance=5_000, quota=100)
    install_plane(monkeypatch, serve(payload))

    code, output = run_check("--key", API_KEY, "--journal-dir", str(tmp_path))

    assert code == 0, output
    assert f"connected to Weather API ({TENANT_ID})" in output
    assert "snapshot loaded: 1 customer(s), 1 key(s)" in output
    assert "clock agrees with MicroAuth within" in output
    assert "price per billable request: $0.001" in output
    assert "a request with this key would be allowed" in output
    assert "journal directory is writable" in output
    assert "Everything looks good" in output


def test_check_explains_why_a_key_would_get_402(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = snapshot_payload(price=1_000, billing_model="payg", balance=0)
    install_plane(monkeypatch, serve(payload))

    code, output = run_check("--key", API_KEY)

    assert code == 1
    assert "requests get 402" in output


def test_check_explains_a_customer_waiting_for_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = snapshot_payload()
    payload["customers"][0]["status"] = "pending"
    install_plane(monkeypatch, serve(payload))

    code, output = run_check("--key", API_KEY)

    assert code == 1
    assert "waiting for approval, so requests get 403" in output
    assert "Approve them on the Customers page" in output


def test_check_warns_when_this_clock_disagrees_with_microauth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = snapshot_payload(generated_at=datetime.now(timezone.utc) + timedelta(seconds=30))
    install_plane(monkeypatch, serve(payload))

    code, output = run_check()

    assert code == 0, output
    assert "clock is 30" in output
    assert "behind MicroAuth's" in output


def test_check_reports_queued_and_refused_usage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    seed_journal(tmp_path)
    install_plane(monkeypatch, serve(snapshot_payload()))

    code, output = run_check("--journal-dir", str(tmp_path))

    assert code == 0, output
    assert "1 item(s) covering 3 request(s) are queued for delivery" in output
    assert "MicroAuth refused 1 usage item(s)" in output
    assert "python -m microauth_fastapi usage" in output


def test_check_reports_a_rejected_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    install_plane(
        monkeypatch,
        lambda request: httpx.Response(
            401,
            json={"title": "Unauthorized", "status": 401, "detail": "invalid SDK secret"},
            headers={"Content-Type": "application/problem+json"},
        ),
    )

    code, output = run_check()

    assert code == 1
    assert "MicroAuth rejected this secret (invalid SDK secret)" in output
    assert "Connect tab" in output


def test_check_requires_an_sdk_secret(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    code, output = run_cli("check")
    assert code == 1
    assert "MICROAUTH_SECRET_KEY is missing" in output
    assert f"Help: {cli.TROUBLESHOOTING_URL}" in output

    code, output = run_cli("check", "--secret-key", "mas_short")
    assert code == 1
    assert "is not an SDK secret" in output


def test_check_reads_the_secret_from_a_dotenv_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    secret = "mas_" + "FromDotenv" * 3 + "9876"
    (tmp_path / ".env").write_text(
        f"# copied from the dashboard\nMICROAUTH_SECRET_KEY={secret}\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["authorization"])
        return serve(snapshot_payload())(request)

    install_plane(monkeypatch, handler)

    code, output = run_cli("check")
    assert code == 0, output
    assert "SDK secret mas_...9876 (from .env)" in output
    assert seen == [f"Bearer {secret}"]


def test_dotenv_parsing_matches_what_people_paste() -> None:
    lines = [
        "OTHER_SECRET=ignored",
        "export MICROAUTH_SECRET_KEY='mas_quoted'",
        'MICROAUTH_BASE_URL="http://127.0.0.1:8080"',
        "MICROAUTH_REDIS_URL=redis://localhost:6379/0  # shared limits",
        "MICROAUTH_JOURNAL_DIR=  # a persistent directory",
        "not a line",
    ]
    values = _env._parse("\n".join(lines))
    assert values == {
        "MICROAUTH_SECRET_KEY": "mas_quoted",
        "MICROAUTH_BASE_URL": "http://127.0.0.1:8080",
        "MICROAUTH_REDIS_URL": "redis://localhost:6379/0",
        "MICROAUTH_JOURNAL_DIR": "",
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


# ------------------------------------------------------------------- usage


def test_usage_lists_queued_and_refused_items_for_this_api(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    seed_journal(tmp_path)
    seed_journal(tmp_path, tenant_id="1a7c3e5f-9b2d-4f4a-8c6e-8d3f2b5a7c91", name="Other API")
    install_plane(monkeypatch, serve(snapshot_payload()))

    code, output = run_cli("usage", "--secret-key", SECRET, "--journal-dir", str(tmp_path))

    assert code == 0, output
    assert f"Weather API ({TENANT_ID})" in output
    assert "Other API" not in output
    assert "queued in the journal: 1 item(s) covering 3 request(s)" in output
    assert "refused by MicroAuth (journal): 1 item(s)" in output
    assert "HTTP 422" in output
    assert "period_start is outside the usage policy's validity" in output
    assert f"item refused-1, key {KEY_ID}" in output
    assert cli.USAGE_DOCS_URL in output


def test_usage_json_is_machine_readable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    seed_journal(tmp_path)
    install_plane(monkeypatch, serve(snapshot_payload()))

    code, output = run_cli(
        "usage", "--json", "--secret-key", SECRET, "--journal-dir", str(tmp_path)
    )

    assert code == 0, output
    report = json.loads(output)
    assert report["lookup_error"] is None
    (api,) = report["apis"]
    assert api["tenant_id"] == TENANT_ID
    journal = api["journal"]
    assert (journal["queued_items"], journal["queued_requests"]) == (1, 3)
    assert journal["oldest_queued_at"].endswith("Z")
    (letter,) = journal["dead_letters"]
    assert letter == {
        "idempotency_key": "refused-1",
        "rejected_at": letter["rejected_at"],
        "http_status": 422,
        "detail": "period_start is outside the usage policy's validity",
        "api_key_id": KEY_ID,
        "usage_policy_id": POLICY_ID,
        "status_code": 200,
        "count": 2,
        "period_start": CURRENT_HOUR,
        "unit_charge_micro": 1_000,
    }


def test_usage_works_offline_from_the_directory_labels(tmp_path: Path) -> None:
    seed_journal(tmp_path)
    seed_journal(tmp_path, tenant_id="1a7c3e5f-9b2d-4f4a-8c6e-8d3f2b5a7c91", name="Other API")

    code, output = run_cli("usage", "--journal-dir", str(tmp_path))

    assert code == 0, output
    assert "No SDK secret was given" in output
    assert "Weather API" in output
    assert "Other API" in output


def test_usage_still_reports_when_microauth_is_unreachable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import microauth_fastapi.client as client_module

    monkeypatch.setattr(client_module, "_BACKOFF", 0)
    seed_journal(tmp_path)

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    install_plane(monkeypatch, down)

    code, output = run_cli("usage", "--secret-key", SECRET, "--journal-dir", str(tmp_path))

    assert code == 0, output
    assert "MicroAuth could not be reached" in output
    assert "Weather API" in output


def test_usage_with_an_empty_journal_says_so(tmp_path: Path) -> None:
    code, output = run_cli("usage", "--journal-dir", str(tmp_path))
    assert code == 0
    assert "No usage journals found" in output


def test_usage_rejects_a_zero_limit() -> None:
    with pytest.raises(SystemExit) as caught:
        run_cli("usage", "--limit", "0")
    assert caught.value.code == 2
