"""The API key fixtures the platform must emit, parsed through the SDK's real code paths.

Each fixture is served byte for byte by the fake issuer, then read by
``TokenAuth`` or ``auth.api_keys`` exactly as a live answer would be. The
platform's tests keep their copies in ``testdata/sdk-contract`` and must match.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import Depends, FastAPI, Request
from oidc_fake import (
    ACCOUNT_API,
    API,
    APP_URL,
    CLIENT_ID,
    CLIENT_SECRET,
    COOKIE_SECRET,
    MCP,
    MCP_CLIENT_ID,
    RESOURCE_CLIENT_ID,
    RESOURCE_SECRET,
    Clock,
    FakeIssuer,
    make_key,
    sign_in,
)

from microauth_fastapi import (
    AccountAPIError,
    APIKey,
    MicroAuthResponseError,
    TokenAuth,
    TokenClaims,
    UserAuth,
)
from microauth_fastapi._keys import display_prefix, key_problem

CONTRACT_DIR = Path(__file__).parent / "contract"
PLATFORM_CONTRACT_DIR = (
    Path(__file__).resolve().parents[3]
    / "app"
    / "internal"
    / "server"
    / "testdata"
    / "sdk-contract"
)
FIXTURES = [
    "introspect_key_active.json",
    "introspect_key_no_expiry.json",
    "introspect_inactive.json",
    "account_key_options.json",
    "account_keys.json",
    "account_key_created.json",
    "account_key.json",
    "account_problem.json",
]
# 2026-10-14T14:00:00Z, a day after the active key was made.
NOW = 1_791_986_400
KEY_ID = "5f0c9a7e-3b2d-4c1e-9a8f-6d4b2e1c0a97"
NO_EXPIRY_KEY_ID = "e7a3d9c1-2b4f-4e6a-9c8d-0f1b3a5c7e92"
OWNER = "8d2f6b1a-4c3e-4f5a-9b7d-1e0c2a4f6d83"
APP_CLIENT_ID = "3f9a1c7e-6b2d-4e8f-a051-9c7d2b4e6f18"
SAME_SITE = {"Origin": APP_URL}


def raw(name: str) -> bytes:
    return (CONTRACT_DIR / name).read_bytes()


def load(name: str) -> Any:
    return json.loads(raw(name))


def run(test: Callable[[], Any]) -> None:
    asyncio.run(test())


def fixture_response(status: int, body: bytes, **headers: str) -> httpx.Response:
    return httpx.Response(
        status, content=body, headers={"Content-Type": "application/json", **headers}
    )


# Introspection


def key_api(
    fake: FakeIssuer, answer: bytes, resource: str = API, client_id: str = RESOURCE_CLIENT_ID
) -> tuple[FastAPI, TokenAuth]:
    async def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/oauth/introspect":
            fake.introspections.append({"token": "seen"})
            return fixture_response(200, answer, **{"Cache-Control": "private, max-age=60"})
        return await fake.handle(request)

    app = FastAPI()
    api = TokenAuth(
        app,
        issuer=fake.issuer,
        resource=resource,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
        api_keys=True,
        resource_client_id=client_id,
        resource_secret=RESOURCE_SECRET,
    )
    assert api.key_checks is not None
    api.key_checks.clock = Clock(NOW)

    @app.get("/me")
    async def me(token: TokenClaims = Depends(api.require())) -> dict[str, Any]:
        return {
            "sub": token.sub,
            "via": token.via,
            "key_id": token.key_id,
            "client_id": token.client_id,
            "scopes": sorted(token.scopes),
            "issuer": token.issuer,
            "audience": list(token.audience),
            "issued_at": token.issued_at,
            "expires_at": token.expires_at,
        }

    return app, api


async def call(app: FastAPI, key: str, base_url: str = API) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=base_url) as client:
        return await client.get("/me", headers={"Authorization": f"Bearer {key}"})


def test_the_active_fixture_is_an_api_key_caller() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, api = key_api(fake, raw("introspect_key_active.json"))
        response = await call(app, make_key())
        assert response.status_code == 200, response.text
        assert response.json() == {
            "sub": OWNER,
            "via": "api_key",
            "key_id": KEY_ID,
            "client_id": None,
            "scopes": ["posts:read", "posts:write"],
            "issuer": "https://auth.example.com",
            "audience": [API, MCP],
            "issued_at": 1_791_900_000,
            "expires_at": 1_799_676_000,
        }
        assert api.key_checks is not None
        answer = await api.key_checks.introspector.check(make_key())
        assert answer.requests_per_minute == 120

    run(main)


def test_the_active_fixture_also_works_at_the_mcp_server_it_names() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = key_api(fake, raw("introspect_key_active.json"), MCP, MCP_CLIENT_ID)
        response = await call(app, make_key(), "https://mcp.example.com")
        assert response.status_code == 200
        assert response.json()["key_id"] == KEY_ID

    run(main)


def test_the_no_expiry_fixture_has_no_expiry_or_limit() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, api = key_api(fake, raw("introspect_key_no_expiry.json"))
        response = await call(app, make_key())
        assert response.status_code == 200, response.text
        assert response.json()["expires_at"] is None
        assert response.json()["audience"] == [API]
        assert response.json()["key_id"] == NO_EXPIRY_KEY_ID
        assert response.json()["scopes"] == ["posts:read"]
        assert api.key_checks is not None
        answer = await api.key_checks.introspector.check(make_key())
        assert answer.requests_per_minute is None

    run(main)


def test_the_inactive_fixture_is_refused() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = key_api(fake, raw("introspect_inactive.json"))
        response = await call(app, make_key())
        assert response.status_code == 401
        assert response.json()["detail"] == "The API key is unknown, revoked or expired"

    run(main)


def test_the_active_fixture_is_refused_at_an_api_it_doesnt_name() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.resource_clients[RESOURCE_CLIENT_ID] = "https://billing.example.com"
        app, _ = key_api(fake, raw("introspect_key_active.json"), "https://billing.example.com")
        response = await call(app, make_key(), "https://billing.example.com")
        assert response.status_code == 401

    run(main)


@pytest.mark.parametrize("member", ["token_use", "key_id", "sub", "scope", "aud", "iss", "iat"])
def test_an_active_answer_missing_a_required_member_is_refused(member: str) -> None:
    async def main() -> None:
        document = load("introspect_key_active.json")
        del document[member]
        app, _ = key_api(FakeIssuer(), json.dumps(document).encode())
        assert (await call(app, make_key())).status_code == 401

    run(main)


def test_an_answer_without_active_is_an_outage() -> None:
    async def main() -> None:
        document = load("introspect_key_active.json")
        del document["active"]
        app, _ = key_api(FakeIssuer(), json.dumps(document).encode())
        assert (await call(app, make_key())).status_code == 503

    run(main)


def test_the_optional_members_are_optional() -> None:
    async def main() -> None:
        document = load("introspect_key_active.json")
        del document["exp"], document["requests_per_minute"]
        document["scope"] = ""
        app, _ = key_api(FakeIssuer(), json.dumps(document).encode())
        response = await call(app, make_key())
        assert response.status_code == 200
        assert response.json()["scopes"] == []
        assert response.json()["expires_at"] is None

    run(main)


# Account API


def account_app(fake: FakeIssuer) -> tuple[FastAPI, dict[str, Any]]:
    app = FastAPI()
    auth = UserAuth(
        app,
        issuer=fake.issuer,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        cookie_secret=COOKIE_SECRET,
        app_url=APP_URL,
        http_client=fake.client(),
        api_keys=True,
    )
    results: dict[str, Any] = {}

    @app.post("/run/{name}")
    async def run_helper(request: Request, name: str) -> dict[str, Any]:
        keys = auth.api_keys
        if name == "options":
            results[name] = await keys.options(request)
        elif name == "list":
            results[name] = await keys.list(request)
        elif name == "create":
            results[name] = await keys.create(
                request,
                name="Zapier",
                resources=[API],
                permissions=["posts:read"],
                expires_in_days=90,
            )
        elif name == "rename":
            results[name] = await keys.rename(request, NO_EXPIRY_KEY_ID, "Backup script")
        elif name == "roll":
            results[name] = await keys.roll(request, KEY_ID, old_secret_lasts_hours=24)
        return {}

    return app, results


async def run_helper(
    fake: FakeIssuer, name: str, canned: dict[tuple[str, str], httpx.Response]
) -> Any:
    app, results = account_app(fake)
    fake.account_canned.update(canned)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=APP_URL) as client:
        await sign_in(client, fake)
        response = await client.post(f"/run/{name}", headers=SAME_SITE)
        assert response.status_code == 200, response.text
    return results[name]


def utc(*parts: int) -> datetime:
    return datetime(*parts, tzinfo=timezone.utc)  # type: ignore[misc]


def test_the_options_fixture() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        canned = {
            ("GET", f"{ACCOUNT_API}/options"): fixture_response(
                200, raw("account_key_options.json")
            )
        }
        options = await run_helper(fake, "options", canned)
        assert options.max_days == 365
        assert options.allow_no_expiry is False
        assert [resource.identifier for resource in options.resources] == [API, MCP]
        assert [resource.name for resource in options.resources] == ["Blog API", "Blog MCP server"]
        blog = options.resources[0]
        assert [(p.name, p.sensitive) for p in blog.permissions] == [
            ("posts:read", False),
            ("posts:write", False),
            ("posts:delete", True),
        ]
        assert blog.permissions[2].description == "Delete posts for good"

    run(main)


def test_the_keys_fixture() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        canned = {("GET", ACCOUNT_API): fixture_response(200, raw("account_keys.json"))}
        keys = await run_helper(fake, "list", canned)
        assert [key.id for key in keys] == [KEY_ID, NO_EXPIRY_KEY_ID]
        rolled, plain = keys
        assert isinstance(rolled, APIKey)
        assert rolled.name == "CI deploys"
        assert rolled.prefix == "cms_D0rlAD"
        assert [(r.identifier, r.name) for r in rolled.resources] == [
            (API, "Blog API"),
            (MCP, "Blog MCP server"),
        ]
        assert rolled.permissions == ("posts:read", "posts:write")
        assert rolled.created_at == utc(2026, 10, 13, 14)
        assert rolled.created_by_app is not None
        assert rolled.created_by_app.client_id == APP_CLIENT_ID
        assert rolled.created_by_app.name == "Blog CMS"
        assert rolled.expires_at == utc(2027, 1, 11, 14)
        assert rolled.last_used_at == utc(2026, 10, 14, 13, 53, 20, 481_000)
        assert rolled.old_secret_expires_at == utc(2026, 10, 15, 9, 30, 12, 500_000)
        assert plain.created_by_app is None
        assert plain.expires_at is None
        assert plain.last_used_at is None
        assert plain.old_secret_expires_at is None

    run(main)


def test_the_created_fixture() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        canned = {("POST", ACCOUNT_API): fixture_response(201, raw("account_key_created.json"))}
        new = await run_helper(fake, "create", canned)
        assert key_problem(new.secret) is None
        assert new.key.prefix == display_prefix(new.secret)
        assert new.key.id == "c41e7b2a-9f3d-4a6e-8b15-2d7f0e9a3c64"
        assert new.key.created_at == utc(2026, 10, 14, 15, 0, 0, 204_118)
        assert new.key.expires_at == utc(2027, 1, 12, 15, 0, 0, 204_118)
        assert new.key.last_used_at is None

    run(main)


def test_the_created_fixture_is_also_the_roll_answer() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        canned = {
            ("POST", f"{ACCOUNT_API}/{KEY_ID}/roll"): fixture_response(
                200, raw("account_key_created.json")
            )
        }
        new = await run_helper(fake, "roll", canned)
        assert new.secret.startswith(new.key.prefix)

    run(main)


def test_the_key_fixture_is_the_rename_answer() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        canned = {
            ("PATCH", f"{ACCOUNT_API}/{NO_EXPIRY_KEY_ID}"): fixture_response(
                200, raw("account_key.json")
            )
        }
        key = await run_helper(fake, "rename", canned)
        assert key.name == "Backup script"
        assert key.id == NO_EXPIRY_KEY_ID
        assert key.created_at == utc(2026, 10, 12, 10, 13, 20)

    run(main)


def test_the_problem_fixture() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        body = raw("account_problem.json")
        canned = {
            ("POST", ACCOUNT_API): httpx.Response(
                422, content=body, headers={"Content-Type": "application/problem+json"}
            )
        }
        with pytest.raises(AccountAPIError) as caught:
            await run_helper(fake, "create", canned)
        error = caught.value
        assert error.status_code == 422
        assert error.title == "Unprocessable Entity"
        assert error.detail == (
            "posts:delete can't be given to a key for Blog MCP server. Expected number <= 365."
        )
        assert [(e.location, e.value) for e in error.errors] == [
            ("body.permissions[1]", "posts:delete"),
            ("body.expires_in_days", 400),
        ]
        assert error.errors[0].message == "posts:delete can't be given to a key for Blog MCP server"

    run(main)


KEY_FIELDS = [
    "id",
    "name",
    "prefix",
    "resources",
    "permissions",
    "created_at",
]


@pytest.mark.parametrize("field", KEY_FIELDS)
def test_a_key_without_a_required_field_is_refused(field: str) -> None:
    async def main() -> None:
        document = load("account_key.json")
        del document[field]
        fake = FakeIssuer()
        canned = {
            ("PATCH", f"{ACCOUNT_API}/{NO_EXPIRY_KEY_ID}"): httpx.Response(200, json=document)
        }
        with pytest.raises(MicroAuthResponseError):
            await run_helper(fake, "rename", canned)

    run(main)


@pytest.mark.parametrize("name", FIXTURES)
def test_fixtures_are_well_formed(name: str) -> None:
    body = raw(name)
    assert body.endswith(b"\n")
    assert isinstance(json.loads(body), dict)


@pytest.mark.skipif(
    not PLATFORM_CONTRACT_DIR.is_dir(),
    reason="the platform repository is not checked out next to the SDK",
)
@pytest.mark.parametrize("name", FIXTURES)
def test_fixtures_match_the_platform(name: str) -> None:
    platform = PLATFORM_CONTRACT_DIR / name
    if not platform.is_file():
        pytest.skip(f"the platform has no {name} yet")
    assert raw(name) == platform.read_bytes()
