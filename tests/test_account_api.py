"""auth.api_keys: people managing their own API keys through MicroAuth's Account API."""

from __future__ import annotations

import asyncio
import dataclasses
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import Response
from oidc_fake import (
    ACCOUNT_API,
    ACCOUNT_SCOPE,
    API,
    APP_NAME,
    APP_URL,
    CLIENT_ID,
    CLIENT_SECRET,
    COOKIE_SECRET,
    FakeIssuer,
    sign_in,
)
from oidc_fake import (
    _bearer_error as bearer_error,
)

from microauth_fastapi import (
    AccountAPIError,
    AccountAPIUnavailable,
    MicroAuthConfigurationError,
    MicroAuthResponseError,
    UserAuth,
)
from microauth_fastapi._keys import display_prefix, key_problem
from microauth_fastapi.api_keys import APIKeys, _key_path, parse_challenge, parse_problem, sentence

SAME_SITE = {"Origin": APP_URL}
SETTINGS = {"Origin": APP_URL, "Referer": f"{APP_URL}/settings/api-keys?tab=keys"}


def build(fake: FakeIssuer, **options: Any) -> tuple[FastAPI, UserAuth]:
    app = FastAPI()
    settings: dict[str, Any] = {
        "issuer": fake.issuer,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "cookie_secret": COOKIE_SECRET,
        "app_url": APP_URL,
        "http_client": fake.client(),
        "api_keys": True,
    }
    settings.update(options)
    auth = UserAuth(app, **settings)

    @app.get("/keys/options")
    async def options_(request: Request) -> Any:
        return dataclasses.asdict(await auth.api_keys.options(request))

    @app.get("/keys")
    async def list_(request: Request) -> Any:
        return [dataclasses.asdict(key) for key in await auth.api_keys.list(request)]

    @app.post("/keys")
    async def create(request: Request) -> Any:
        body = await request.json()
        return dataclasses.asdict(await auth.api_keys.create(request, **body))

    @app.patch("/keys/{key_id}")
    async def rename(request: Request, key_id: str) -> Any:
        name = (await request.json())["name"]
        return dataclasses.asdict(await auth.api_keys.rename(request, key_id, name))

    @app.post("/keys/{key_id}/roll")
    async def roll(request: Request, key_id: str, hours: int = 0) -> Any:
        new = await auth.api_keys.roll(request, key_id, old_secret_lasts_hours=hours)
        return dataclasses.asdict(new)

    @app.delete("/keys/{key_id}")
    async def revoke(request: Request, key_id: str) -> Response:
        await auth.api_keys.revoke(request, key_id)
        return Response(status_code=204)

    @app.delete("/keys")
    async def revoke_all(request: Request) -> Response:
        await auth.api_keys.revoke_all(request)
        return Response(status_code=204)

    return app, auth


def client_for(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=APP_URL)


def run(test: Callable[[], Any]) -> None:
    asyncio.run(test())


NEW_KEY = {
    "name": "CI deploys",
    "resources": [API],
    "permissions": ["posts:read", "posts:write"],
    "expires_in_days": 90,
}


def when(value: str | None) -> datetime | None:
    return None if value is None else datetime.fromisoformat(value)


def test_the_session_asks_for_the_scope_and_keeps_the_access_token() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, auth = build(fake)
        assert auth.scopes[-1] == ACCOUNT_SCOPE
        assert auth.keep_access_token is True
        async with client_for(app) as client:
            await sign_in(client, fake)
        assert ACCOUNT_SCOPE in fake.par_requests[0]["scope"].split()
        assert "resource" not in fake.par_requests[0]

    run(main)


def test_every_helper_against_the_account_api() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            await sign_in(client, fake)
            options = (await client.get("/keys/options")).json()
            assert options["max_days"] == 365
            assert options["allow_no_expiry"] is True
            assert options["resources"][0]["identifier"] == API
            assert options["resources"][0]["permissions"][2] == {
                "name": "posts:delete",
                "description": "Delete posts",
                "sensitive": True,
            }

            created = await client.post("/keys", json=NEW_KEY, headers=SETTINGS)
            assert created.status_code == 200, created.text
            new = created.json()
            secret = new["secret"]
            assert key_problem(secret) is None
            key = new["key"]
            assert key["prefix"] == display_prefix(secret)
            assert key["name"] == "CI deploys"
            assert key["resources"] == [{"identifier": API, "name": "Blog API"}]
            assert key["permissions"] == ["posts:read", "posts:write"]
            assert key["created_by_app"] == {"client_id": CLIENT_ID, "name": APP_NAME}
            created_at = when(key["created_at"])
            expires_at = when(key["expires_at"])
            assert created_at is not None and expires_at is not None
            assert (expires_at - created_at).days == 90
            assert key["last_used_at"] is None and key["old_secret_expires_at"] is None

            listed = (await client.get("/keys")).json()
            assert [item["id"] for item in listed] == [key["id"]]
            assert "secret" not in listed[0]

            renamed = await client.patch(
                f"/keys/{key['id']}", json={"name": "Deploys"}, headers=SAME_SITE
            )
            assert renamed.json()["name"] == "Deploys"

            rolled = await client.post(f"/keys/{key['id']}/roll?hours=24", headers=SAME_SITE)
            assert rolled.status_code == 200, rolled.text
            assert rolled.json()["secret"] != secret
            assert key_problem(rolled.json()["secret"]) is None
            old_until = when(rolled.json()["key"]["old_secret_expires_at"])
            assert old_until is not None
            assert abs(old_until.timestamp() - time.time() - 86400) < 60
            now = int(time.time())
            assert fake._find_key(secret, now) is not None
            assert fake._find_key(rolled.json()["secret"], now) is not None

            other = await client.post(
                "/keys", json={**NEW_KEY, "expires_in_days": None}, headers=SAME_SITE
            )
            assert other.json()["key"]["expires_at"] is None
            assert len((await client.get("/keys")).json()) == 2

            revoked = await client.delete(f"/keys/{key['id']}", headers=SAME_SITE)
            assert revoked.status_code == 204
            assert [item["id"] for item in (await client.get("/keys")).json()] == [
                other.json()["key"]["id"]
            ]
            assert (await client.delete("/keys", headers=SAME_SITE)).status_code == 204
            assert (await client.get("/keys")).json() == []

        methods = [(method, path) for method, path, _ in fake.account_requests]
        assert methods[:3] == [
            ("GET", f"{ACCOUNT_API}/options"),
            ("POST", ACCOUNT_API),
            ("GET", ACCOUNT_API),
        ]
        assert ("PATCH", f"{ACCOUNT_API}/{key['id']}") in methods
        assert ("POST", f"{ACCOUNT_API}/{key['id']}/roll") in methods
        assert ("DELETE", f"{ACCOUNT_API}/{key['id']}") in methods
        assert ("DELETE", ACCOUNT_API) in methods
        bearer = {header for _, _, header in fake.account_requests}
        assert bearer == {f"Bearer {fake.issued_access_tokens[0]}"}

    run(main)


def test_the_account_api_url_is_on_the_issuer() -> None:
    fake = FakeIssuer()
    _, auth = build(fake)
    assert isinstance(auth.api_keys, APIKeys)
    assert auth.api_keys.url == "https://auth.example.com/api/v1/me/api-keys"


def test_an_old_sign_in_must_be_renewed_to_create_or_roll() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.last_sign_in = int(time.time()) - 3600
        app, _ = build(fake)
        existing = fake.add_key()
        async with client_for(app) as client:
            await sign_in(client, fake, next="/settings/api-keys")
            assert (await client.get("/keys")).status_code == 200

            stale = await client.post("/keys", json=NEW_KEY, headers=SETTINGS)
            assert stale.status_code == 401
            assert stale.headers["cache-control"] == "no-store"
            problem = stale.json()
            assert problem["detail"] == "Sign in again to continue"
            login_url = problem["login_url"]
            parts = urlsplit(login_url)
            assert parts.path == "/auth/login"
            assert parse_qs(parts.query) == {
                "next": ["/settings/api-keys?tab=keys"],
                "max_age": ["600"],
            }
            roll = await client.post(f"/keys/{existing.id}/roll", headers=SETTINGS)
            assert roll.status_code == 401
            assert roll.json()["login_url"] == login_url

            start = await client.get(login_url)
            assert start.status_code == 303
            assert fake.par_requests[-1]["max_age"] == "600"
            done = await client.get(fake.authorize(start.headers["location"]))
            assert done.status_code == 303
            assert done.headers["location"] == "/settings/api-keys?tab=keys"
            assert fake.reauthentications == 1

            created = await client.post("/keys", json=NEW_KEY, headers=SETTINGS)
            assert created.status_code == 200, created.text
            rolled = await client.post(f"/keys/{existing.id}/roll", headers=SETTINGS)
            assert rolled.status_code == 200

    run(main)


def test_reauthentication_returns_to_the_request_path_without_a_referer() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.last_sign_in = int(time.time()) - 3600
        app, auth = build(fake)
        async with client_for(app) as client:
            await sign_in(client, fake)
            stale = await client.post("/keys", json=NEW_KEY, headers=SAME_SITE)
            assert parse_qs(urlsplit(stale.json()["login_url"]).query)["next"] == ["/keys"]
            elsewhere = await client.post(
                "/keys",
                json=NEW_KEY,
                headers={"Origin": APP_URL, "Referer": "https://evil.example/settings"},
            )
            assert parse_qs(urlsplit(elsewhere.json()["login_url"]).query)["next"] == ["/keys"]
        assert (
            auth.login_url(next="/a?b=1", max_age=600)
            == "/auth/login?next=%2Fa%3Fb%3D1&max_age=600"
        )

    run(main)


@pytest.mark.parametrize("keep_access_token", [False, True])
def test_a_session_from_before_api_keys_must_sign_in_again(keep_access_token: bool) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        plain = FastAPI()
        UserAuth(
            plain,
            issuer=fake.issuer,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            cookie_secret=COOKIE_SECRET,
            app_url=APP_URL,
            keep_access_token=keep_access_token,
            http_client=fake.client(),
        )
        app, _ = build(fake)
        async with client_for(plain) as before:
            await sign_in(before, fake)
            cookies = before.cookies
        async with client_for(app) as client:
            client.cookies = cookies
            response = await client.get("/keys")
        assert response.status_code == 401
        assert response.json()["login_url"] == "/auth/login?next=%2Fkeys"
        assert fake.account_requests == []

    run(main)


def test_nobody_signed_in_gets_401() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            response = await client.get("/keys")
        assert response.status_code == 401
        assert response.json()["detail"] == "Sign in to continue"
        assert fake.account_requests == []

    run(main)


def test_a_cross_site_change_is_refused_before_microauth_is_called() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            await sign_in(client, fake)
            response = await client.post(
                "/keys", json=NEW_KEY, headers={"Origin": "https://evil.example"}
            )
        assert response.status_code == 403
        assert fake.account_requests == []

    run(main)


def test_an_expired_access_token_is_refreshed_before_the_call() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.access_ttl = 20
        app, _ = build(fake)
        async with client_for(app) as client:
            await sign_in(client, fake)
            assert fake.refreshes() == 0
            assert (await client.get("/keys")).status_code == 200
        assert fake.refreshes() == 1
        assert len(fake.issued_access_tokens) == 2
        assert fake.account_requests[-1][2] == f"Bearer {fake.issued_access_tokens[1]}"

    run(main)


def test_a_token_microauth_no_longer_accepts_signs_the_user_out() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        fake.account_canned[("GET", ACCOUNT_API)] = bearer_error(
            401, "invalid_token", "The access token was revoked"
        )
        async with client_for(app) as client:
            await sign_in(client, fake)
            response = await client.get("/keys")
            assert response.status_code == 401
            assert response.json()["detail"] == "Sign in to continue"
            assert "__Host-microauth=" in response.headers["set-cookie"]
            assert "Max-Age=0" in response.headers["set-cookie"]
            assert (await client.get("/keys/options")).status_code == 401
        assert len(fake.account_requests) == 1

    run(main)


def test_an_app_that_may_not_manage_keys_is_a_configuration_error() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.account_forbidden = True
        app, _ = build(fake)
        async with client_for(app) as client:
            await sign_in(client, fake)
            with pytest.raises(MicroAuthConfigurationError, match="web application"):
                await client.get("/keys")

    run(main)


def test_a_refusal_raises_account_api_error_with_the_details() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            await sign_in(client, fake)
            with pytest.raises(AccountAPIError) as caught:
                await client.post(
                    "/keys",
                    json={**NEW_KEY, "permissions": ["posts:publish"]},
                    headers=SAME_SITE,
                )
            error = caught.value
            assert error.status_code == 422
            assert error.detail == "You can't give a key this permission."
            assert error.title == "Unprocessable Entity"
            assert len(error.errors) == 1
            assert error.errors[0].message == "You can't give a key this permission"
            assert error.errors[0].location == "body.permissions[0]"
            assert error.errors[0].value == "posts:publish"
            assert not isinstance(error, AccountAPIUnavailable)

            missing = "00000000-0000-4000-8000-000000000000"
            with pytest.raises(AccountAPIError) as gone:
                await client.patch(f"/keys/{missing}", json={"name": "x"}, headers=SAME_SITE)
            assert gone.value.status_code == 404
            assert gone.value.detail == "There is no such API key."
            assert gone.value.errors == ()

            fake.account_canned[("PATCH", f"{ACCOUNT_API}/{missing}")] = httpx.Response(409)
            with pytest.raises(AccountAPIError) as bare:
                await client.patch(f"/keys/{missing}", json={"name": "x"}, headers=SAME_SITE)
            assert bare.value.status_code == 409
            assert (
                bare.value.detail == "The request to manage API keys was refused with status 409."
            )

    run(main)


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_a_microauth_failure_raises_account_api_unavailable(
    status: int, caplog: pytest.LogCaptureFixture
) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            await sign_in(client, fake)
            fake.account_canned[("GET", ACCOUNT_API)] = httpx.Response(
                status, json={"title": "Internal Server Error", "status": status}
            )
            with pytest.raises(AccountAPIUnavailable) as caught:
                await client.get("/keys")
        assert caught.value.status_code == 503
        assert caught.value.upstream_status == status
        assert caught.value.detail == (
            "API keys can't be managed right now. Please try again in a moment."
        )
        assert f"the Account API answered {status}" in caplog.text

    run(main)


@pytest.mark.parametrize(
    ("words", "shown"),
    [
        ("validation failed", "Validation failed."),
        ("can't do that", "Can't do that."),
        ("posts:delete can't be given to a key", "posts:delete can't be given to a key."),
        ("expected number <= 365", "Expected number <= 365."),
        ("There is no such API key.", "There is no such API key."),
        ("Really?", "Really?"),
        ("  padded  ", "Padded."),
        ("", ""),
    ],
)
def test_problem_details_become_sentences(words: str, shown: str) -> None:
    assert sentence(words) == shown


def test_a_problem_without_words_still_reads_as_a_sentence() -> None:
    assert parse_problem(404, None).detail == (
        "The request to manage API keys was refused with status 404."
    )
    assert parse_problem(422, {"detail": "validation failed", "errors": []}).detail == (
        "Validation failed."
    )


A_KEY = {
    "id": "c41e7b2a-9f3d-4a6e-8b15-2d7f0e9a3c64",
    "name": "Zapier",
    "prefix": "cms_kYBhn9",
    "resources": [{"identifier": API, "name": "Blog API"}],
    "permissions": ["posts:read"],
    "created_at": "2026-10-14T15:00:00Z",
    "created_by_app": None,
    "expires_at": None,
    "last_used_at": None,
    "old_secret_expires_at": None,
}


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, text="not json"),
        httpx.Response(200, json=[]),
        httpx.Response(200, json={"keys": {}}),
        httpx.Response(200, json={"keys": [{"id": "only an id"}]}),
        httpx.Response(200, json={"keys": [{**A_KEY, "created_at": "yesterday"}]}),
        httpx.Response(200, json={"keys": [{**A_KEY, "created_at": "2026-10-14T15:00:00"}]}),
        httpx.Response(200, json={"keys": [{**A_KEY, "expires_at": 1799676000}]}),
        httpx.Response(200, json={"keys": [{**A_KEY, "permissions": [1]}]}),
        httpx.Response(200, json={"keys": [{**A_KEY, "resources": [{"identifier": API}]}]}),
        httpx.Response(200, json={"keys": [{**A_KEY, "created_by_app": {"name": "x"}}]}),
    ],
)
def test_an_unreadable_answer_raises_a_response_error(response: httpx.Response) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        fake.account_canned[("GET", ACCOUNT_API)] = response
        async with client_for(app) as client:
            await sign_in(client, fake)
            with pytest.raises(MicroAuthResponseError):
                await client.get("/keys")

    run(main)


def test_an_unreachable_account_api_raises_account_api_unavailable(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, auth = build(fake)

        async def handle(request: httpx.Request) -> httpx.Response:
            if request.url.path.startswith(ACCOUNT_API):
                raise httpx.ConnectError("down", request=request)
            return await fake.handle(request)

        auth._http._client = httpx.AsyncClient(transport=httpx.MockTransport(handle))
        async with client_for(app) as client:
            await sign_in(client, fake)
            with pytest.raises(AccountAPIUnavailable) as caught:
                await client.get("/keys")
        assert isinstance(caught.value, AccountAPIError)
        assert caught.value.status_code == 503
        assert caught.value.upstream_status is None
        assert caught.value.detail.endswith("Please try again in a moment.")
        assert "ConnectError" in caplog.text
        assert "Bearer" not in caplog.text

    run(main)


def test_helper_arguments_are_checked_before_any_call() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        _, auth = build(fake)
        keys = auth.api_keys
        request: Any = None
        with pytest.raises(ValueError, match="0, 1 or 24"):
            await keys.roll(request, "id", old_secret_lasts_hours=2)
        with pytest.raises(ValueError, match="0, 1 or 24"):
            await keys.roll(request, "id", old_secret_lasts_hours=True)
        with pytest.raises(TypeError, match="list"):
            await keys.create(request, name="x", resources=API, permissions=[], expires_in_days=1)
        with pytest.raises(TypeError, match="list"):
            await keys.create(
                request, name="x", resources=[API], permissions=[""], expires_in_days=1
            )
        with pytest.raises(ValueError, match="expires_in_days"):
            await keys.create(request, name="x", resources=[API], permissions=[], expires_in_days=0)
        with pytest.raises(TypeError, match="name"):
            await keys.create(request, name=7, resources=[API], permissions=[], expires_in_days=1)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="key_id"):
            await keys.rename(request, "", "x")
        with pytest.raises(ValueError, match="key_id"):
            await keys.revoke(request, "x" * 200)
        assert fake.account_requests == []

    run(main)


def test_key_ids_are_escaped_in_the_path() -> None:
    assert _key_path("5f0c9a7e-3b2d-4c1e-9a8f-6d4b2e1c0a97") == (
        "/5f0c9a7e-3b2d-4c1e-9a8f-6d4b2e1c0a97"
    )
    assert _key_path("../admin?x=1#y") == "/..%2Fadmin%3Fx%3D1%23y"


def test_api_keys_settings_are_checked() -> None:
    fake = FakeIssuer()
    with pytest.raises(MicroAuthConfigurationError, match="resource"):
        build(fake, resource=API)
    _, plain = build(fake, api_keys=False)
    with pytest.raises(MicroAuthConfigurationError, match=r"api_keys=True"):
        plain.api_keys  # noqa: B018
    assert ACCOUNT_SCOPE not in plain.scopes
    assert plain.keep_access_token is False


def test_the_login_route_accepts_max_age() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, auth = build(fake, api_keys=False)
        async with client_for(app) as client:
            ok = await client.get("/auth/login", params={"next": "/settings", "max_age": "600"})
            assert ok.status_code == 303
            assert fake.par_requests[-1]["max_age"] == "600"
            zero = await client.get("/auth/login", params={"max_age": "0"})
            assert zero.status_code == 303
            assert fake.par_requests[-1]["max_age"] == "0"
            for bad in ("abc", "-1", "86401", "1e3", "600 ", "123456"):
                response = await client.get("/auth/login", params={"max_age": bad})
                assert response.status_code == 400, bad
                assert "max_age" in response.text
        assert auth.login_url(max_age=86400) == "/auth/login?max_age=86400"
        for bad_age in (-1, 86401, True, 1.5):
            with pytest.raises(ValueError):
                auth.login_url(max_age=bad_age)  # type: ignore[arg-type]

    run(main)


def test_a_sign_in_that_ignored_max_age_is_refused() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.last_sign_in = int(time.time()) - 3600
        app, _ = build(fake)
        async with client_for(app) as client:
            start = await client.get("/auth/login", params={"max_age": "600"})
            redirect = fake.authorize(start.headers["location"])
            fake.last_sign_in = int(time.time()) - 3600
            done = await client.get(redirect)
        assert done.status_code == 400
        assert "couldn&#x27;t be verified" in done.text

    run(main)


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (None, {}),
        ("", {}),
        ("Basic realm=x", {}),
        ("Bearer", {}),
        (
            (
                'Bearer error="insufficient_user_authentication", '
                'error_description="Sign in again, \\"please\\"", max_age="600"'
            ),
            {
                "error": "insufficient_user_authentication",
                "error_description": 'Sign in again, "please"',
                "max_age": "600",
            },
        ),
        ("bearer ERROR=invalid_token, Max_Age=60", {"error": "invalid_token", "max_age": "60"}),
        ('Bearer error="a", error="b"', {"error": "a"}),
    ],
)
def test_bearer_challenges_are_parsed(header: str | None, expected: dict[str, str]) -> None:
    assert parse_challenge(header) == expected


def test_a_step_up_challenge_without_a_usable_max_age_uses_ten_minutes() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        response = httpx.Response(
            401,
            json={"title": "Unauthorized", "status": 401, "detail": "x"},
            headers={"WWW-Authenticate": 'Bearer error="insufficient_user_authentication"'},
        )
        fake.account_canned[("POST", ACCOUNT_API)] = response
        async with client_for(app) as client:
            await sign_in(client, fake)
            stale = await client.post("/keys", json=NEW_KEY, headers=SAME_SITE)
        assert stale.status_code == 401
        assert "max_age=600" in stale.json()["login_url"]

    run(main)


def test_new_key_secrets_stay_out_of_repr() -> None:
    from microauth_fastapi import NewAPIKey
    from microauth_fastapi.api_keys import parse_key

    key = parse_key(A_KEY)
    new = NewAPIKey(key=key, secret="cms_kYBhn9pUbWLeMKXMo9xYRpJvSRHF3irSjKgWoebe41Ms4z")
    assert "pUbWLe" not in repr(new)
    assert key.created_at == datetime(2026, 10, 14, 15, tzinfo=timezone.utc)
