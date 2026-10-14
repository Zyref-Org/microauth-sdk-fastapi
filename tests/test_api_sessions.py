"""TokenAuth(sessions=auth): one route for signed in browsers, access tokens and API keys."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from fastapi import Depends, FastAPI
from oidc_fake import (
    API,
    APP_URL,
    CLIENT_ID,
    CLIENT_SECRET,
    COOKIE_SECRET,
    RESOURCE_CLIENT_ID,
    RESOURCE_SECRET,
    FakeIssuer,
    FakeUser,
    sign_in,
)

from microauth_fastapi import MicroAuthConfigurationError, TokenAuth, TokenClaims, UserAuth

SAME_SITE = {"Origin": APP_URL}


def user_auth(fake: FakeIssuer, app: FastAPI | None = None, **options: Any) -> UserAuth:
    settings: dict[str, Any] = {
        "issuer": fake.issuer,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "cookie_secret": COOKIE_SECRET,
        "app_url": APP_URL,
        "http_client": fake.client(),
    }
    settings.update(options)
    return UserAuth(app, **settings)


def build(fake: FakeIssuer, **options: Any) -> tuple[FastAPI, UserAuth, TokenAuth]:
    app = FastAPI()
    auth = user_auth(fake, app)
    settings: dict[str, Any] = {
        "issuer": fake.issuer,
        "resource": API,
        "http_client": fake.client(),
        "api_keys": True,
        "resource_client_id": RESOURCE_CLIENT_ID,
        "resource_secret": RESOURCE_SECRET,
        "sessions": auth,
    }
    settings.update(options)
    api = TokenAuth(app, **settings)

    def describe(token: TokenClaims) -> dict[str, Any]:
        return {
            "sub": token.sub,
            "via": token.via,
            "scopes": sorted(token.scopes),
            "client_id": token.client_id,
            "key_id": token.key_id,
            "expires_at": token.expires_at,
            "session_id": token.session_id,
            "email": token.claims.get("email"),
        }

    @app.get("/api/posts")
    async def posts(token: TokenClaims = Depends(api.require("posts:read"))) -> dict[str, Any]:
        return describe(token)

    @app.post("/api/posts")
    async def create(token: TokenClaims = Depends(api.require("posts:write"))) -> dict[str, Any]:
        return describe(token)

    @app.delete("/api/posts")
    async def delete(token: TokenClaims = Depends(api.require("posts:delete"))) -> dict[str, Any]:
        return describe(token)

    return app, auth, api


def client_for(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=APP_URL)


def run(test: Callable[[], Any]) -> None:
    asyncio.run(test())


def test_a_signed_in_browser_is_a_session_caller_with_its_permissions() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.user = FakeUser(permissions=["posts:read", "posts:write"])
        app, _, _ = build(fake)
        async with client_for(app) as client:
            await sign_in(client, fake)
            response = await client.get("/api/posts")
            assert response.status_code == 200, response.text
            assert response.json() == {
                "sub": "user_1",
                "via": "session",
                "scopes": ["posts:read", "posts:write"],
                "client_id": None,
                "key_id": None,
                "expires_at": None,
                "session_id": "sid_1",
                "email": "ada@example.com",
            }
            created = await client.post("/api/posts", headers=SAME_SITE)
            assert created.status_code == 200
            assert created.json()["via"] == "session"
        assert fake.introspections == []

    run(main)


def test_a_session_without_the_permission_gets_403() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.user = FakeUser(permissions=["posts:read"])
        app, _, _ = build(fake)
        async with client_for(app) as client:
            await sign_in(client, fake)
            response = await client.delete("/api/posts", headers=SAME_SITE)
        assert response.status_code == 403
        assert response.json()["detail"] == "You don't have a permission this request needs"
        assert response.json()["scopes"] == ["posts:delete"]

    run(main)


def test_unsafe_session_requests_must_come_from_this_site() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _, _ = build(fake)
        async with client_for(app) as client:
            await sign_in(client, fake)
            cross_site = await client.post("/api/posts", headers={"Origin": "https://evil.example"})
            assert cross_site.status_code == 403
            assert cross_site.json()["detail"] == "This request came from another site"
            assert (await client.post("/api/posts")).status_code == 403
            referer = await client.post("/api/posts", headers={"Referer": f"{APP_URL}/editor"})
            assert referer.status_code == 200
            assert (await client.post("/api/posts", headers=SAME_SITE)).status_code == 200

    run(main)


def test_a_cross_site_request_with_a_key_is_fine() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _, _ = build(fake)
        key = fake.add_key(permissions=["posts:write"])
        async with client_for(app) as client:
            response = await client.post(
                "/api/posts",
                headers={"Authorization": f"Bearer {key.secret}", "Origin": "https://evil.example"},
            )
        assert response.status_code == 200
        assert response.json()["via"] == "api_key"

    run(main)


def test_an_authorization_header_is_judged_alone() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.user = FakeUser(permissions=["posts:read", "posts:write"])
        app, _, _ = build(fake)
        key = fake.add_key(permissions=["posts:read"])
        async with client_for(app) as client:
            await sign_in(client, fake)
            bad = await client.get("/api/posts", headers={"Authorization": "Bearer nope"})
            assert bad.status_code == 401
            basic = await client.get("/api/posts", headers={"Authorization": "Basic dTpw"})
            assert basic.status_code == 401
            with_key = await client.get(
                "/api/posts", headers={"Authorization": f"Bearer {key.secret}"}
            )
            assert with_key.json()["via"] == "api_key"
            weaker = await client.post(
                "/api/posts", headers={**SAME_SITE, "Authorization": f"Bearer {key.secret}"}
            )
            assert weaker.status_code == 403
            assert weaker.json()["detail"] == "The API key is missing a scope this request needs"
            token = await client.get(
                "/api/posts", headers={"Authorization": f"Bearer {fake.access_token()}"}
            )
            assert token.json()["via"] == "access_token"

    run(main)


def test_signed_out_browsers_are_told_both_ways_in() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _, _ = build(fake)
        async with client_for(app) as client:
            response = await client.get("/api/posts")
        assert response.status_code == 401
        assert response.json()["detail"] == (
            "Sign in, or send a MicroAuth access token or API key in the Authorization header"
        )

    run(main)


def test_sessions_work_without_api_keys() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.user = FakeUser(permissions=["posts:read"])
        app, _, api = build(fake, api_keys=False)
        assert api.key_checks is None
        async with client_for(app) as client:
            signed_out = await client.get("/api/posts")
            assert signed_out.json()["detail"] == (
                "Sign in, or send a MicroAuth access token in the Authorization header"
            )
            await sign_in(client, fake)
            assert (await client.get("/api/posts")).json()["via"] == "session"

    run(main)


def test_sessions_need_the_roles_scope() -> None:
    fake = FakeIssuer()
    without_roles = user_auth(fake, scopes="openid profile email")
    with pytest.raises(MicroAuthConfigurationError, match="roles"):
        TokenAuth(issuer=fake.issuer, resource=API, sessions=without_roles)


def test_sessions_need_the_same_issuer() -> None:
    fake = FakeIssuer()
    other = FakeIssuer("https://other.example.com")
    with pytest.raises(MicroAuthConfigurationError, match="same issuer"):
        TokenAuth(issuer=fake.issuer, resource=API, sessions=user_auth(other))


def test_sessions_must_be_a_user_auth() -> None:
    fake = FakeIssuer()
    with pytest.raises(MicroAuthConfigurationError, match="UserAuth"):
        TokenAuth(issuer=fake.issuer, resource=API, sessions=object())  # type: ignore[arg-type]
