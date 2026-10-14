from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from fastapi import Depends, FastAPI
from oidc_fake import API, FakeIssuer, hmac_token, unsigned_token

from microauth_fastapi import MicroAuthConfigurationError, TokenAuth, TokenClaims
from microauth_fastapi.tokens import bearer_challenge, metadata_path, metadata_url

METADATA = f"{API}/.well-known/oauth-protected-resource"


def build(fake: FakeIssuer, resource: str = API, **options: Any) -> tuple[FastAPI, TokenAuth]:
    app = FastAPI()
    api = TokenAuth(
        app, issuer=fake.issuer, resource=resource, http_client=fake.client(), **options
    )

    @app.get("/posts")
    async def posts(token: TokenClaims = Depends(api.require("posts:read"))) -> dict[str, Any]:
        return {
            "sub": token.sub,
            "client_id": token.client_id,
            "scopes": sorted(token.scopes),
            "session_id": token.session_id,
        }

    @app.post("/posts")
    async def create(
        token: TokenClaims = Depends(api.require("posts:read", "posts:write")),
    ) -> dict[str, Any]:
        return {"created_by": token.sub}

    @app.get("/ping")
    async def ping(token: TokenClaims = Depends(api.require())) -> dict[str, Any]:
        return {"sub": token.sub}

    return app, api


def client_for(app: FastAPI, base_url: str = API) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=base_url)


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def run(test: Callable[[], Any]) -> None:
    asyncio.run(test())


def test_a_valid_token_reaches_the_route() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            response = await client.get("/posts", headers=bearer(fake.access_token()))
            assert response.status_code == 200
            assert response.json() == {
                "sub": "user_1",
                "client_id": "app_web_1",
                "scopes": ["posts:read"],
                "session_id": "sid_1",
            }
            other_typ = fake.access_token(typ="application/at+jwt")
            assert (await client.get("/posts", headers=bearer(other_typ))).status_code == 200
            several = fake.access_token(aud=["https://other.example.com", API])
            assert (await client.get("/posts", headers=bearer(several))).status_code == 200
            lower = {"Authorization": f"bearer {fake.access_token()}"}
            assert (await client.get("/posts", headers=lower)).status_code == 200

    run(main)


def test_no_token_gets_a_challenge_without_an_error() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            response = await client.get("/posts")
            basic = await client.get("/posts", headers={"Authorization": "Basic dXNlcjpwYXNz"})
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == f'Bearer resource_metadata="{METADATA}"'
        assert response.headers["content-type"] == "application/problem+json"
        assert response.json()["status"] == 401
        assert basic.status_code == 401
        assert "error=" not in basic.headers["www-authenticate"]

    run(main)


def _expired(fake: FakeIssuer) -> str:
    now = int(time.time())
    return fake.access_token(exp=now - 3600, iat=now - 7200, nbf=now - 7200)


BAD_TOKENS: dict[str, tuple[Callable[[FakeIssuer], str], str]] = {
    "minted for another resource": (
        lambda fake: fake.access_token(aud="https://billing.example.com"),
        "different audience",
    ),
    "minted for the issuer itself": (
        lambda fake: fake.access_token(aud=fake.issuer),
        "different audience",
    ),
    "wrong issuer": (
        lambda fake: fake.access_token(iss="https://evil.example"),
        "different server",
    ),
    "expired": (_expired, "expired"),
    "not valid yet": (
        lambda fake: fake.access_token(nbf=int(time.time()) + 3600),
        "not valid yet",
    ),
    "ID token typ": (lambda fake: fake.access_token(typ="JWT"), "wrong type"),
    "no typ": (lambda fake: fake.access_token(typ=None), "no type"),
    "no client_id": (lambda fake: fake.access_token(client_id=None), "client_id"),
    "no sub": (lambda fake: fake.access_token(sub=None), "sub"),
    "alg none": (
        lambda fake: unsigned_token(fake.access_token_claims(), {"typ": "at+jwt"}),
        "RS256",
    ),
    "HS256": (lambda fake: hmac_token(fake.access_token_claims(), {"typ": "at+jwt"}), "RS256"),
    "garbage": (lambda fake: "not.a.jwt", "malformed"),
    "forged with a known kid": (
        lambda fake: fake.sign(fake.access_token_claims(), typ="at+jwt", key_index=5),
        "signature",
    ),
}


@pytest.mark.parametrize("case", sorted(BAD_TOKENS))
def test_bad_tokens_are_refused(case: str) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        make, reason = BAD_TOKENS[case]
        app, _ = build(fake)
        async with client_for(app) as client:
            response = await client.get("/posts", headers=bearer(make(fake)))
        assert response.status_code == 401
        challenge = response.headers["www-authenticate"]
        assert challenge.startswith('Bearer error="invalid_token", error_description="')
        assert challenge.endswith(f'resource_metadata="{METADATA}"')
        assert reason in response.json()["detail"]

    run(main)


def test_a_token_for_resource_a_is_refused_at_resource_b() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app_a, _ = build(fake, resource="https://a.example.com")
        app_b, _ = build(fake, resource="https://b.example.com")
        token = fake.access_token(aud="https://a.example.com")
        async with client_for(app_a, "https://a.example.com") as client:
            assert (await client.get("/posts", headers=bearer(token))).status_code == 200
        async with client_for(app_b, "https://b.example.com") as client:
            refused = await client.get("/posts", headers=bearer(token))
        assert refused.status_code == 401
        assert "different audience" in refused.json()["detail"]

    run(main)


def test_two_authorization_headers_are_refused() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        token = fake.access_token()
        async with client_for(app) as client:
            response = await client.get(
                "/posts",
                headers=[("Authorization", f"Bearer {token}"), ("Authorization", "Bearer x")],
            )
        assert response.status_code == 401
        assert 'error="invalid_token"' in response.headers["www-authenticate"]

    run(main)


def test_a_missing_scope_gets_403_listing_every_scope_needed() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            response = await client.post("/posts", headers=bearer(fake.access_token()))
            assert response.status_code == 403
            assert response.headers["www-authenticate"] == (
                'Bearer error="insufficient_scope", scope="posts:read posts:write", '
                f'resource_metadata="{METADATA}", '
                'error_description="The access token is missing a scope this request needs"'
            )
            assert response.json()["scopes"] == ["posts:read", "posts:write"]

            writer = fake.access_token(scope="posts:read posts:write")
            created = await client.post("/posts", headers=bearer(writer))
            assert created.json() == {"created_by": "user_1"}
            no_scope = fake.access_token(scope=None)
            assert (await client.get("/ping", headers=bearer(no_scope))).status_code == 200

    run(main)


def test_global_scopes_are_added_to_every_route() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, api = build(fake, scopes="api:access")
        assert api.scopes_supported == {"api:access", "posts:read", "posts:write"}
        async with client_for(app) as client:
            response = await client.get("/ping", headers=bearer(fake.access_token()))
            assert response.status_code == 403
            assert 'scope="api:access"' in response.headers["www-authenticate"]
            token = fake.access_token(scope="api:access posts:read")
            assert (await client.get("/posts", headers=bearer(token))).status_code == 200

    run(main)


def test_an_unknown_kid_refetches_the_keys_once() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, api = build(fake)
        clock = [1000.0]
        api.verifier.keys.clock = lambda: clock[0]
        async with client_for(app) as client:
            assert (
                await client.get("/posts", headers=bearer(fake.access_token()))
            ).status_code == 200
            assert fake.jwks_fetches == 1
            assert (
                await client.get("/posts", headers=bearer(fake.access_token()))
            ).status_code == 200
            assert fake.jwks_fetches == 1

            fake.rotate("key-2", 2)
            rotated = await client.get("/posts", headers=bearer(fake.access_token()))
            assert rotated.status_code == 200
            assert fake.jwks_fetches == 2

            stranger = fake.sign(fake.access_token_claims(), typ="at+jwt", kid="key-7", key_index=7)
            refused = await asyncio.gather(
                *(client.get("/posts", headers=bearer(stranger)) for _ in range(5))
            )
            assert {response.status_code for response in refused} == {401}
            assert "unknown key" in refused[0].json()["detail"]
            assert fake.jwks_fetches == 2

            clock[0] += 61
            fake.rotate("key-7", 7)
            accepted = await client.get("/posts", headers=bearer(stranger))
            assert accepted.status_code == 200
            assert fake.jwks_fetches == 3

    run(main)


def test_keys_refresh_on_a_schedule() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, api = build(fake)
        clock = [1000.0]
        api.verifier.keys.clock = lambda: clock[0]
        async with client_for(app) as client:
            await client.get("/posts", headers=bearer(fake.access_token()))
            assert fake.jwks_fetches == 1
            clock[0] += 901
            assert (
                await client.get("/posts", headers=bearer(fake.access_token()))
            ).status_code == 200
            await asyncio.sleep(0.01)
            assert fake.jwks_fetches == 2

    run(main)


def test_an_unreachable_issuer_answers_503() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.discovery_overrides = {"issuer": "https://other.example"}
        app, _ = build(fake)
        async with client_for(app) as client:
            response = await client.get("/posts", headers=bearer(fake.access_token()))
        assert response.status_code == 503
        assert response.headers["retry-after"] == "5"

    run(main)


def test_metadata_is_served_at_the_root_for_a_resource_without_a_path() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, api = build(fake)
        assert api.metadata_url == METADATA
        async with client_for(app) as client:
            response = await client.get("/.well-known/oauth-protected-resource")
        assert response.status_code == 200
        assert response.json() == {
            "resource": API,
            "authorization_servers": [fake.issuer],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["posts:read", "posts:write"],
        }
        assert response.headers["access-control-allow-origin"] == "*"

    run(main)


def test_metadata_path_inserts_the_resource_path() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        resource = "https://api.example.com/v1"
        app, api = build(fake, resource=resource, scopes_supported=["posts:read"])
        expected = "https://api.example.com/.well-known/oauth-protected-resource/v1"
        assert api.metadata_url == expected
        async with client_for(app) as client:
            response = await client.get("/.well-known/oauth-protected-resource/v1")
            assert response.json()["resource"] == resource
            assert response.json()["scopes_supported"] == ["posts:read"]
            assert (await client.get("/.well-known/oauth-protected-resource")).status_code == 404
            challenge = (await client.get("/posts")).headers["www-authenticate"]
        assert challenge == f'Bearer resource_metadata="{expected}"'

    run(main)


def test_metadata_helpers() -> None:
    assert metadata_path("https://x.example") == "/.well-known/oauth-protected-resource"
    assert metadata_path("https://x.example/mcp") == "/.well-known/oauth-protected-resource/mcp"
    assert metadata_url("https://x.example:8443/a/b") == (
        "https://x.example:8443/.well-known/oauth-protected-resource/a/b"
    )
    assert bearer_challenge(error=None, scope='a"b') == 'Bearer scope="a\\"b"'
    assert bearer_challenge() == "Bearer"


@pytest.mark.parametrize(
    "resource",
    [
        "https://api.example.com/",
        "https://api.example.com/v1/",
        "https://api.example.com?x=1",
        "https://api.example.com#frag",
        "http://api.example.com",
        "api.example.com",
    ],
)
def test_bad_resources_are_refused(resource: str) -> None:
    with pytest.raises(MicroAuthConfigurationError):
        TokenAuth(issuer="https://auth.example.com", resource=resource)


def test_bad_scope_names_are_refused() -> None:
    api = TokenAuth(issuer="https://auth.example.com", resource=API)
    with pytest.raises(MicroAuthConfigurationError):
        api.require('posts "read"')


def test_settings_come_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MICROAUTH_ISSUER", "https://auth.example.com")
    monkeypatch.setenv("MICROAUTH_RESOURCE", "http://localhost:8000")
    api = TokenAuth()
    assert api.resource == "http://localhost:8000"
    assert api.metadata_url == "http://localhost:8000/.well-known/oauth-protected-resource"


def test_the_openapi_schema_declares_bearer_auth() -> None:
    fake = FakeIssuer()
    app, _ = build(fake)
    schema = app.openapi()
    assert schema["components"]["securitySchemes"]["MicroAuthAccessToken"] == {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
        "description": "A MicroAuth access token issued for this API.",
    }
