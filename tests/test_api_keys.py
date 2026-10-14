"""TokenAuth accepting API keys: format, introspection, caching, outages and limits."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
from collections.abc import Callable
from typing import Any
from urllib.parse import quote_plus

import httpx
import pytest
from fastapi import Depends, FastAPI, Request
from oidc_fake import (
    API,
    MCP,
    RESOURCE_CLIENT_ID,
    RESOURCE_SECRET,
    Clock,
    FakeIssuer,
    make_key,
)

from microauth_fastapi import MicroAuthConfigurationError, TokenAuth, TokenClaims
from microauth_fastapi._keys import (
    cache_lifetime,
    display_prefix,
    key_checksum,
    key_problem,
)

METADATA = f"{API}/.well-known/oauth-protected-resource"
INACTIVE = "The API key is unknown, revoked or expired"


def build(
    fake: FakeIssuer, clock: Clock | None = None, **options: Any
) -> tuple[FastAPI, TokenAuth]:
    app = FastAPI()
    settings: dict[str, Any] = {
        "issuer": fake.issuer,
        "resource": API,
        "http_client": fake.client(),
        "api_keys": True,
        "resource_client_id": RESOURCE_CLIENT_ID,
        "resource_secret": RESOURCE_SECRET,
    }
    settings.update(options)
    api = TokenAuth(app, **settings)
    if clock is not None:
        assert api.key_checks is not None
        api.key_checks.clock = clock
        fake.now = clock

    @app.get("/posts")
    async def posts(token: TokenClaims = Depends(api.require("posts:read"))) -> dict[str, Any]:
        return {
            "sub": token.sub,
            "via": token.via,
            "key_id": token.key_id,
            "client_id": token.client_id,
            "scopes": sorted(token.scopes),
            "expires_at": token.expires_at,
        }

    @app.post("/posts")
    async def create(token: TokenClaims = Depends(api.require("posts:write"))) -> dict[str, Any]:
        return {"by": token.sub}

    return app, api


def client_for(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=API)


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def run(test: Callable[[], Any]) -> None:
    asyncio.run(test())


# Format


def test_the_checksum_matches_known_vectors() -> None:
    # Worked out by hand from zlib's CRC-32, apart from both implementations.
    assert key_checksum("cms_" + "0" * 40) == "2xU3TD"
    assert key_checksum("cms_PKoGmRaCz4iLD7O60sk3NHPx7vRO58zu9rprukmq") == "0ADQpV"
    assert key_problem("cms_PKoGmRaCz4iLD7O60sk3NHPx7vRO58zu9rprukmq0ADQpV") is None
    for _ in range(50):
        key = make_key("ab9")
        assert key_problem(key) is None
        assert key_checksum(key[:-6]) == key[-6:]


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("cms_short", "malformed"),
        ("Cms_" + "a" * 46, "malformed"),
        ("c_" + "a" * 46, "malformed"),
        ("abcdefghijk_" + "a" * 46, "malformed"),
        ("cms-" + "a" * 46, "malformed"),
        ("cms_" + "a" * 45 + "!", "malformed"),
        ("cms_" + "a" * 47, "malformed"),
        ("", "malformed"),
        ("cms_" + "0" * 40 + "2xU3TE", "mistyped"),
        ("cms_" + "0" * 39 + "1" + "2xU3TD", "mistyped"),
        ("cmt_" + "0" * 40 + "2xU3TD", "mistyped"),
    ],
)
def test_bad_keys_are_named_malformed_or_mistyped(value: str, reason: str) -> None:
    problem = key_problem(value)
    assert problem is not None and reason in problem


def test_the_display_prefix_is_the_prefix_and_six_characters() -> None:
    assert display_prefix("cms_Ab12CdEf34GhIj56KlMn78OpQr90StUvWxYz12341aSWxs") == "cms_Ab12Cd"


@pytest.mark.parametrize(
    ("header", "seconds"),
    [
        (None, 30),
        ("", 30),
        ("public", 30),
        ("max-age=120", 120),
        ("private, max-age=45", 45),
        ('max-age="60"', 60),
        ("MAX-AGE=10", 10),
        ("max-age=900", 300),
        ("max-age=0", 0),
        ("no-store", 0),
        ("no-cache", 0),
        ("max-age=60, no-store", 0),
        ("max-age=abc", 0),
        ("max-age=-5", 0),
        ("max-age=10, max-age=20", 0),
        ("max-age=99999999999", 0),
    ],
)
def test_cache_lifetime_follows_cache_control(header: str | None, seconds: int) -> None:
    assert cache_lifetime(header) == seconds


# Accepting keys


def test_a_key_reaches_the_route_as_an_api_key_caller() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        clock = Clock()
        app, _ = build(fake, clock)
        key = fake.add_key(permissions=["posts:read"], expires_at=int(clock.now) + 86400)
        forever = fake.add_key(permissions=["posts:read", "posts:write"])
        async with client_for(app) as client:
            response = await client.get("/posts", headers=bearer(key.secret))
            assert response.status_code == 200, response.text
            assert response.json() == {
                "sub": "user_1",
                "via": "api_key",
                "key_id": key.id,
                "client_id": None,
                "scopes": ["posts:read"],
                "expires_at": key.expires_at,
            }
            other = await client.get("/posts", headers=bearer(forever.secret))
            assert other.json()["expires_at"] is None
            assert (await client.post("/posts", headers=bearer(forever.secret))).json() == {
                "by": "user_1"
            }
        assert fake.introspections[0] == {"token": key.secret}

    run(main)


def test_the_check_uses_basic_auth_with_form_encoded_credentials() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        seen: list[httpx.Request] = []
        transport = httpx.MockTransport(
            lambda request: seen.append(request) or fake.handle(request)
        )
        app, _ = build(fake, http_client=httpx.AsyncClient(transport=transport))
        key = fake.add_key()
        async with client_for(app) as client:
            assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 200
        check = next(request for request in seen if request.url.path == "/oauth/introspect")
        expected = f"{quote_plus(RESOURCE_CLIENT_ID)}:{quote_plus(RESOURCE_SECRET)}"
        assert check.headers["authorization"] == (
            "Basic " + base64.b64encode(expected.encode()).decode()
        )
        assert check.headers["accept"] == "application/json"
        assert check.headers["content-type"] == "application/x-www-form-urlencoded"

    run(main)


def test_a_key_missing_a_scope_gets_403_naming_the_key() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        key = fake.add_key(permissions=["posts:read"])
        async with client_for(app) as client:
            response = await client.post("/posts", headers=bearer(key.secret))
        assert response.status_code == 403
        assert response.json()["detail"] == "The API key is missing a scope this request needs"
        assert response.json()["scopes"] == ["posts:write"]
        assert 'error="insufficient_scope"' in response.headers["www-authenticate"]

    run(main)


def test_a_key_with_no_permissions_still_identifies_its_owner() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, api = build(fake)

        @app.get("/me")
        async def me(token: TokenClaims = Depends(api.require())) -> dict[str, Any]:
            return {"sub": token.sub, "scopes": sorted(token.scopes)}

        key = fake.add_key(permissions=[])
        async with client_for(app) as client:
            response = await client.get("/me", headers=bearer(key.secret))
        assert response.json() == {"sub": "user_1", "scopes": []}

    run(main)


def test_no_credential_asks_for_a_token_or_key() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, api = build(fake)
        async with client_for(app) as client:
            response = await client.get("/posts")
        assert response.status_code == 401
        assert response.json()["detail"] == (
            "Send a MicroAuth access token or API key in the Authorization header"
        )
        assert response.headers["www-authenticate"] == f'Bearer resource_metadata="{METADATA}"'
        assert app.openapi()["components"]["securitySchemes"]["MicroAuthAccessToken"] == {
            "type": "http",
            "scheme": "bearer",
            "description": "A MicroAuth access token issued for this API, or an API key.",
        }
        assert api.key_checks is not None

    run(main)


@pytest.mark.parametrize(
    "value",
    [
        "cms_short",
        "abcdefghijk_" + "a" * 46,
        "cms_" + "0" * 40 + "2xU3TE",
        "Cms_" + "0" * 40 + "2xU3TD",
    ],
)
def test_bad_keys_are_refused_without_asking_microauth(value: str) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            response = await client.get("/posts", headers=bearer(value))
        assert response.status_code == 401
        assert response.json()["detail"].startswith("The API key is m")
        assert 'error="invalid_token"' in response.headers["www-authenticate"]
        assert fake.introspections == []

    run(main)


def test_access_tokens_are_never_introspected() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            ok = await client.get("/posts", headers=bearer(fake.access_token()))
            assert ok.status_code == 200
            assert ok.json()["via"] == "access_token"
            assert ok.json()["client_id"] == "app_web_1"
            bad = await client.get("/posts", headers=bearer("not.a.jwt"))
            assert bad.status_code == 401
            assert "API key" not in bad.json()["detail"]
        assert fake.introspections == []

    run(main)


def test_an_unknown_key_is_401_and_the_answer_is_cached() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        clock = Clock()
        app, _ = build(fake, clock)
        unknown = make_key()
        async with client_for(app) as client:
            first = await client.get("/posts", headers=bearer(unknown))
            assert first.status_code == 401
            assert first.json()["detail"] == INACTIVE
            assert (await client.get("/posts", headers=bearer(unknown))).status_code == 401
            assert len(fake.introspections) == 1
            clock.advance(31)
            assert (await client.get("/posts", headers=bearer(unknown))).status_code == 401
            assert len(fake.introspections) == 2

    run(main)


def test_a_revoked_key_stops_working_once_its_answer_expires() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        clock = Clock()
        fake.introspect_cache_control = "private, max-age=60"
        app, _ = build(fake, clock)
        key = fake.add_key()
        async with client_for(app) as client:
            assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 200
            del fake.api_keys[key.id]
            clock.advance(59)
            assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 200
            clock.advance(2)
            revoked = await client.get("/posts", headers=bearer(key.secret))
            assert revoked.status_code == 401
            assert revoked.json()["detail"] == INACTIVE

    run(main)


@pytest.mark.parametrize(
    ("header", "lifetime"),
    [(None, 30), ("max-age=120", 120), ("max-age=900", 300), ("no-store", 0), ("max-age=0", 0)],
)
def test_answers_are_reused_for_their_cache_lifetime(header: str | None, lifetime: int) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        clock = Clock()
        fake.introspect_cache_control = header
        app, _ = build(fake, clock)
        key = fake.add_key()
        async with client_for(app) as client:

            async def check() -> int:
                response = await client.get("/posts", headers=bearer(key.secret))
                assert response.status_code == 200
                return len(fake.introspections)

            assert await check() == 1
            if lifetime == 0:
                assert await check() == 2
                return
            clock.advance(lifetime - 1)
            assert await check() == 1
            clock.advance(2)
            assert await check() == 2

    run(main)


def test_concurrent_checks_of_one_key_share_one_request() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.introspect_delay = 0.05
        app, _ = build(fake)
        key = fake.add_key()
        unknown = make_key()
        async with client_for(app) as client:
            responses = await asyncio.gather(
                *(client.get("/posts", headers=bearer(key.secret)) for _ in range(10)),
                *(client.get("/posts", headers=bearer(unknown)) for _ in range(5)),
            )
        assert [response.status_code for response in responses] == [200] * 10 + [401] * 5
        assert len(fake.introspections) == 2

    run(main)


def test_a_cancelled_caller_does_not_cancel_the_shared_check() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.introspect_delay = 0.05
        _, api = build(fake)
        assert api.key_checks is not None
        key = fake.add_key()
        first = asyncio.ensure_future(api.key_checks.verify(key.secret, "203.0.113.9"))
        await asyncio.sleep(0.01)
        second = asyncio.ensure_future(api.key_checks.verify(key.secret, "203.0.113.9"))
        await asyncio.sleep(0.01)
        first.cancel()
        answer = await second
        assert answer.key_id == key.id
        assert len(fake.introspections) == 1

    run(main)


# Misconfiguration and outages


def test_refused_server_credentials_are_a_logged_503(caplog: pytest.LogCaptureFixture) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake, resource_secret="the-wrong-secret")
        key = fake.add_key()
        async with client_for(app) as client:
            for _ in range(2):
                response = await client.get("/posts", headers=bearer(key.secret))
                assert response.status_code == 503
        assert len(fake.introspections) == 2
        errors = [record for record in caplog.records if record.levelno == logging.ERROR]
        assert len(errors) == 1
        message = errors[0].getMessage()
        assert "MICROAUTH_RESOURCE_CLIENT_ID" in message
        assert "MICROAUTH_RESOURCE_SECRET" in message
        assert "the-wrong-secret" not in caplog.text
        assert RESOURCE_CLIENT_ID not in caplog.text
        assert key.secret not in caplog.text

    caplog.set_level(logging.DEBUG, logger="microauth")
    run(main)


@pytest.mark.parametrize("status", [400, 401])
def test_a_400_or_401_from_introspection_is_a_misconfiguration(
    status: int, caplog: pytest.LogCaptureFixture
) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.introspect_failure = status
        app, _ = build(fake)
        key = fake.add_key()
        async with client_for(app) as client:
            assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 503
        assert "MICROAUTH_RESOURCE_SECRET" in caplog.text

    run(main)


def test_an_issuer_without_introspection_is_a_misconfiguration(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.discovery_overrides["introspection_endpoint"] = None
        app, _ = build(fake)
        key = fake.add_key()
        async with client_for(app) as client:
            assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 503
        assert "introspection_endpoint" in caplog.text

    run(main)


OUTAGES: list[int | type[httpx.HTTPError]] = [
    429,
    500,
    502,
    503,
    504,
    302,
    404,
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.RemoteProtocolError,
]


@pytest.mark.parametrize("failure", OUTAGES)
def test_an_outage_without_a_cached_answer_is_503_and_not_cached(
    failure: int | type[httpx.HTTPError],
) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.introspect_failure = failure
        app, _ = build(fake)
        key = fake.add_key()
        async with client_for(app) as client:
            response = await client.get("/posts", headers=bearer(key.secret))
            assert response.status_code == 503
            assert response.json()["detail"] == "Authorization is temporarily unavailable"
            fake.introspect_failure = None
            assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 200
        assert len(fake.introspections) == 2

    run(main)


@pytest.mark.parametrize(
    "body",
    [b"not json", b"[]", b'{"active": "yes"}', b"{}", b'{"active": true' + b" " * 70000 + b"}"],
)
def test_an_unreadable_answer_is_an_outage(body: bytes) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, api = build(fake)
        real = fake.handle

        async def handle(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/oauth/introspect":
                return httpx.Response(200, content=body)
            return await real(request)

        assert api.key_checks is not None
        api.verifier._http._client = httpx.AsyncClient(transport=httpx.MockTransport(handle))
        async with client_for(app) as client:
            response = await client.get("/posts", headers=bearer(make_key()))
        assert response.status_code == 503

    run(main)


def test_a_stale_answer_rides_out_an_outage(caplog: pytest.LogCaptureFixture) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        clock = Clock()
        app, _ = build(fake, clock)
        key = fake.add_key()
        async with client_for(app) as client:
            assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 200
            fake.introspect_failure = 503
            clock.advance(31)
            stale = await client.get("/posts", headers=bearer(key.secret))
            assert stale.status_code == 200
            assert stale.json()["key_id"] == key.id
            clock.advance(590)
            assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 200
            clock.advance(20)
            assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 503
            fake.introspect_failure = None
            assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 200
        assert "cached answers keep working" in caplog.text

    run(main)


def test_a_fresh_answer_after_the_outage_replaces_the_stale_one() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        clock = Clock()
        app, _ = build(fake, clock)
        key = fake.add_key()
        async with client_for(app) as client:
            assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 200
            clock.advance(31)
            fake.introspect_failure = httpx.ConnectError
            assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 200
            fake.introspect_failure = None
            del fake.api_keys[key.id]
            assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 401

    run(main)


def test_stale_if_error_zero_turns_stale_answers_off() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        clock = Clock()
        app, _ = build(fake, clock, stale_if_error=0)
        key = fake.add_key()
        async with client_for(app) as client:
            assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 200
            fake.introspect_failure = 500
            clock.advance(31)
            assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 503

    run(main)


def test_inactive_answers_are_never_served_stale() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        clock = Clock()
        app, _ = build(fake, clock)
        unknown = make_key()
        async with client_for(app) as client:
            assert (await client.get("/posts", headers=bearer(unknown))).status_code == 401
            fake.introspect_failure = 503
            clock.advance(31)
            assert (await client.get("/posts", headers=bearer(unknown))).status_code == 503

    run(main)


def test_an_uncacheable_answer_has_no_stale_copy() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        clock = Clock()
        fake.introspect_cache_control = "no-store"
        app, _ = build(fake, clock)
        key = fake.add_key()
        async with client_for(app) as client:
            assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 200
            fake.introspect_failure = 503
            assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 503

    run(main)


# Answers that don't fit this API


def _edit(**changes: Any) -> Callable[[dict[str, Any]], dict[str, Any]]:
    def edit(document: dict[str, Any]) -> dict[str, Any]:
        document = dict(document)
        for name, value in changes.items():
            if value is _DROP:
                document.pop(name, None)
            else:
                document[name] = value
        return document

    return edit


_DROP = object()

UNFIT_ANSWERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "an access token": _edit(token_use="access_token"),
    "no token_use": _edit(token_use=_DROP),
    "another API": _edit(aud="https://billing.example.com"),
    "a list without this API": _edit(aud=["https://billing.example.com", MCP]),
    "an API that only starts the same": _edit(aud="https://api.example.com/v2"),
    "another issuer": _edit(iss="https://evil.example"),
    "an issuer with a trailing slash": _edit(iss="https://auth.example.com/"),
    "an expired key": _edit(exp=1),
    "no key_id": _edit(key_id=_DROP),
    "no sub": _edit(sub=_DROP),
    "a numeric sub": _edit(sub=7),
    "no scope": _edit(scope=_DROP),
    "a list scope": _edit(scope=["posts:read"]),
    "no iat": _edit(iat=_DROP),
    "a text exp": _edit(exp="soon"),
    "a zero limit": _edit(requests_per_minute=0),
    "a text limit": _edit(requests_per_minute="10"),
}


@pytest.mark.parametrize("edit", UNFIT_ANSWERS.values(), ids=list(UNFIT_ANSWERS))
def test_an_active_answer_that_doesnt_fit_is_treated_as_inactive(
    edit: Callable[[dict[str, Any]], dict[str, Any]], caplog: pytest.LogCaptureFixture
) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.introspect_edit = edit
        fake.introspect_cache_control = "no-store"
        app, _ = build(fake)
        key = fake.add_key()
        async with client_for(app) as client:
            for _ in range(3):
                response = await client.get("/posts", headers=bearer(key.secret))
                assert response.status_code == 401
                assert response.json()["detail"] == INACTIVE
        warnings = [
            record for record in caplog.records if "can't be used here" in record.getMessage()
        ]
        assert len(warnings) == 1
        assert key.secret not in caplog.text

    caplog.set_level(logging.WARNING, logger="microauth")
    run(main)


def test_an_answer_naming_this_api_among_others_is_accepted() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        key = fake.add_key(resources=[MCP, API])
        async with client_for(app) as client:
            assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 200

    run(main)


def test_expiry_allows_the_leeway_and_is_checked_at_use() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        clock = Clock()
        fake.introspect_cache_control = "max-age=300"
        app, _ = build(fake, clock)
        now = int(clock.now)
        late = fake.add_key()
        fake.introspect_edit = lambda document: {**document, "exp": now - 30}
        async with client_for(app) as client:
            assert (await client.get("/posts", headers=bearer(late.secret))).status_code == 200
            clock.advance(31)
            expired = await client.get("/posts", headers=bearer(late.secret))
            assert expired.status_code == 401
            assert expired.json()["detail"] == "The API key has expired"
        assert len(fake.introspections) == 1

    run(main)


# Limits


def test_requests_per_minute_is_counted_per_person() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        clock = Clock()
        app, _ = build(fake, clock)
        first = fake.add_key(requests_per_minute=3)
        second = fake.add_key(requests_per_minute=3)
        someone_else = fake.add_key(requests_per_minute=3, sub="user_2")
        async with client_for(app) as client:
            for key in (first, second, first):
                assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 200
            over = await client.get("/posts", headers=bearer(second.secret))
            assert over.status_code == 429
            assert over.headers["retry-after"] == "20"
            assert over.headers["content-type"] == "application/problem+json"
            assert over.json()["detail"] == (
                "This API allows 3 requests a minute with each person's API keys"
            )
            other = await client.get("/posts", headers=bearer(someone_else.secret))
            assert other.status_code == 200
            token = await client.get("/posts", headers=bearer(fake.access_token()))
            assert token.status_code == 200
            clock.advance(19)
            assert (await client.get("/posts", headers=bearer(first.secret))).status_code == 429
            clock.advance(1)
            assert (await client.get("/posts", headers=bearer(first.secret))).status_code == 200
            assert (await client.get("/posts", headers=bearer(first.secret))).status_code == 429

    run(main)


def test_a_refused_request_does_not_use_up_the_limit() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        clock = Clock()
        app, _ = build(fake, clock)
        key = fake.add_key(requests_per_minute=2)
        async with client_for(app) as client:
            for _ in range(2):
                assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 200
            for _ in range(5):
                assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 429
            clock.advance(30)
            assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 200

    run(main)


def test_a_key_without_a_limit_is_unlimited() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        key = fake.add_key()
        async with client_for(app) as client:
            for _ in range(50):
                assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 200

    run(main)


def test_unknown_keys_from_one_address_are_throttled() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        clock = Clock()
        app, _ = build(fake, clock)
        good = fake.add_key()
        bad = ["cms_short", "cms_" + "0" * 40 + "2xU3TE"] + [make_key() for _ in range(18)]
        async with client_for(app) as client:
            for value in bad:
                assert (await client.get("/posts", headers=bearer(value))).status_code == 401
            asked = len(fake.introspections)
            assert asked == 18
            throttled = await client.get("/posts", headers=bearer(make_key()))
            assert throttled.status_code == 429
            assert throttled.headers["retry-after"] == "3"
            assert throttled.json()["detail"] == "Too many unknown API keys came from this address"
            assert (await client.get("/posts", headers=bearer(good.secret))).status_code == 429
            assert len(fake.introspections) == asked
            token = await client.get("/posts", headers=bearer(fake.access_token()))
            assert token.status_code == 200
            clock.advance(3)
            assert (await client.get("/posts", headers=bearer(good.secret))).status_code == 200

    run(main)


def test_the_unknown_key_throttle_is_per_client_address() -> None:
    async def main() -> None:
        fake = FakeIssuer()

        def address(request: Request) -> str | None:
            return request.headers.get("x-real-ip")

        app, _ = build(fake, unknown_key_limit=2, client_address=address)
        good = fake.add_key()
        async with client_for(app) as client:
            for _ in range(2):
                response = await client.get(
                    "/posts", headers={**bearer(make_key()), "X-Real-IP": "198.51.100.1"}
                )
                assert response.status_code == 401
            blocked = await client.get(
                "/posts", headers={**bearer(good.secret), "X-Real-IP": "198.51.100.1"}
            )
            assert blocked.status_code == 429
            other = await client.get(
                "/posts", headers={**bearer(good.secret), "X-Real-IP": "198.51.100.2"}
            )
            assert other.status_code == 200

    run(main)


def test_unknown_key_limit_zero_turns_the_throttle_off() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake, unknown_key_limit=0)
        async with client_for(app) as client:
            for _ in range(40):
                assert (await client.get("/posts", headers=bearer("cms_short"))).status_code == 401

    run(main)


def test_good_keys_do_not_count_toward_the_throttle() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake, unknown_key_limit=1)
        key = fake.add_key()
        async with client_for(app) as client:
            for _ in range(10):
                assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 200
            assert (await client.get("/posts", headers=bearer(make_key()))).status_code == 401
            assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 429

    run(main)


# Secrets stay out of logs and caches


def test_the_raw_key_never_reaches_logs_or_the_cache(caplog: pytest.LogCaptureFixture) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        clock = Clock()
        app, api = build(fake, clock)
        assert api.key_checks is not None
        key = fake.add_key(requests_per_minute=1)
        async with client_for(app) as client:
            await client.get("/posts", headers=bearer(key.secret))
            await client.get("/posts", headers=bearer(key.secret))
            fake.introspect_failure = 503
            clock.advance(700)
            await client.get("/posts", headers=bearer(key.secret))
        entries = api.key_checks.introspector.answers._entries  # type: ignore[attr-defined]
        assert set(entries) <= {hashlib.sha256(key.secret.encode()).hexdigest()}
        assert key.secret not in caplog.text
        assert key.secret[:-6] not in caplog.text

    caplog.set_level(logging.DEBUG)
    run(main)


# Shutdown


async def lifespan(app: Any) -> None:
    messages = iter([{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}])
    sent: list[str] = []

    async def receive() -> dict[str, Any]:
        return next(messages)

    async def send(message: dict[str, Any]) -> None:
        sent.append(message["type"])

    await app({"type": "lifespan", "asgi": {"version": "3.0"}, "state": {}}, receive, send)
    assert sent == ["lifespan.startup.complete", "lifespan.shutdown.complete"]


def test_shutdown_empties_the_key_caches_and_limits() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, api = build(fake, Clock())
        assert api.key_checks is not None
        key = fake.add_key(requests_per_minute=5)
        async with client_for(app) as client:
            assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 200
        entries = api.key_checks.introspector.answers._entries  # type: ignore[attr-defined]
        counters = api.key_checks.limits._gcra._drained_at  # type: ignore[attr-defined]
        assert entries and counters
        await lifespan(app)
        assert not entries and not counters
        async with client_for(app) as client:
            assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 200
        assert len(fake.introspections) == 2

    run(main)


def test_shutdown_closes_the_http_client_token_auth_made() -> None:
    async def main() -> None:
        app = FastAPI()
        api = TokenAuth(app, issuer="https://auth.example.com", resource=API)
        made = api.verifier._http()
        passed_in = httpx.AsyncClient()
        app_with_client = FastAPI()
        TokenAuth(
            app_with_client, issuer="https://auth.example.com", resource=API, http_client=passed_in
        )
        await lifespan(app)
        await lifespan(app_with_client)
        assert made.is_closed
        assert not passed_in.is_closed
        await passed_in.aclose()

    run(main)


def test_a_failing_close_at_shutdown_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, api = build(fake)

        async def broken() -> None:
            raise RuntimeError("boom")

        api._bearer.aclose = broken  # type: ignore[method-assign]
        await lifespan(app)
        assert "closing TokenAuth at shutdown failed" in caplog.text

    run(main)


# Configuration


def test_keys_need_the_server_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeIssuer()
    with pytest.raises(MicroAuthConfigurationError) as caught:
        TokenAuth(issuer=fake.issuer, resource=API, api_keys=True)
    assert "MICROAUTH_RESOURCE_CLIENT_ID" in str(caught.value)
    assert "MICROAUTH_RESOURCE_SECRET" in str(caught.value)
    with pytest.raises(MicroAuthConfigurationError):
        TokenAuth(issuer=fake.issuer, resource=API, api_keys=True, resource_client_id="id")
    monkeypatch.setenv("MICROAUTH_RESOURCE_CLIENT_ID", RESOURCE_CLIENT_ID)
    monkeypatch.setenv("MICROAUTH_RESOURCE_SECRET", RESOURCE_SECRET)
    api = TokenAuth(issuer=fake.issuer, resource=API, api_keys=True)
    assert api.key_checks is not None
    assert TokenAuth(issuer=fake.issuer, resource=API).key_checks is None


def test_keys_read_the_credentials_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        monkeypatch.setenv("MICROAUTH_RESOURCE_CLIENT_ID", RESOURCE_CLIENT_ID)
        monkeypatch.setenv("MICROAUTH_RESOURCE_SECRET", RESOURCE_SECRET)
        app, _ = build(fake, resource_client_id=None, resource_secret=None)
        key = fake.add_key()
        async with client_for(app) as client:
            assert (await client.get("/posts", headers=bearer(key.secret))).status_code == 200

    run(main)


@pytest.mark.parametrize(
    "options",
    [
        {"stale_if_error": -1},
        {"stale_if_error": 86_401},
        {"stale_if_error": True},
        {"stale_if_error": "600"},
        {"unknown_key_limit": -1},
        {"unknown_key_limit": 2.5},
        {"unknown_key_limit": True},
        {"client_address": "x-forwarded-for"},
    ],
)
def test_bad_key_settings_are_refused(options: dict[str, Any]) -> None:
    with pytest.raises(MicroAuthConfigurationError):
        build(FakeIssuer(), **options)


def test_key_settings_are_ignored_without_api_keys() -> None:
    fake = FakeIssuer()
    api = TokenAuth(issuer=fake.issuer, resource=API, stale_if_error=5, unknown_key_limit=3)
    assert api.key_checks is None


def test_a_key_shaped_value_is_a_bad_token_without_api_keys() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake, api_keys=False)
        async with client_for(app) as client:
            response = await client.get("/posts", headers=bearer(fake.add_key().secret))
        assert response.status_code == 401
        assert "API key" not in response.json()["detail"]
        assert fake.introspections == []

    run(main)
