from __future__ import annotations

import asyncio
import base64
import html
import secrets
import time
from collections.abc import Callable
from http.cookiejar import Cookie
from typing import Any
from urllib.parse import parse_qs, quote_plus, urlencode, urlsplit

import httpx
import jwt
import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from oidc_fake import (
    API,
    APP_URL,
    CLIENT_ID,
    CLIENT_SECRET,
    COOKIE_SECRET,
    Clock,
    FakeIssuer,
    hmac_token,
    sign_in,
    unsigned_token,
)

from microauth_fastapi import (
    MicroAuthConfigurationError,
    PermissionDenied,
    TokenAuth,
    User,
    UserAuth,
    refusal_response,
)
from microauth_fastapi._cookies import CHUNK_SIZE, CookieSealer, read_value, split_value
from microauth_fastapi.login import safe_path, user_from_claims

SESSION = "__Host-microauth"
LOGIN = "__Host-microauth-login"
SAME_SITE = {"Origin": APP_URL}


def build(fake: FakeIssuer, app: FastAPI | None = None, **options: Any) -> tuple[FastAPI, UserAuth]:
    app = app or FastAPI()
    settings: dict[str, Any] = {
        "issuer": fake.issuer,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "cookie_secret": COOKIE_SECRET,
        "app_url": APP_URL,
        "http_client": fake.client(),
    }
    settings.update(options)
    auth = UserAuth(app, **settings)

    @app.get("/dashboard")
    async def dashboard(user: User = Depends(auth.login_required)) -> dict[str, Any]:
        return {"name": user.name}

    @app.get("/api/me")
    async def me(user: User = Depends(auth.user)) -> dict[str, Any]:
        return user.to_dict()

    @app.get("/maybe")
    async def maybe(user: User | None = Depends(auth.optional)) -> dict[str, Any]:
        return {"user": user.id if user else None}

    @app.post("/posts")
    async def create_post(
        user: User = Depends(auth.require(permissions="posts:write")),
    ) -> dict[str, Any]:
        return {"by": user.id}

    @app.delete("/posts/1")
    async def delete_post(user: User = Depends(auth.require(roles="admin"))) -> dict[str, Any]:
        return {"deleted_by": user.id}

    @app.get("/admin")
    async def admin(
        user: User = Depends(auth.require(roles="admin", redirect=True)),
    ) -> dict[str, Any]:
        return {"admin": user.id}

    @app.get("/plain")
    async def plain(user: User = Depends(auth.user)) -> PlainTextResponse:
        return PlainTextResponse(f"hello {user.id}")

    return app, auth


def client_for(app: FastAPI, base_url: str = APP_URL) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=base_url)


def set_cookies(response: httpx.Response) -> dict[str, str]:
    """The response's Set-Cookie headers by cookie name."""
    return {header.split("=", 1)[0]: header for header in response.headers.get_list("set-cookie")}


def page(response: httpx.Response) -> str:
    return html.unescape(response.text)


def jar_cookie(client: httpx.AsyncClient, name: str) -> Cookie | None:
    for cookie in client.cookies.jar:
        if cookie.name == name:
            return cookie
    return None


def jar_names(client: httpx.AsyncClient) -> set[str]:
    return {cookie.name for cookie in client.cookies.jar}


def run(test: Callable[[], Any]) -> None:
    asyncio.run(test())


def test_login_pushes_the_request_with_pkce_state_and_nonce() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            response = await client.get("/auth/login", params={"next": "/dashboard?tab=1"})

        assert response.status_code == 303
        location = urlsplit(response.headers["location"])
        assert f"{location.scheme}://{location.netloc}{location.path}" == fake.url(
            "/oauth/authorize"
        )
        assert set(parse_qs(location.query)) == {"client_id", "request_uri"}
        pushed = fake.par_requests[0]
        assert pushed["response_type"] == "code"
        assert pushed["client_id"] == CLIENT_ID
        assert pushed["redirect_uri"] == f"{APP_URL}/auth/callback"
        assert pushed["scope"] == "openid profile email roles"
        assert pushed["code_challenge_method"] == "S256"
        assert len(pushed["code_challenge"]) == 43
        assert len(pushed["state"]) >= 43
        assert len(pushed["nonce"]) >= 43
        assert pushed["state"] != pushed["nonce"]

        # client_secret_basic form encodes the id and secret before base64.
        raw = base64.b64decode(fake.basic_headers[0][len("Basic ") :]).decode()
        assert raw == f"{CLIENT_ID}:{quote_plus(CLIENT_SECRET, safe='')}"

        cookie = set_cookies(response)[LOGIN]
        for attribute in ("Path=/", "SameSite=Lax", "HttpOnly", "Secure", "Max-Age=600"):
            assert attribute in cookie
        assert "Domain" not in cookie
        assert response.headers["cache-control"] == "no-store"

    run(main)


def test_login_without_par_puts_the_request_in_the_redirect() -> None:
    async def main() -> None:
        fake = FakeIssuer(par=False)
        app, _ = build(fake)
        async with client_for(app) as client:
            response = await client.get("/auth/login")
        query = parse_qs(urlsplit(response.headers["location"]).query)
        assert query["code_challenge_method"] == ["S256"]
        assert query["redirect_uri"] == [f"{APP_URL}/auth/callback"]
        assert {"state", "nonce", "code_challenge"} <= set(query)
        assert fake.par_requests == []

    run(main)


@pytest.mark.parametrize(
    "next_value",
    [
        "https://evil.example/",
        "//evil.example/",
        "/\\evil.example",
        "javascript:alert(1)",
        "/\r\nLocation: https://evil.example",
        "dashboard",
    ],
)
def test_login_refuses_a_next_that_leaves_the_site(next_value: str) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            response = await client.get("/auth/login", params={"next": next_value})
        assert response.status_code == 400
        assert "isn't on this site" in page(response)
        assert fake.par_requests == []
        assert LOGIN not in set_cookies(response)

    run(main)


def test_safe_path_accepts_only_local_paths() -> None:
    assert safe_path("/posts?page=2#top") == "/posts?page=2#top"
    assert safe_path("/") == "/"
    for value in ("", None, "//x", "/\\x", "https://x/", "/a b", "/caf\u00e9", "x"):
        assert safe_path(value) is None


def test_signup_asks_for_the_create_prompt() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            response = await client.get("/auth/signup")
        assert response.status_code == 303
        assert fake.par_requests[0]["prompt"] == "create"

    run(main)


def test_sign_in_round_trip() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            done = await sign_in(client, fake, next="/dashboard?tab=1")
            assert done.headers["location"] == "/dashboard?tab=1"
            cookies = set_cookies(done)
            session = cookies[SESSION]
            for attribute in ("Path=/", "SameSite=Lax", "HttpOnly", "Secure"):
                assert attribute in session
            max_age = int(session.split("Max-Age=")[1].split(";")[0])
            assert 30 * 24 * 3600 - 5 <= max_age <= 30 * 24 * 3600
            assert "Max-Age=0" in cookies[LOGIN]

            value = session.split(";")[0].split("=", 1)[1]
            assert value.startswith("v1.")
            assert fake.user.email not in value

            exchange = fake.token_requests[0]
            assert exchange["grant_type"] == "authorization_code"
            assert exchange["redirect_uri"] == f"{APP_URL}/auth/callback"
            assert exchange["code_verifier"]

            me = await client.get("/api/me")
            assert me.status_code == 200
            body = me.json()
            signed_in_at = body.pop("auth_time")
            assert type(signed_in_at) is int and abs(signed_in_at - time.time()) < 60
            assert body == {
                "id": "user_1",
                "email": "ada@example.com",
                "email_verified": True,
                "name": "Ada Lovelace",
                "picture": "https://cdn.example.com/ada.png",
                "roles": ["editor"],
                "permissions": ["posts:write"],
                "session_id": "sid_1",
                "amr": ["pwd"],
            }
            builtin = await client.get("/auth/me")
            assert builtin.json() == me.json()
            assert builtin.headers["cache-control"] == "no-store"
            assert (await client.get("/dashboard")).json() == {"name": "Ada Lovelace"}
            assert (await client.get("/maybe")).json() == {"user": "user_1"}

    run(main)


def test_a_replayed_callback_goes_home_without_reusing_the_code() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            start = await client.get("/auth/login")
            callback = fake.authorize(start.headers["location"])
            assert (await client.get(callback)).status_code == 303
            again = await client.get(callback)
        assert again.status_code == 303
        assert again.headers["location"] == "/"
        assert len(fake.token_requests) == 1

    run(main)


@pytest.mark.parametrize("iss", ["https://evil.example", "https://auth.example.com/", None])
def test_callback_refuses_a_response_from_another_issuer(iss: str | None) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            start = await client.get("/auth/login")
            response = await client.get(fake.authorize(start.headers["location"], iss=iss))
            assert response.status_code == 400
            assert "expected server" in page(response)
            assert fake.token_requests == []
            assert SESSION not in set_cookies(response)
            assert (await client.get("/api/me")).status_code == 401

    run(main)


def test_callback_shows_nothing_from_an_error_with_the_wrong_issuer() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            start = await client.get("/auth/login")
            callback = fake.authorize(
                start.headers["location"], error="server_error", iss="https://evil.example"
            )
            callback += "&" + urlencode({"error_description": "Call +1 555 0100 to fix this"})
            response = await client.get(callback)
        assert response.status_code == 400
        assert "555 0100" not in page(response)
        assert "server_error" not in page(response)

    run(main)


def test_callback_refuses_the_wrong_state() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            start = await client.get("/auth/login")
            response = await client.get(fake.authorize(start.headers["location"], state="forged"))
        assert response.status_code == 400
        assert "doesn't match" in page(response)
        assert fake.token_requests == []

    run(main)


def test_callback_without_the_login_cookie_is_refused() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            start = await client.get("/auth/login")
            client.cookies.clear()
            response = await client.get(fake.authorize(start.headers["location"]))
        assert response.status_code == 400
        assert "Sign in expired" in page(response)
        assert fake.token_requests == []

    run(main)


def test_callback_reports_a_cancelled_sign_in() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            start = await client.get("/auth/login")
            response = await client.get(
                fake.authorize(start.headers["location"], error="access_denied")
            )
        assert response.status_code == 400
        assert "cancelled" in page(response)
        assert "Max-Age=0" in set_cookies(response)[LOGIN]

    run(main)


def test_silent_sign_in_failure_returns_to_next() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            start = await client.get("/auth/login", params={"prompt": "none", "next": "/feed"})
            assert fake.par_requests[0]["prompt"] == "none"
            response = await client.get(
                fake.authorize(start.headers["location"], error="login_required")
            )
        assert response.status_code == 303
        assert response.headers["location"] == "/feed"

    run(main)


def _claims_edit(change: Callable[[dict[str, Any]], None]) -> Callable[..., str]:
    def edit(fake: FakeIssuer, claims: dict[str, Any], header: dict[str, Any]) -> str:
        change(claims)
        return fake.sign(claims, typ=header["typ"])

    return edit


def _expired(claims: dict[str, Any]) -> None:
    claims["exp"] = int(time.time()) - 3600
    claims["iat"] = int(time.time()) - 7200


ID_TOKEN_EDITS: dict[str, Callable[..., str]] = {
    "wrong audience": _claims_edit(lambda c: c.update(aud="another_app")),
    "wrong nonce": _claims_edit(lambda c: c.update(nonce="forged")),
    "missing nonce": _claims_edit(lambda c: c.pop("nonce")),
    "wrong issuer": _claims_edit(lambda c: c.update(iss="https://evil.example")),
    "expired": _claims_edit(_expired),
    "wrong at_hash": _claims_edit(lambda c: c.update(at_hash="AAAAAAAAAAAAAAAAAAAAAA")),
    "other azp": _claims_edit(lambda c: c.update(azp="another_app")),
    "alg none": lambda fake, claims, header: unsigned_token(claims),
    "HS256": lambda fake, claims, header: hmac_token(claims),
    "access token typ": lambda fake, claims, header: fake.sign(claims, typ="at+jwt"),
    "unknown key": lambda fake, claims, header: fake.sign(claims, kid="key-9", key_index=9),
    "forged with a known kid": lambda fake, claims, header: fake.sign(
        claims, kid="key-1", key_index=5
    ),
}


@pytest.mark.parametrize("case", sorted(ID_TOKEN_EDITS))
def test_callback_refuses_a_bad_id_token(case: str) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.id_token_edit = ID_TOKEN_EDITS[case]
        app, _ = build(fake)
        async with client_for(app) as client:
            start = await client.get("/auth/login")
            response = await client.get(fake.authorize(start.headers["location"]))
            assert response.status_code == 400, response.text
            assert "couldn't be verified" in page(response)
            assert SESSION not in set_cookies(response)
            assert (await client.get("/api/me")).status_code == 401

    run(main)


def test_an_id_token_without_typ_is_accepted() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.id_token_edit = lambda fake, claims, header: fake.sign(claims, typ=None)
        app, _ = build(fake)
        async with client_for(app) as client:
            await sign_in(client, fake)
            assert (await client.get("/api/me")).status_code == 200

    run(main)


def test_a_tampered_session_cookie_means_signed_out() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            await sign_in(client, fake)
            cookie = jar_cookie(client, SESSION)
            assert cookie is not None and cookie.value is not None
            middle = len(cookie.value) // 2
            flipped = "A" if cookie.value[middle] != "A" else "B"
            cookie.value = cookie.value[:middle] + flipped + cookie.value[middle + 1 :]

            response = await client.get("/api/me")
            assert response.status_code == 401
            assert response.headers["content-type"] == "application/problem+json"
            assert response.json() == {
                "type": "about:blank",
                "title": "Unauthorized",
                "status": 401,
                "detail": "Sign in to continue",
            }
            assert "Max-Age=0" in set_cookies(response)[SESSION]
            page = await client.get("/dashboard")
            assert page.status_code == 303
            assert page.headers["location"] == "/auth/login?next=%2Fdashboard"
            assert (await client.get("/maybe")).json() == {"user": None}

    run(main)


def test_the_login_cookie_cannot_stand_in_for_the_session() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            start = await client.get("/auth/login")
            login_value = set_cookies(start)[LOGIN].split(";")[0].split("=", 1)[1]
            client.cookies.set(SESSION, login_value, domain="app.example.com", path="/")
            response = await client.get("/api/me")
        assert response.status_code == 401

    run(main)


def test_cookie_chunks_round_trip() -> None:
    sealer = CookieSealer([COOKIE_SECRET.encode()], "session", compress=True)
    payload = {"blob": [secrets.token_hex(16) for _ in range(600)]}
    value = sealer.seal(payload)
    chunks = split_value(value)
    assert len(chunks) > 2
    assert all(len(chunk) <= CHUNK_SIZE for chunk in chunks)
    cookies = {f"s.{index}": chunk for index, chunk in enumerate(chunks)}
    assert sealer.unseal(read_value(cookies, "s") or "") == payload
    del cookies["s.1"]
    assert sealer.unseal(read_value(cookies, "s") or "") is None
    other_purpose = CookieSealer([COOKIE_SECRET.encode()], "login state", compress=True)
    assert other_purpose.unseal(value) is None


def test_a_large_session_is_chunked_and_stale_chunks_are_cleared() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.user.permissions = [f"perm:{secrets.token_hex(8)}" for _ in range(300)]
        fake.access_ttl = 1
        app, _ = build(fake, keep_access_token=True)
        async with client_for(app) as client:
            done = await sign_in(client, fake)
            names = set(set_cookies(done)) - {LOGIN}
            assert SESSION not in names
            assert len(names) >= 2
            assert names == {f"{SESSION}.{index}" for index in range(len(names))}
            for header in set_cookies(done).values():
                assert len(header) < 4096

            fake.access_ttl = 600
            fake.user.permissions = ["posts:write"]
            response = await client.get("/api/me")
            assert response.status_code == 200
            assert response.json()["permissions"] == ["posts:write"]
            written = set_cookies(response)
            assert "Max-Age=0" not in written[SESSION]
            for name in names:
                assert "Max-Age=0" in written[name]
            assert jar_names(client) == {SESSION}
            assert (await client.get("/api/me")).status_code == 200

    run(main)


def test_refresh_rotates_tokens_and_rewrites_the_cookie_on_any_response() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.access_ttl = 1
        app, _ = build(fake)
        async with client_for(app) as client:
            await sign_in(client, fake)
            before = jar_cookie(client, SESSION)
            assert before is not None
            old_value = before.value
            [first_refresh_token] = fake.issued_refresh_tokens

            fake.access_ttl = 600
            fake.user.roles = ["editor", "admin"]
            response = await client.get("/plain")
            assert response.status_code == 200
            assert response.text == "hello user_1"
            assert SESSION in set_cookies(response)
            assert response.headers["cache-control"] == "no-store"
            assert fake.refreshes() == 1
            assert fake.token_requests[-1]["refresh_token"] == first_refresh_token
            assert len(fake.issued_refresh_tokens) == 2
            after = jar_cookie(client, SESSION)
            assert after is not None and after.value != old_value

            deleted = await client.delete("/posts/1", headers=SAME_SITE)
            assert deleted.status_code == 200
            assert fake.refreshes() == 1

    run(main)


def test_an_old_cookie_right_after_a_refresh_reuses_the_result() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.access_ttl = 1
        app, _ = build(fake)
        async with client_for(app) as client:
            await sign_in(client, fake)
            cookie = jar_cookie(client, SESSION)
            assert cookie is not None
            old_value = cookie.value
            fake.access_ttl = 600
            assert (await client.get("/api/me")).status_code == 200
            refreshed = jar_cookie(client, SESSION)
            assert refreshed is not None
            refreshed.value = old_value
            again = await client.get("/api/me")
        assert again.status_code == 200
        assert fake.refreshes() == 1

    run(main)


def test_parallel_requests_share_one_refresh() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.access_ttl = 1
        app, _ = build(fake)
        async with client_for(app) as client:
            await sign_in(client, fake)
            fake.access_ttl = 600
            fake.token_delay = 0.05
            responses = await asyncio.gather(*(client.get("/api/me") for _ in range(5)))
            assert [response.status_code for response in responses] == [200] * 5
            assert fake.refreshes() == 1
            assert (await client.get("/api/me")).status_code == 200
            assert fake.refreshes() == 1

    run(main)


def test_invalid_grant_on_refresh_signs_the_user_out() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.access_ttl = 1
        app, _ = build(fake)
        async with client_for(app) as client:
            await sign_in(client, fake)
            fake.end_sessions()
            response = await client.get("/api/me")
            assert response.status_code == 401
            assert "Max-Age=0" in set_cookies(response)[SESSION]
            assert jar_cookie(client, SESSION) is None

    run(main)


def test_a_refreshed_id_token_has_no_nonce_and_keeps_the_sign_in_details() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.access_ttl = 1
        fake.user.amr = ["pwd", "otp", "mfa"]
        fake.last_sign_in = int(time.time()) - 120
        issued: list[dict[str, Any]] = []

        def record(fake: FakeIssuer, claims: dict[str, Any], header: dict[str, Any]) -> str:
            issued.append(dict(claims))
            return fake.sign(claims, typ=header["typ"])

        fake.id_token_edit = record
        app, _ = build(fake)
        async with client_for(app) as client:
            await sign_in(client, fake)
            fake.access_ttl = 600
            body = (await client.get("/api/me")).json()
        assert fake.refreshes() == 1
        assert "nonce" in issued[0] and "nonce" not in issued[1]
        assert issued[1]["auth_time"] == issued[0]["auth_time"] == fake.last_sign_in
        assert body["amr"] == ["mfa", "otp", "pwd"]
        assert body["auth_time"] == fake.last_sign_in

    run(main)


def test_two_workers_refreshing_one_cookie_in_the_grace_window_both_stay_signed_in() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.now = Clock()
        fake.access_ttl = 1
        first, _ = build(fake)
        second, _ = build(fake)
        async with client_for(first) as one, client_for(second) as two:
            await sign_in(one, fake)
            cookie = jar_cookie(one, SESSION)
            assert cookie is not None
            old = {"Cookie": f"{SESSION}={cookie.value}"}
            fake.access_ttl = 600
            assert (await one.get("/api/me")).status_code == 200
            fake.now.advance(10)
            assert (await two.get("/api/me", headers=old)).status_code == 200
        assert fake.refreshes() == 2
        # Inside the grace window the old token gets the same next token.
        assert fake.issued_refresh_tokens[-1] == fake.issued_refresh_tokens[-2]

    run(main)


def test_reusing_an_old_refresh_token_later_signs_out_everywhere() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.now = Clock()
        fake.access_ttl = 1
        first, _ = build(fake)
        second, _ = build(fake)
        async with client_for(first) as one, client_for(second) as two:
            await sign_in(one, fake)
            cookie = jar_cookie(one, SESSION)
            assert cookie is not None
            old = {"Cookie": f"{SESSION}={cookie.value}"}
            assert (await one.get("/api/me")).status_code == 200
            fake.now.advance(31)
            replayed = await two.get("/api/me", headers=old)
            assert replayed.status_code == 401
            assert "Max-Age=0" in set_cookies(replayed)[SESSION]
            # The reuse revoked the whole chain, so the rotated token is dead too.
            after = await one.get("/api/me")
            assert after.status_code == 401
            assert jar_cookie(one, SESSION) is None
        assert fake.refresh_families == {}

    run(main)


def test_optional_treats_a_cross_site_post_as_signed_out() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, auth = build(fake)

        @app.post("/comment")
        async def comment(user: User | None = Depends(auth.optional)) -> dict[str, Any]:
            return {"user": user.id if user else None}

        evil = {"Origin": "https://evil.example"}
        async with client_for(app) as client:
            await sign_in(client, fake)
            cross_site = await client.post("/comment", headers=evil)
            assert cross_site.status_code == 200
            assert cross_site.json() == {"user": None}
            assert "set-cookie" not in cross_site.headers
            assert (await client.post("/comment", headers=SAME_SITE)).json() == {"user": "user_1"}
            assert (await client.post("/posts", headers=evil)).status_code == 403
            assert (await client.get("/api/me")).status_code == 200

    run(main)


def test_a_failed_refresh_keeps_the_session_for_a_grace_period() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.access_ttl = 1
        app, _ = build(fake)
        async with client_for(app) as client:
            await sign_in(client, fake)
            fake.token_error = "temporarily_unavailable"
            response = await client.get("/api/me")
        assert response.status_code == 200
        assert SESSION not in set_cookies(response)

    run(main)


def test_a_session_without_a_refresh_token_ends_with_the_access_token() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.issue_refresh_tokens = False
        fake.access_ttl = 0
        app, _ = build(fake)
        async with client_for(app) as client:
            await sign_in(client, fake)
            response = await client.get("/api/me")
        assert response.status_code == 401
        assert fake.refreshes() == 0

    run(main)


def test_a_refreshed_id_token_for_another_user_signs_out() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.access_ttl = 1
        app, _ = build(fake)
        async with client_for(app) as client:
            await sign_in(client, fake)
            fake.id_token_edit = _claims_edit(lambda c: c.update(sub="user_2"))
            response = await client.get("/api/me")
        assert response.status_code == 401

    run(main)


def test_cross_site_unsafe_requests_are_refused() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            signed_out = await client.post("/posts", headers={"Origin": "https://evil.example"})
            assert signed_out.status_code == 401

            await sign_in(client, fake)
            evil = await client.post("/posts", headers={"Origin": "https://evil.example"})
            assert evil.status_code == 403
            assert evil.json()["detail"] == "This request came from another site"
            assert (await client.post("/posts", headers={"Origin": "null"})).status_code == 403
            assert (await client.post("/posts")).status_code == 403
            lookalike = await client.post(
                "/posts", headers={"Referer": "https://app.example.com.evil.example/"}
            )
            assert lookalike.status_code == 403

            assert (await client.post("/posts", headers=SAME_SITE)).json() == {"by": "user_1"}
            referred = await client.post("/posts", headers={"Referer": f"{APP_URL}/editor"})
            assert referred.status_code == 200

    run(main)


def test_require_answers_403_problem_json() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            signed_out = await client.delete("/posts/1", headers=SAME_SITE)
            assert signed_out.status_code == 401
            page = await client.get("/admin")
            assert page.status_code == 303
            assert page.headers["location"] == "/auth/login?next=%2Fadmin"

            await sign_in(client, fake)
            response = await client.delete("/posts/1", headers=SAME_SITE)
            assert response.status_code == 403
            assert response.headers["content-type"] == "application/problem+json"
            assert response.json() == {
                "type": "about:blank",
                "title": "Forbidden",
                "status": 403,
                "detail": "You don't have permission to do this",
            }
            assert (await client.get("/admin")).status_code == 403

    run(main)


@pytest.mark.parametrize("registered", ["before", "after"])
def test_an_app_can_render_its_own_refusal_pages(registered: str) -> None:
    async def denied(request: Request, exc: Exception) -> Response:
        if "text/html" in request.headers.get("accept", ""):
            return HTMLResponse("<h1>No entry</h1>", status_code=403)
        return await refusal_response(request, exc)

    async def main() -> None:
        fake = FakeIssuer()
        app = FastAPI()
        if registered == "before":
            app.add_exception_handler(PermissionDenied, denied)
        app, _ = build(fake, app)
        if registered == "after":
            app.add_exception_handler(PermissionDenied, denied)
        async with client_for(app) as client:
            await sign_in(client, fake)
            page = await client.get("/admin", headers={"Accept": "text/html"})
            assert page.status_code == 403
            assert page.text == "<h1>No entry</h1>"
            api = await client.delete("/posts/1", headers=SAME_SITE)
            assert api.status_code == 403
            assert api.headers["content-type"] == "application/problem+json"
            assert api.json()["detail"] == "You don't have permission to do this"
            signed_out = await client.post("/auth/logout", headers=SAME_SITE)
            assert signed_out.status_code in (303, 307)
            assert (await client.get("/api/me")).status_code == 401

    run(main)


def test_logout_revokes_and_ends_the_session_at_microauth() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake)
        async with client_for(app) as client:
            await sign_in(client, fake)
            [refresh_token] = fake.issued_refresh_tokens

            cross_site = await client.post(
                "/auth/logout", headers={"Origin": "https://evil.example"}
            )
            assert cross_site.status_code == 403
            assert (await client.get("/api/me")).status_code == 200

            response = await client.post("/auth/logout", headers=SAME_SITE)
            assert response.status_code == 303
            location = urlsplit(response.headers["location"])
            assert f"{location.scheme}://{location.netloc}{location.path}" == fake.url(
                "/oauth/logout"
            )
            query = {name: values[0] for name, values in parse_qs(location.query).items()}
            assert query["post_logout_redirect_uri"] == f"{APP_URL}/"
            assert query["client_id"] == CLIENT_ID
            assert query["state"]
            hint = jwt.decode(query["id_token_hint"], options={"verify_signature": False})
            assert hint["sub"] == "user_1"
            assert fake.revoked == [{"token": refresh_token, "token_type_hint": "refresh_token"}]
            assert "Max-Age=0" in set_cookies(response)[SESSION]
            assert (await client.get("/api/me")).status_code == 401

            again = await client.post("/auth/logout", headers=SAME_SITE)
            assert again.status_code == 303
            assert again.headers["location"] == "/"

    run(main)


@pytest.mark.parametrize(
    "override",
    [
        {"issuer": "https://other.example"},
        {"code_challenge_methods_supported": ["plain"]},
        {"token_endpoint": None},
    ],
)
def test_an_issuer_that_cannot_run_the_flow_is_refused(override: dict[str, Any]) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.discovery_overrides = override
        app, _ = build(fake)
        async with client_for(app) as client:
            response = await client.get("/auth/login")
        assert response.status_code == 503
        assert "Sign in is unavailable" in page(response)
        assert fake.par_requests == []

    run(main)


def test_plain_http_on_localhost_uses_plain_cookie_names() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, auth = build(fake, app_url="http://localhost:8000")
        assert auth.session_cookie == "microauth"
        async with client_for(app, "http://localhost:8000") as client:
            done = await sign_in(client, fake)
            session = set_cookies(done)["microauth"]
            assert "Secure" not in session
            assert "HttpOnly" in session
            assert fake.par_requests[0]["redirect_uri"] == "http://localhost:8000/auth/callback"
            assert (await client.get("/api/me")).status_code == 200

    run(main)


def test_cookie_secrets_rotate() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        old_secret, new_secret = COOKIE_SECRET, "rotated-secret-" + "n" * 40
        old_app, _ = build(fake)
        async with client_for(old_app) as client:
            await sign_in(client, fake)
            cookie = jar_cookie(client, SESSION)
            assert cookie is not None and cookie.value is not None
            value = cookie.value

        rotated_app, _ = build(fake, cookie_secret=f"{new_secret},{old_secret}")
        async with client_for(rotated_app) as client:
            client.cookies.set(SESSION, value, domain="app.example.com", path="/")
            assert (await client.get("/api/me")).status_code == 200

        retired_app, _ = build(fake, cookie_secret=new_secret)
        async with client_for(retired_app) as client:
            client.cookies.set(SESSION, value, domain="app.example.com", path="/")
            response = await client.get("/api/me")
            assert response.status_code == 401
            assert "Max-Age=0" in set_cookies(response)[SESSION]

    run(main)


def test_access_token_is_kept_for_server_side_calls() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, auth = build(fake, keep_access_token=True, resource=API)

        api = TokenAuth(issuer=fake.issuer, resource=API, http_client=fake.client())

        @app.get("/token-audience")
        async def audience(request: Request) -> dict[str, Any]:
            token = await auth.access_token(request)
            assert token is not None
            return {"aud": jwt.decode(token, options={"verify_signature": False})["aud"]}

        @app.get("/call-api")
        async def call_api(request: Request) -> dict[str, Any]:
            token = await auth.access_token(request)
            assert token is not None
            claims = await api.verifier.verify(token)
            return {"audience": list(claims.audience), "session_id": claims.session_id}

        async with client_for(app) as client:
            await sign_in(client, fake)
            assert fake.par_requests[0]["resource"] == API
            assert fake.token_requests[0]["resource"] == API
            # The real server adds the issuer to aud when openid was granted.
            assert (await client.get("/token-audience")).json() == {"aud": [API, fake.issuer]}
            assert (await client.get("/call-api")).json() == {
                "audience": [API, fake.issuer],
                "session_id": "sid_1",
            }

    run(main)


def test_offline_access_tokens_leave_out_sid_but_the_user_keeps_a_session_id() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, auth = build(
            fake,
            keep_access_token=True,
            resource=API,
            scopes=["openid", "profile", "email", "roles", "offline_access"],
        )
        api = TokenAuth(issuer=fake.issuer, resource=API, http_client=fake.client())

        @app.get("/call-api")
        async def call_api(request: Request, user: User = Depends(auth.user)) -> dict[str, Any]:
            token = await auth.access_token(request)
            assert token is not None
            claims = await api.verifier.verify(token)
            return {"token_session": claims.session_id, "user_session": user.session_id}

        async with client_for(app) as client:
            await sign_in(client, fake)
            response = await client.get("/call-api")
        assert response.json() == {"token_session": None, "user_session": "sid_1"}

    run(main)


def test_the_id_token_carries_only_the_claims_its_scopes_allow() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake, scopes=["openid", "profile"])
        async with client_for(app) as client:
            await sign_in(client, fake)
            body = (await client.get("/api/me")).json()
        assert body["name"] == "Ada Lovelace"
        assert body["email"] is None
        assert body["email_verified"] is False
        assert body["roles"] == [] and body["permissions"] == []

    run(main)


def test_access_token_needs_keep_access_token() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, auth = build(fake)

        @app.get("/token")
        async def token(request: Request) -> dict[str, Any]:
            with pytest.raises(MicroAuthConfigurationError):
                await auth.access_token(request)
            return {}

        async with client_for(app) as client:
            assert (await client.get("/token")).status_code == 200

    run(main)


def test_settings_come_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MICROAUTH_ISSUER", "https://auth.example.com")
    monkeypatch.setenv("MICROAUTH_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("MICROAUTH_CLIENT_SECRET", CLIENT_SECRET)
    monkeypatch.setenv("MICROAUTH_COOKIE_SECRET", COOKIE_SECRET)
    monkeypatch.setenv("MICROAUTH_APP_URL", "https://app.example.com/")
    auth = UserAuth()
    assert auth.issuer == "https://auth.example.com"
    assert auth.redirect_uri == "https://app.example.com/auth/callback"
    assert auth.session_cookie == SESSION
    assert auth.login_cookie == LOGIN


@pytest.mark.parametrize(
    "override",
    [
        {"cookie_secret": "too-short"},
        {"cookie_secret": f"{COOKIE_SECRET},short"},
        {"issuer": "http://auth.example.com"},
        {"issuer": "https://auth.example.com/tenant"},
        {"app_url": "https://app.example.com/base"},
        {"app_url": "http://app.example.com"},
        {"after_sign_in": "https://evil.example/"},
        {"prefix": "auth"},
        {"client_id": ""},
        {"scopes": ["openid", "bad scope"]},
        {"cookie_name": "bad name"},
    ],
)
def test_bad_settings_are_refused(override: dict[str, Any]) -> None:
    settings: dict[str, Any] = {
        "issuer": "https://auth.example.com",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "cookie_secret": COOKIE_SECRET,
        "app_url": APP_URL,
    }
    settings.update(override)
    with pytest.raises(MicroAuthConfigurationError):
        UserAuth(**settings)


def test_user_checks_roles_and_permissions() -> None:
    user = user_from_claims(
        {"sub": "u1", "roles": ["editor", 7], "permissions": ["a", "b"], "email_verified": "yes"}
    )
    assert user.has_role("editor") and not user.has_role("editor", "admin")
    assert user.has_permission("a", "b") and not user.has_permission("c")
    assert user.roles == frozenset({"editor"})
    assert user.email_verified is False
