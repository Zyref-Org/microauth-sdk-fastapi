"""API keys at MCP servers: McpAuth(api_keys=True) and MicroAuthTokenVerifier(api_keys=True)."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from oidc_fake import MCP, MCP_CLIENT_ID, MCP_SECRET, Clock, FakeIssuer, make_key

from microauth_fastapi import (
    McpAuth,
    MicroAuthConfigurationError,
    MicroAuthTokenVerifier,
    current_identity,
)

HOST = "https://mcp.example.com"
PROTOCOL = "2026-07-28"
HAS_MCP = importlib.util.find_spec("mcp") is not None
KEY_SETTINGS = {
    "api_keys": True,
    "resource_client_id": MCP_CLIENT_ID,
    "resource_secret": MCP_SECRET,
}


class StandInServer:
    """Records who reached it and answers every message with an empty result."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                else:
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        identity = current_identity()
        self.calls.append(
            {
                "sub": identity.sub,
                "via": identity.via,
                "key_id": identity.key_id,
                "auth": sorted(scope["auth"].scopes),
                "user": scope.get("user"),
            }
        )
        request_id = json.loads(body).get("id") if body else None
        payload = json.dumps({"jsonrpc": "2.0", "id": request_id, "result": {}})
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": payload.encode()})


def make_auth(fake: FakeIssuer, clock: Clock | None = None, **options: Any) -> McpAuth:
    settings: dict[str, Any] = {
        "issuer": fake.issuer,
        "resource": MCP,
        "scopes": ["invoices:read"],
        "http_client": fake.client(),
        **KEY_SETTINGS,
    }
    settings.update(options)
    auth = McpAuth(**settings)
    if clock is not None:
        assert auth.key_checks is not None
        auth.key_checks.clock = clock
        fake.now = clock

    @auth.tool("invoices:read")
    def list_invoices() -> None: ...

    @auth.tool("invoices:write", name="create_invoice")
    def create() -> None: ...

    return auth


def client_for(app: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=HOST)


def call(tool: str, credential: str | None) -> dict[str, Any]:
    headers = {
        "MCP-Protocol-Version": PROTOCOL,
        "Mcp-Method": "tools/call",
        "Mcp-Name": tool,
        "Accept": "application/json, text/event-stream",
    }
    if credential is not None:
        headers["Authorization"] = f"Bearer {credential}"
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {}},
    }
    return {"json": message, "headers": headers}


def refused(response: httpx.Response) -> tuple[str | None, str]:
    """The OAuth error code, or None without one, and the sentence of a JSON-RPC refusal."""
    body = response.json()
    assert body["jsonrpc"] == "2.0" and body["id"] is None
    assert body["error"]["code"] == response.status_code
    data = body["error"].get("data")
    return (None if data is None else data["error"]), body["error"]["message"]


def run(test: Callable[[], Any]) -> None:
    asyncio.run(test())


def test_a_key_calls_tools_its_permissions_allow() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        server = StandInServer()
        app = make_auth(fake).wrap(server)
        key = fake.add_key(resources=[MCP], permissions=["invoices:read", "invoices:write"])
        async with client_for(app) as client:
            listed = await client.post("/mcp", **call("list_invoices", key.secret))
            assert listed.status_code == 200, listed.text
            created = await client.post("/mcp", **call("create_invoice", key.secret))
            assert created.status_code == 200
        assert server.calls[0]["sub"] == "user_1"
        assert server.calls[0]["via"] == "api_key"
        assert server.calls[0]["key_id"] == key.id
        assert server.calls[0]["auth"] == ["invoices:read", "invoices:write"]
        if HAS_MCP:
            user = server.calls[0]["user"]
            assert user.access_token.client_id == key.id
            assert user.access_token.token == key.secret
            assert user.access_token.scopes == ["invoices:read", "invoices:write"]
            assert user.access_token.expires_at is None

    run(main)


def test_a_key_missing_a_tool_scope_gets_403() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        server = StandInServer()
        app = make_auth(fake).wrap(server)
        key = fake.add_key(resources=[MCP], permissions=["invoices:read"])
        async with client_for(app) as client:
            response = await client.post("/mcp", **call("create_invoice", key.secret))
            fake.add_key(resources=[MCP], permissions=["other"], name="Bare")
            bare = fake.api_keys[list(fake.api_keys)[-1]]
            nothing = await client.post("/mcp", **call("create_invoice", bare.secret))
        assert response.status_code == 403
        challenge = response.headers["www-authenticate"]
        assert 'error="insufficient_scope"' in challenge
        assert 'scope="invoices:read invoices:write"' in challenge
        description = (
            "The create_invoice tool needs the invoices:write permission, and this API key "
            "doesn't have it"
        )
        assert f'error_description="{description}"' in challenge
        assert response.json()["error"]["message"] == description + "."
        assert response.json()["error"]["data"]["error"] == "insufficient_scope"
        assert nothing.json()["error"]["message"] == (
            "The create_invoice tool needs the invoices:read and invoices:write permissions, "
            "and this API key doesn't have them."
        )
        assert server.calls == []

    run(main)


def test_an_unknown_key_gets_invalid_token() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app = make_auth(fake).wrap(StandInServer())
        async with client_for(app) as client:
            unknown = await client.post("/mcp", **call("list_invoices", make_key()))
            mistyped = await client.post("/mcp", **call("list_invoices", "cms_" + "0" * 46))
            missing = await client.post("/mcp", **call("list_invoices", None))
        assert unknown.status_code == 401
        assert refused(unknown) == (
            "invalid_token",
            "The API key is unknown, revoked or expired.",
        )
        assert 'error_description="The API key is unknown' in unknown.headers["www-authenticate"]
        assert mistyped.status_code == 401
        assert refused(mistyped)[0] == "invalid_token"
        assert "mistyped" in refused(mistyped)[1]
        assert 'error="invalid_token"' in mistyped.headers["www-authenticate"]
        assert refused(missing) == (
            None,
            "Send a MicroAuth access token or API key in the Authorization header.",
        )
        assert "error=" not in missing.headers["www-authenticate"]
        assert len(fake.introspections) == 1

    run(main)


def test_a_key_for_another_server_is_refused() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app = make_auth(fake).wrap(StandInServer())
        key = fake.add_key(permissions=["invoices:read"])
        async with client_for(app) as client:
            response = await client.post("/mcp", **call("list_invoices", key.secret))
        assert response.status_code == 401

    run(main)


def test_limits_answer_429_with_retry_after() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        clock = Clock()
        app = make_auth(fake, clock, unknown_key_limit=1).wrap(StandInServer())
        key = fake.add_key(resources=[MCP], permissions=["invoices:read"], requests_per_minute=1)
        async with client_for(app) as client:
            assert (
                await client.post("/mcp", **call("list_invoices", key.secret))
            ).status_code == 200
            over = await client.post("/mcp", **call("list_invoices", key.secret))
            assert over.status_code == 429
            assert over.headers["retry-after"] == "60"
            assert refused(over) == (
                "rate_limited",
                "This API allows 1 requests a minute with each person's API keys.",
            )
            assert (
                await client.post("/mcp", **call("list_invoices", make_key()))
            ).status_code == 401
            throttled = await client.post("/mcp", **call("list_invoices", make_key()))
            assert throttled.status_code == 429
            assert refused(throttled)[1] == "Too many unknown API keys came from this address."

    run(main)


def test_the_client_address_function_sees_the_request() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        seen: list[str | None] = []

        def address(request: Any) -> str | None:
            seen.append(request.headers.get("x-real-ip"))
            return request.headers.get("x-real-ip")

        app = make_auth(fake, client_address=address).wrap(StandInServer())
        key = fake.add_key(resources=[MCP], permissions=["invoices:read"])
        async with client_for(app) as client:
            request = call("list_invoices", key.secret)
            request["headers"]["X-Real-IP"] = "198.51.100.7"
            assert (await client.post("/mcp", **request)).status_code == 200
        assert seen == ["198.51.100.7"]

    run(main)


def test_an_outage_answers_503() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.introspect_failure = 502
        app = make_auth(fake).wrap(StandInServer())
        key = fake.add_key(resources=[MCP], permissions=["invoices:read"])
        async with client_for(app) as client:
            response = await client.post("/mcp", **call("list_invoices", key.secret))
        assert response.status_code == 503
        assert refused(response) == (
            "temporarily_unavailable",
            "Authorization is temporarily unavailable.",
        )
        assert response.headers["retry-after"] == "5"

    run(main)


def test_tokens_keys_and_secrets_never_reach_the_logs(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)

    async def main() -> list[str]:
        fake = FakeIssuer()
        auth = make_auth(fake)
        app = auth.wrap(StandInServer())
        reader = fake.access_token(aud=MCP, scope="invoices:read")
        expired = fake.access_token(aud=MCP, scope="invoices:read", exp=1)
        elsewhere = fake.access_token(aud="https://other.example.com", scope="invoices:read")
        key = fake.add_key(resources=[MCP], permissions=["invoices:read"])
        unknown = make_key()
        async with client_for(app) as client:
            for tool, credential in [
                ("list_invoices", reader),
                ("create_invoice", reader),
                ("list_invoices", expired),
                ("list_invoices", elsewhere),
                ("list_invoices", key.secret),
                ("create_invoice", key.secret),
                ("list_invoices", unknown),
                ("list_invoices", reader[:-4]),
            ]:
                await client.post("/mcp", **call(tool, credential))
            fake.introspect_failure = 502
            other = fake.add_key(resources=[MCP], permissions=["invoices:read"])
            refused = await client.post("/mcp", **call("list_invoices", other.secret))
            assert refused.status_code == 503
        await auth.aclose()
        return [reader, expired, elsewhere, key.secret, unknown, other.secret, MCP_SECRET]

    secrets = asyncio.run(main())
    assert caplog.records
    for secret in secrets:
        assert secret not in caplog.text
        assert secret[-12:] not in caplog.text


def test_mcp_keys_are_off_by_default() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        auth = make_auth(fake, api_keys=False)
        assert auth.key_checks is None
        key = fake.add_key(resources=[MCP], permissions=["invoices:read"])
        async with client_for(auth.wrap(StandInServer())) as client:
            response = await client.post("/mcp", **call("list_invoices", key.secret))
            missing = await client.post("/mcp", **call("list_invoices", None))
        assert response.status_code == 401
        assert refused(missing) == (
            None,
            "Send a MicroAuth access token in the Authorization header.",
        )
        assert fake.introspections == []

    run(main)


def test_mcp_keys_need_the_mcp_servers_credentials() -> None:
    fake = FakeIssuer()
    classes: list[Any] = [McpAuth]
    if HAS_MCP:
        classes.append(MicroAuthTokenVerifier)
    for cls in classes:
        with pytest.raises(MicroAuthConfigurationError) as caught:
            cls(issuer=fake.issuer, resource=MCP, api_keys=True)
        assert str(caught.value) == (
            "API keys need this MCP server's server credentials. Set "
            "MICROAUTH_RESOURCE_CLIENT_ID and MICROAUTH_RESOURCE_SECRET, or pass "
            "resource_client_id= and resource_secret=. They're on the MCP server's page in "
            "the MicroAuth dashboard: open APIs and MCP servers, then the server, then "
            "Server credentials."
        )


@pytest.mark.parametrize(
    "given", [{"resource_client_id": MCP_CLIENT_ID}, {"resource_secret": MCP_SECRET}]
)
def test_mcp_server_credentials_come_as_a_pair(
    monkeypatch: pytest.MonkeyPatch, given: dict[str, str]
) -> None:
    fake = FakeIssuer()
    monkeypatch.setenv("MICROAUTH_RESOURCE_CLIENT_ID", "rs_api")
    monkeypatch.setenv("MICROAUTH_RESOURCE_SECRET", "the-api-secret")
    classes: list[Any] = [McpAuth]
    if HAS_MCP:
        classes.append(MicroAuthTokenVerifier)
    for cls in classes:
        with pytest.raises(MicroAuthConfigurationError, match="together"):
            cls(issuer=fake.issuer, resource=MCP, api_keys=True, **given)


def test_shutdown_empties_the_key_cache() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        auth = make_auth(fake)
        app = auth.wrap(StandInServer())
        key = fake.add_key(resources=[MCP], permissions=["invoices:read"])
        async with client_for(app) as client:
            assert (
                await client.post("/mcp", **call("list_invoices", key.secret))
            ).status_code == 200
        assert auth.key_checks is not None
        answers = auth.key_checks.introspector.answers
        assert answers._entries  # type: ignore[attr-defined]

        messages = iter([{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}])
        sent: list[str] = []

        async def receive() -> dict[str, Any]:
            return next(messages)

        async def send(message: dict[str, Any]) -> None:
            sent.append(message["type"])

        await app({"type": "lifespan", "asgi": {"version": "3.0"}}, receive, send)
        assert sent == ["lifespan.startup.complete", "lifespan.shutdown.complete"]
        assert not answers._entries  # type: ignore[attr-defined]

    run(main)


# The MCP SDK's own auth


@pytest.mark.skipif(not HAS_MCP, reason="the MCP SDK is not installed")
def test_the_sdk_verifier_accepts_keys(caplog: pytest.LogCaptureFixture) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        verifier = MicroAuthTokenVerifier(
            issuer=fake.issuer, resource=MCP, http_client=fake.client(), **KEY_SETTINGS
        )
        key = fake.add_key(
            resources=[MCP],
            permissions=["invoices:read"],
            requests_per_minute=1,
            expires_at=int(fake.now()) + 3600,
        )
        for _ in range(3):
            access = await verifier.verify_token(key.secret)
            assert access is not None
        assert access.client_id == key.id
        assert access.scopes == ["invoices:read"]
        assert access.expires_at == key.expires_at
        assert access.resource == MCP
        assert await verifier.verify_token(make_key()) is None
        assert await verifier.verify_token("cms_short") is None
        assert await verifier.verify_token(fake.access_token(aud=MCP)) is not None
        for _ in range(30):
            assert await verifier.verify_token(make_key()) is None
        fake.introspect_failure = httpx.ConnectError
        assert await verifier.verify_token(make_key()) is None
        warnings = [r for r in caplog.records if "doesn't enforce requests_per_minute" in r.message]
        assert len(warnings) == 1
        await verifier.aclose()

    caplog.set_level(logging.WARNING, logger="microauth")
    run(main)


@pytest.mark.skipif(not HAS_MCP, reason="the MCP SDK is not installed")
def test_the_sdk_verifier_refuses_keys_by_default() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        verifier = MicroAuthTokenVerifier(
            issuer=fake.issuer, resource=MCP, http_client=fake.client()
        )
        assert verifier.key_checks is None
        key = fake.add_key(resources=[MCP])
        assert await verifier.verify_token(key.secret) is None
        assert fake.introspections == []

    run(main)
