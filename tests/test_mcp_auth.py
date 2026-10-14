from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
import logging
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from oidc_fake import FakeIssuer

from microauth_fastapi import McpAuth, MicroAuthTokenVerifier, current_identity

RESOURCE = "https://mcp.example.com/mcp"
HOST = "https://mcp.example.com"
METADATA = f"{HOST}/.well-known/oauth-protected-resource/mcp"
PROTOCOL = "2026-07-28"
HAS_MCP = importlib.util.find_spec("mcp") is not None


class StandInServer:
    """A stand in MCP server that records what reached it."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.lifespans = 0

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            self.lifespans += 1
            message = await receive()
            assert message["type"] == "lifespan.startup"
            await send({"type": "lifespan.startup.complete"})
            return
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        try:
            sub: str | None = current_identity().sub
        except LookupError:
            sub = None
        self.calls.append(
            {
                "method": scope["method"],
                "body": body,
                "sub": sub,
                "user": scope.get("user"),
                "auth": scope.get("auth"),
            }
        )
        request_id = json.loads(body).get("id") if body else None
        payload = json.dumps({"jsonrpc": "2.0", "id": request_id, "result": {"sub": sub}})
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": payload.encode()})


def make_auth(fake: FakeIssuer, **options: Any) -> McpAuth:
    settings: dict[str, Any] = {
        "issuer": fake.issuer,
        "resource": RESOURCE,
        "scopes": ["invoices:read"],
        "http_client": fake.client(),
    }
    settings.update(options)
    auth = McpAuth(**settings)

    @auth.tool("invoices:read")
    def list_invoices() -> None: ...

    @auth.tool("invoices:write", name="create_invoice")
    def create() -> None: ...

    return auth


def client_for(app: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=HOST)


def token(fake: FakeIssuer, scope: str = "invoices:read", **overrides: Any) -> str:
    return fake.access_token(aud=RESOURCE, scope=scope, **overrides)


def rpc(method: str, params: dict[str, Any] | None = None, request_id: int = 1) -> dict[str, Any]:
    message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    return message


def headers(
    method: str, name: str | None = None, access_token: str | None = None
) -> dict[str, str]:
    found = {
        "MCP-Protocol-Version": PROTOCOL,
        "Mcp-Method": method,
        "Accept": "application/json, text/event-stream",
    }
    if name is not None:
        found["Mcp-Name"] = name
    if access_token is not None:
        found["Authorization"] = f"Bearer {access_token}"
    return found


def call(tool: str, access_token: str | None, request_id: int = 1) -> dict[str, Any]:
    return {
        "json": rpc("tools/call", {"name": tool, "arguments": {}}, request_id),
        "headers": headers("tools/call", tool, access_token),
    }


def run(test: Callable[[], Any]) -> None:
    asyncio.run(test())


def test_no_token_gets_401_with_the_metadata_url_and_scope() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        server = StandInServer()
        app = make_auth(fake).wrap(server)
        async with client_for(app) as client:
            response = await client.post(
                "/mcp", json=rpc("tools/list"), headers=headers("tools/list")
            )
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == (
            f'Bearer resource_metadata="{METADATA}", scope="invoices:read"'
        )
        assert response.json() == {
            "jsonrpc": "2.0",
            "id": None,
            "error": {
                "code": 401,
                "message": "Send a MicroAuth access token in the Authorization header.",
                "data": {"error": "invalid_token"},
            },
        }
        assert server.calls == []
        async with client_for(app) as client:
            stream = await client.get("/mcp", headers=headers("tools/list"))
        assert stream.status_code == 401
        assert stream.json() == {
            "error": "invalid_token",
            "error_description": "Send a MicroAuth access token in the Authorization header",
        }

    run(main)


def test_a_token_for_another_resource_gets_invalid_token() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        server = StandInServer()
        app = make_auth(fake).wrap(server)
        other = fake.access_token(aud="https://api.example.com", scope="invoices:read")
        async with client_for(app) as client:
            response = await client.post(
                "/mcp", json=rpc("tools/list"), headers=headers("tools/list", None, other)
            )
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == (
            'Bearer error="invalid_token", '
            'error_description="The token was issued for a different audience", '
            f'resource_metadata="{METADATA}", scope="invoices:read"'
        )
        assert server.calls == []

    run(main)


def test_metadata_is_served_only_at_the_path_inserted_url() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        server = StandInServer()
        auth = make_auth(fake)
        app = auth.wrap(server)
        expected = {
            "resource": RESOURCE,
            "authorization_servers": [fake.issuer],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["invoices:read"],
        }
        assert auth.metadata_url == METADATA
        path = "/.well-known/oauth-protected-resource/mcp"
        async with client_for(app) as client:
            response = await client.get(path)
            assert response.status_code == 200
            assert response.json() == expected
            assert response.headers["access-control-allow-origin"] == "*"
            assert (await client.head(path)).status_code == 200
            assert (await client.options(path)).status_code == 204
            assert (await client.post(path)).status_code == 405
            assert server.calls == []
            root = await client.get("/.well-known/oauth-protected-resource")
            assert root.status_code == 401
        assert server.calls == []

    run(main)


def test_a_resource_without_a_path_serves_metadata_at_the_root() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        server = StandInServer()
        auth = make_auth(fake, resource=HOST)
        assert auth.metadata_url == f"{HOST}/.well-known/oauth-protected-resource"
        async with client_for(auth.wrap(server)) as client:
            response = await client.get("/.well-known/oauth-protected-resource")
        assert response.status_code == 200
        assert response.json()["resource"] == HOST
        assert server.calls == []

    run(main)


def test_a_read_token_lists_and_calls_read_tools_but_not_write_tools() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        server = StandInServer()
        app = make_auth(fake).wrap(server)
        reader = token(fake)
        async with client_for(app) as client:
            listed = await client.post(
                "/mcp", json=rpc("tools/list"), headers=headers("tools/list", None, reader)
            )
            assert listed.status_code == 200
            read = await client.post("/mcp", **call("list_invoices", reader))
            assert read.status_code == 200
            assert read.json()["result"] == {"sub": "user_1"}

            write = await client.post("/mcp", **call("create_invoice", reader, request_id=7))
            assert write.status_code == 403
            assert write.headers["www-authenticate"] == (
                'Bearer error="insufficient_scope", scope="invoices:read invoices:write", '
                f'resource_metadata="{METADATA}", '
                'error_description="The create_invoice tool needs the invoices:write scope, '
                "and this access token doesn't have it\""
            )
            assert write.headers["content-type"] == "application/json"
            assert write.json() == {
                "jsonrpc": "2.0",
                "id": 7,
                "error": {
                    "code": 403,
                    "message": "The create_invoice tool needs the invoices:write scope, and "
                    "this access token doesn't have it.",
                    "data": {
                        "error": "insufficient_scope",
                        "scope": "invoices:read invoices:write",
                    },
                },
            }
            assert len(server.calls) == 2

            writer = token(fake, "invoices:read invoices:write")
            assert (await client.post("/mcp", **call("create_invoice", writer))).status_code == 200

    run(main)


def test_the_server_gets_the_same_body_and_the_caller_identity() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        server = StandInServer()
        app = make_auth(fake).wrap(server)
        body = json.dumps(rpc("tools/call", {"name": "list_invoices", "arguments": {"q": "é"}}))
        async with client_for(app) as client:
            response = await client.post(
                "/mcp",
                content=body.encode(),
                headers={
                    **headers("tools/call", "list_invoices", token(fake)),
                    "Content-Type": "application/json",
                },
            )
        assert response.status_code == 200
        seen = server.calls[0]
        assert seen["body"] == body.encode()
        assert seen["sub"] == "user_1"
        assert seen["auth"].scopes == ["invoices:read"]
        if HAS_MCP:
            assert seen["user"].access_token.client_id == "app_web_1"
            assert seen["user"].access_token.resource == RESOURCE
        else:
            assert seen["user"] is None

    run(main)


def test_batches_are_refused() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        server = StandInServer()
        app = make_auth(fake).wrap(server)
        batch = [rpc("tools/list"), rpc("tools/call", {"name": "create_invoice"}, 2)]
        async with client_for(app) as client:
            response = await client.post(
                "/mcp", json=batch, headers=headers("tools/list", None, token(fake))
            )
        assert response.status_code == 400
        assert response.json()["error"] == {
            "code": -32600,
            "message": "Batched JSON-RPC requests aren't supported. Send one request per POST.",
        }
        assert server.calls == []

    run(main)


def test_headers_must_match_the_body() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        server = StandInServer()
        app = make_auth(fake).wrap(server)
        reader = token(fake)
        message = rpc("tools/call", {"name": "create_invoice"})
        async with client_for(app) as client:
            wrong_method = await client.post(
                "/mcp", json=message, headers=headers("tools/list", None, reader)
            )
            assert wrong_method.status_code == 400
            assert wrong_method.json()["error"]["code"] == -32020

            wrong_name = await client.post(
                "/mcp", json=message, headers=headers("tools/call", "list_invoices", reader)
            )
            assert wrong_name.status_code == 400
            assert wrong_name.json()["error"]["code"] == -32020

            encoded = "=?base64?" + base64.b64encode(b"list_invoices").decode() + "?="
            sentinel = await client.post(
                "/mcp",
                json=rpc("tools/call", {"name": "list_invoices"}),
                headers=headers("tools/call", encoded, reader),
            )
            assert sentinel.status_code == 200
        assert len(server.calls) == 1

    run(main)


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (
            (
                b'{"jsonrpc":"2.0","id":1,"method":"tools/list",'
                b'"method":"tools/call","params":{"name":"create_invoice"}}'
            ),
            -32700,
        ),
        (b"{not json", -32700),
        (b"\xff\xfe", -32700),
        (b'"just a string"', -32600),
        (b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}', -32602),
        (b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":[]}', -32602),
    ],
)
def test_malformed_messages_are_refused(body: bytes, code: int) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        server = StandInServer()
        app = make_auth(fake).wrap(server)
        async with client_for(app) as client:
            response = await client.post(
                "/mcp",
                content=body,
                headers={
                    "Authorization": f"Bearer {token(fake)}",
                    "Content-Type": "application/json",
                },
            )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == code
        assert server.calls == []

    run(main)


def test_an_undeclared_tool_needs_only_the_base_scopes(caplog: pytest.LogCaptureFixture) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        server = StandInServer()
        app = make_auth(fake).wrap(server)
        async with client_for(app) as client:
            for _ in range(2):
                response = await client.post("/mcp", **call("ping", token(fake)))
                assert response.status_code == 200
            missing_base = await client.post("/mcp", **call("ping", token(fake, scope="other")))
            assert missing_base.status_code == 403

    with caplog.at_level(logging.WARNING, logger="microauth"):
        run(main)
    warnings = [record for record in caplog.records if "'ping'" in record.getMessage()]
    assert len(warnings) == 1


def test_other_requests_need_a_valid_token_with_the_base_scopes() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        server = StandInServer()
        app = make_auth(fake).wrap(server)
        async with client_for(app) as client:
            assert (await client.get("/mcp")).status_code == 401
            assert (await client.delete("/mcp")).status_code == 401
            allowed = await client.get("/mcp", headers={"Authorization": f"Bearer {token(fake)}"})
            assert allowed.status_code == 200
            preflight = await client.options("/mcp")
            assert preflight.status_code == 200
            stream = await client.get(
                "/mcp", headers={"Authorization": f"Bearer {token(fake, scope='other')}"}
            )
            assert stream.status_code == 403
            assert stream.json() == {
                "error": "insufficient_scope",
                "error_description": "This MCP server needs the invoices:read scope, and this "
                "access token doesn't have it",
                "scope": "invoices:read",
            }
            assert 'scope="invoices:read"' in stream.headers["www-authenticate"]
        assert [call["method"] for call in server.calls] == ["GET", "OPTIONS"]
        assert server.calls[1]["sub"] is None

    run(main)


@pytest.mark.parametrize("method", ["initialize", "tools/list", "resources/read", "prompts/get"])
def test_every_message_needs_the_base_scopes(method: str) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        server = StandInServer()
        app = make_auth(fake).wrap(server)
        async with client_for(app) as client:
            refused = await client.post(
                "/mcp",
                json=rpc(method, {}, request_id=3),
                headers=headers(method, None, token(fake, scope="other")),
            )
            assert refused.status_code == 403
            assert refused.json()["id"] == 3
            assert refused.json()["error"]["message"] == (
                "This MCP server needs the invoices:read scope, and this access token doesn't "
                "have it."
            )
            challenge = refused.headers["www-authenticate"]
            assert 'error="insufficient_scope", scope="invoices:read"' in challenge
            allowed = await client.post(
                "/mcp", json=rpc(method, {}), headers=headers(method, None, token(fake))
            )
            assert allowed.status_code == 200
        assert len(server.calls) == 1

    run(main)


def test_a_tool_name_unsafe_for_a_header_is_left_out_of_it() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        server = StandInServer()
        auth = make_auth(fake, tool_scopes={'say "hi" é': "invoices:write"})
        name = 'say "hi" é'
        async with client_for(auth.wrap(server)) as client:
            response = await client.post(
                "/mcp",
                json=rpc("tools/call", {"name": name, "arguments": {}}),
                headers=headers("tools/call", None, token(fake)),
            )
        assert response.status_code == 403
        challenge = response.headers["www-authenticate"]
        assert 'error_description="This tool needs the invoices:write scope' in challenge
        assert response.json()["error"]["message"].startswith("This tool needs")

    run(main)


def test_an_oversized_body_is_refused() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        server = StandInServer()
        app = make_auth(fake, max_body_size=1024).wrap(server)
        message = rpc("tools/list", {"padding": "x" * 2000})
        async with client_for(app) as client:
            response = await client.post(
                "/mcp", json=message, headers=headers("tools/list", None, token(fake))
            )
        assert response.status_code == 413
        assert server.calls == []

    run(main)


def test_an_unreachable_issuer_answers_503() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        fake.discovery_overrides = {"jwks_uri": None}
        server = StandInServer()
        app = make_auth(fake).wrap(server)
        async with client_for(app) as client:
            response = await client.post(
                "/mcp", json=rpc("tools/list"), headers=headers("tools/list", None, token(fake))
            )
        assert response.status_code == 503
        assert response.headers["retry-after"] == "5"

    run(main)


def test_lifespan_reaches_the_server_and_websockets_are_closed() -> None:
    async def main() -> None:
        fake = FakeIssuer()
        server = StandInServer()
        app = make_auth(fake).wrap(server)
        sent: list[dict[str, Any]] = []

        async def receive() -> dict[str, Any]:
            return {"type": "lifespan.startup"}

        async def send(message: dict[str, Any]) -> None:
            sent.append(message)

        await app({"type": "lifespan", "asgi": {"version": "3.0"}}, receive, send)
        assert server.lifespans == 1
        await app({"type": "websocket", "path": "/mcp", "headers": []}, receive, send)
        assert sent[-1] == {"type": "websocket.close", "code": 1008}

    run(main)


def test_shutdown_closes_the_http_client_mcp_auth_created() -> None:
    async def lifespan_app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return

    async def main() -> None:
        auth = McpAuth(issuer="https://auth.example.com", resource=RESOURCE)
        client = auth.verifier._http()
        messages = iter([{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}])
        sent: list[str] = []

        async def receive() -> dict[str, Any]:
            return next(messages)

        async def send(message: dict[str, Any]) -> None:
            sent.append(message["type"])

        await auth.wrap(lifespan_app)({"type": "lifespan"}, receive, send)
        assert sent == ["lifespan.startup.complete", "lifespan.shutdown.complete"]
        assert client.is_closed

    run(main)


def test_tool_scopes_can_come_from_a_dict_or_the_decorator() -> None:
    fake = FakeIssuer()
    auth = make_auth(fake, tool_scopes={"send_invoice": ["invoices:send"]})
    assert dict(auth.tool_scopes) == {
        "list_invoices": frozenset({"invoices:read"}),
        "create_invoice": frozenset({"invoices:write"}),
        "send_invoice": frozenset({"invoices:send"}),
    }
    assert auth.scopes_for("send_invoice") == {"invoices:read", "invoices:send"}
    assert auth.scopes_for("unknown") == {"invoices:read"}
    with pytest.raises(TypeError):
        auth.tool(lambda: None)  # type: ignore[arg-type]


def test_current_identity_outside_a_request_raises() -> None:
    with pytest.raises(LookupError):
        current_identity()


def test_the_real_mcp_server_behind_mcp_auth() -> None:
    mcpserver = pytest.importorskip("mcp.server.mcpserver")
    mcp_types = pytest.importorskip("mcp_types")
    from mcp.server.auth.middleware.auth_context import get_access_token
    from mcp.server.transport_security import TransportSecuritySettings

    fake = FakeIssuer()
    auth = make_auth(fake)
    server = mcpserver.MCPServer("Invoices")

    @server.tool()
    def list_invoices() -> str:
        access = get_access_token()
        assert access is not None
        return f"{current_identity().sub} via {access.client_id}"

    @server.tool()
    def create_invoice() -> str:
        return "created"

    inner = server.streamable_http_app(
        json_response=True,
        stateless_http=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    app = auth.wrap(inner)
    meta = {
        mcp_types.PROTOCOL_VERSION_META_KEY: PROTOCOL,
        mcp_types.CLIENT_CAPABILITIES_META_KEY: {},
        mcp_types.CLIENT_INFO_META_KEY: {"name": "tests", "version": "1"},
    }

    def tool_call(name: str, access_token: str) -> dict[str, Any]:
        return {
            "json": rpc("tools/call", {"name": name, "arguments": {}, "_meta": meta}),
            "headers": headers("tools/call", name, access_token),
        }

    async def main() -> None:
        reader = token(fake)
        async with server.session_manager.run(), client_for(app) as client:
            listed = await client.post(
                "/mcp",
                json=rpc("tools/list", {"_meta": meta}),
                headers=headers("tools/list", None, reader),
            )
            assert listed.status_code == 200, listed.text
            names = {tool["name"] for tool in listed.json()["result"]["tools"]}
            assert names == {"list_invoices", "create_invoice"}

            read = await client.post("/mcp", **tool_call("list_invoices", reader))
            assert read.status_code == 200, read.text
            assert read.json()["result"]["content"][0]["text"] == "user_1 via app_web_1"

            write = await client.post("/mcp", **tool_call("create_invoice", reader))
            assert write.status_code == 403
            assert 'error="insufficient_scope"' in write.headers["www-authenticate"]

            unauthenticated = await client.post(
                "/mcp", json=rpc("tools/list", {"_meta": meta}), headers=headers("tools/list")
            )
            assert unauthenticated.status_code == 401

    run(main)


def test_token_verifier_for_the_mcp_sdk() -> None:
    pytest.importorskip("mcp")

    async def main() -> None:
        fake = FakeIssuer()
        verifier = MicroAuthTokenVerifier(
            issuer=fake.issuer, resource=RESOURCE, http_client=fake.client()
        )
        raw = token(fake, scope="invoices:read invoices:write")
        access = await verifier.verify_token(raw)
        assert access is not None
        assert access.token == raw
        assert access.client_id == "app_web_1"
        assert sorted(access.scopes) == ["invoices:read", "invoices:write"]
        assert access.resource == RESOURCE
        assert isinstance(access.expires_at, int)
        if hasattr(access, "subject"):
            assert access.subject == "user_1"
        assert await verifier.verify_token(fake.access_token(scope="invoices:read")) is None
        assert await verifier.verify_token("garbage") is None
        await verifier.aclose()

    run(main)
