from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from oidc_fake import FakeIssuer
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from microauth_fastapi import McpAuth, MicroAuthConfigurationError, current_identity

RESOURCE = "https://mcp.example.com/mcp"
HOST = "https://mcp.example.com"
METADATA = f"{HOST}/.well-known/oauth-protected-resource/mcp"
PROTOCOL = "2026-07-28"


def make_auth(fake: FakeIssuer, resource: str = RESOURCE) -> McpAuth:
    auth = McpAuth(issuer=fake.issuer, resource=resource, scopes=["invoices:read"])
    auth.verifier._http._client = fake.client()
    return auth


def stand_in(events: list[str], path: str = "/mcp") -> Starlette:
    """What streamable_http_app() returns, with a lifespan that records."""

    async def endpoint(request: Request) -> JSONResponse:
        return JSONResponse({"sub": current_identity().sub, "body": (await request.json())})

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        events.append("mcp up")
        yield
        events.append("mcp down")

    return Starlette(routes=[Route(path, endpoint, methods=["POST"])], lifespan=lifespan)


def host_app(events: list[str]) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[dict[str, str]]:
        events.append("app up")
        yield {"greeting": "hello"}
        events.append("app down")

    app = FastAPI(lifespan=lifespan)

    @app.get("/")
    def home() -> dict[str, str]:
        return {"page": "home"}

    return app


def rpc_call(tool: str, access_token: str | None = None) -> dict[str, Any]:
    headers = {
        "MCP-Protocol-Version": PROTOCOL,
        "Mcp-Method": "tools/call",
        "Mcp-Name": tool,
        "Accept": "application/json, text/event-stream",
    }
    if access_token is not None:
        headers["Authorization"] = f"Bearer {access_token}"
    return {
        "json": {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool, "arguments": {}},
        },
        "headers": headers,
    }


def test_mount_adds_the_mcp_server_and_its_metadata_to_an_app() -> None:
    fake = FakeIssuer()
    auth = make_auth(fake)
    owned = auth.verifier._http()
    events: list[str] = []
    app = host_app(events)
    auth.mount(app, stand_in(events))

    @app.get("/later")
    def later() -> dict[str, str]:
        return {"page": "later"}

    async def main() -> None:
        async with (
            app.router.lifespan_context(app) as state,
            httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=HOST) as client,
        ):
            assert state == {"greeting": "hello"}
            assert events == ["app up", "mcp up"]
            assert (await client.get("/")).json() == {"page": "home"}
            assert (await client.get("/later")).json() == {"page": "later"}

            refused = await client.post("/mcp", **rpc_call("list_invoices"))
            assert refused.status_code == 401
            assert f'resource_metadata="{METADATA}"' in refused.headers["www-authenticate"]
            metadata = await client.get("/.well-known/oauth-protected-resource/mcp")
            assert metadata.status_code == 200
            assert metadata.json()["resource"] == RESOURCE
            assert (await client.get("/.well-known/oauth-protected-resource")).status_code == 404

            access = fake.access_token(aud=RESOURCE, scope="invoices:read")
            served = await client.post("/mcp", **rpc_call("list_invoices", access))
            assert served.status_code == 200, served.text
            assert served.json()["sub"] == "user_1"
            assert "/mcp" not in (await client.get("/openapi.json")).json()["paths"]
        assert events == ["app up", "mcp up", "mcp down", "app down"]
        assert owned.is_closed

    asyncio.run(main())


def test_a_resource_without_a_path_mounts_at_mcp_with_metadata_at_the_root() -> None:
    fake = FakeIssuer()
    fake.resource_clients["rs_root"] = HOST
    auth = make_auth(fake, resource=HOST)
    app = FastAPI()
    auth.mount(app, stand_in([]))

    async def main() -> None:
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=HOST) as client,
        ):
            metadata = await client.get("/.well-known/oauth-protected-resource")
            assert metadata.json()["resource"] == HOST
            access = fake.access_token(aud=HOST, scope="invoices:read")
            assert (await client.post("/mcp", **rpc_call("x", access))).status_code == 200

    asyncio.run(main())


@pytest.mark.parametrize(
    ("app", "server", "path", "message"),
    [
        (FastAPI(), stand_in([]), "/", "needs a path below the root"),
        (FastAPI(), stand_in([]), "mcp", "needs a path below the root"),
        (object(), stand_in([]), None, "needs a FastAPI or Starlette app"),
        (FastAPI(), lambda scope, receive, send: None, None, "takes an MCPServer"),
        (FastAPI(), stand_in([], path="/other"), None, "doesn't answer at /mcp"),
    ],
)
def test_mount_explains_what_it_needs(app: Any, server: Any, path: Any, message: str) -> None:
    auth = McpAuth(issuer="https://auth.example.com", resource=RESOURCE)
    with pytest.raises(MicroAuthConfigurationError, match=message):
        auth.mount(app, server, path=path)


def test_mount_serves_an_mcp_server_to_the_mcp_sdk_client() -> None:
    mcpserver = pytest.importorskip("mcp.server.mcpserver")
    httpx2 = pytest.importorskip("httpx2")
    from mcp import Client
    from mcp.client.auth.utils import (
        build_protected_resource_metadata_discovery_urls,
        extract_resource_metadata_from_www_auth,
    )
    from mcp.client.streamable_http import streamable_http_client
    from mcp.shared.exceptions import MCPError

    fake = FakeIssuer()
    auth = make_auth(fake)
    server = mcpserver.MCPServer("Invoices", log_level="WARNING")

    @server.tool()
    @auth.tool("invoices:read")
    def whoami() -> str:
        return current_identity().sub

    @server.tool()
    @auth.tool("invoices:write")
    def create_invoice() -> str:
        return "created"

    app = FastAPI()
    auth.mount(app, server)

    def mcp_client(access_token: str, host: str = HOST) -> Client:
        http = httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            base_url=host,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        return Client(streamable_http_client(f"{host}/mcp", http_client=http))

    async def main() -> None:
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=HOST) as plain,
        ):
            refused = await plain.post("/mcp", **rpc_call("whoami"))
            assert refused.status_code == 401
            from_header = extract_resource_metadata_from_www_auth(refused)
            without_header = build_protected_resource_metadata_discovery_urls(None, RESOURCE)
            for url in (from_header, without_header[0]):
                assert url == METADATA
                assert (await plain.get(url)).json()["resource"] == RESOURCE

            reader = fake.access_token(aud=RESOURCE, scope="invoices:read")
            async with mcp_client(reader) as client:
                result = await client.call_tool("whoami", {})
                assert result.content[0].text == "user_1"
                with pytest.raises(MCPError) as refusal:
                    await client.call_tool("create_invoice", {})
            assert str(refusal.value) == (
                "The create_invoice tool needs the invoices:write scope, and this access "
                "token doesn't have it."
            )

            other_host = await plain.post("https://evil.example/mcp", **rpc_call("whoami", reader))
            assert other_host.status_code == 421

    asyncio.run(main())
