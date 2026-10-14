from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from oidc_fake import MCP, MCP_CLIENT_ID, MCP_SECRET, FakeIssuer, make_key
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


def found(exc: BaseException, kind: type[BaseException]) -> BaseException | None:
    """``exc`` or the first ``kind`` inside it, through exception groups and causes."""
    if isinstance(exc, kind):
        return exc
    for inner in [*getattr(exc, "exceptions", ()), exc.__cause__, exc.__context__]:
        if inner is not None and inner is not exc:
            hit = found(inner, kind)
            if hit is not None:
                return hit
    return None


def test_the_mcp_sdk_client_shows_why_a_key_was_refused() -> None:
    mcpserver = pytest.importorskip("mcp.server.mcpserver")
    httpx2 = pytest.importorskip("httpx2")
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client
    from mcp.shared.exceptions import MCPError

    fake = FakeIssuer()
    auth = McpAuth(
        issuer=fake.issuer,
        resource=MCP,
        scopes=["invoices:read"],
        api_keys=True,
        resource_client_id=MCP_CLIENT_ID,
        resource_secret=MCP_SECRET,
        http_client=fake.client(),
    )
    server = mcpserver.MCPServer("Invoices", log_level="WARNING")

    @server.tool()
    @auth.tool("invoices:read")
    def whoami() -> str:
        return current_identity().sub

    app = FastAPI()
    auth.mount(app, server)
    good = fake.add_key(resources=[MCP], permissions=["invoices:read"]).secret

    def key_client(key: str) -> Client:
        http = httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            base_url=HOST,
            headers={"Authorization": f"Bearer {key}"},
        )
        return Client(streamable_http_client(f"{HOST}/mcp", http_client=http))

    async def main() -> None:
        async with app.router.lifespan_context(app):
            async with key_client(good) as client:
                assert (await client.call_tool("whoami", {})).content[0].text == "user_1"
            with pytest.raises(BaseException) as raised:
                async with key_client(make_key()) as client:
                    await client.call_tool("whoami", {})
            refusal = found(raised.value, MCPError)
            assert refusal is not None, raised.value
            assert str(refusal) == "The API key is unknown, revoked or expired."

    asyncio.run(main())


def test_the_mcp_sdk_oauth_client_still_discovers_and_starts_sign_in() -> None:
    mcpserver = pytest.importorskip("mcp.server.mcpserver")
    httpx2 = pytest.importorskip("httpx2")
    from urllib.parse import parse_qs, urlsplit

    from mcp import Client
    from mcp.client.auth import OAuthClientProvider
    from mcp.client.streamable_http import streamable_http_client
    from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata

    fake = FakeIssuer()
    auth = make_auth(fake)
    server = mcpserver.MCPServer("Invoices", log_level="WARNING")

    @server.tool()
    @auth.tool("invoices:read")
    def whoami() -> str:
        return current_identity().sub

    app = FastAPI()
    auth.mount(app, server)
    to_app = httpx2.ASGITransport(app=app)
    issuer_host = urlsplit(fake.issuer).netloc

    def issuer_documents(request: Any) -> Any:
        assert request.url.path.startswith("/.well-known/"), request.url
        return httpx2.Response(200, json=fake.discovery())

    to_issuer = httpx2.MockTransport(issuer_documents)
    seen: list[tuple[str, int]] = []

    class Router(httpx2.AsyncBaseTransport):
        async def handle_async_request(self, request: Any) -> Any:
            target = to_issuer if request.url.netloc.decode() == issuer_host else to_app
            response = await target.handle_async_request(request)
            seen.append((str(request.url).split("?")[0], response.status_code))
            return response

    class Stop(Exception):
        pass

    redirects: list[str] = []

    async def redirect_handler(url: str) -> None:
        redirects.append(url)
        raise Stop

    async def callback_handler() -> Any:
        raise AssertionError("the test never signs in")

    class Storage:
        async def get_tokens(self) -> None:
            return None

        async def set_tokens(self, tokens: Any) -> None: ...

        async def get_client_info(self) -> Any:
            return OAuthClientInformationFull(
                client_id="probe", redirect_uris=["http://127.0.0.1:9/callback"]
            )

        async def set_client_info(self, client_info: Any) -> None:
            raise AssertionError("the client must not register")

    provider = OAuthClientProvider(
        server_url=RESOURCE,
        client_metadata=OAuthClientMetadata(redirect_uris=["http://127.0.0.1:9/callback"]),
        storage=Storage(),
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
    )

    async def main() -> None:
        async with app.router.lifespan_context(app):
            http = httpx2.AsyncClient(transport=Router(), auth=provider)
            with pytest.raises(BaseException) as raised:
                async with Client(streamable_http_client(RESOURCE, http_client=http)) as client:
                    await client.list_tools()
            assert found(raised.value, Stop) is not None, raised.value
        assert seen[0] == (RESOURCE, 401)
        assert (METADATA, 200) in seen
        assert any(url.startswith(fake.issuer + "/.well-known/") for url, _ in seen)
        (url,) = redirects
        query = parse_qs(urlsplit(url).query)
        assert url.startswith(fake.discovery()["authorization_endpoint"])
        assert query["resource"] == [RESOURCE]
        assert "invoices:read" in query["scope"][0].split()

    asyncio.run(main())
