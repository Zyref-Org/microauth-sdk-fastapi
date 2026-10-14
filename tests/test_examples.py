from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import pytest
from oidc_fake import (
    APP_URL,
    CLIENT_ID,
    CLIENT_SECRET,
    COOKIE_SECRET,
    FakeIssuer,
    FakeUser,
    sign_in,
)

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
SAME_SITE = {"Origin": APP_URL}


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"example_{name}", EXAMPLES / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_blog_cms_example(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeIssuer()
    monkeypatch.setenv("MICROAUTH_ISSUER", fake.issuer)
    monkeypatch.setenv("MICROAUTH_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("MICROAUTH_CLIENT_SECRET", CLIENT_SECRET)
    monkeypatch.setenv("MICROAUTH_COOKIE_SECRET", COOKIE_SECRET)
    monkeypatch.setenv("MICROAUTH_APP_URL", APP_URL)
    blog = load("blog_cms")
    blog.auth._http._client = fake.client()

    def client() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=blog.app), base_url=APP_URL)

    async def main() -> None:
        post = {"title": "Hello", "body": "The first post"}
        async with client() as editor:
            assert "Sign in" in (await editor.get("/")).text
            page = await editor.get("/editor")
            assert page.status_code == 303
            assert page.headers["location"] == "/auth/login?next=%2Feditor"
            assert (
                await editor.post("/api/posts", json=post, headers=SAME_SITE)
            ).status_code == 401

            await sign_in(editor, fake, next="/editor")
            assert (await editor.get("/editor")).status_code == 200
            created = await editor.post("/api/posts", json=post, headers=SAME_SITE)
            assert created.status_code == 201
            assert created.json()["author_id"] == "user_1"
            cross_site = await editor.post(
                "/api/posts", json=post, headers={"Origin": "https://evil.example"}
            )
            assert cross_site.status_code == 403
            post_id = created.json()["id"]
            denied = await editor.delete(f"/api/posts/{post_id}", headers=SAME_SITE)
            assert denied.status_code == 403
            home = (await editor.get("/")).text
            assert "Hello" in home and "Write a post" in home

        fake.user = FakeUser(sub="user_admin", roles=["admin"], permissions=[])
        async with client() as admin:
            await sign_in(admin, fake)
            assert (await admin.post("/api/posts", json=post, headers=SAME_SITE)).status_code == 403
            deleted = await admin.delete(f"/api/posts/{post_id}", headers=SAME_SITE)
            assert deleted.status_code == 204
            assert (await admin.get("/api/posts")).json() == []

    asyncio.run(main())


def test_invoices_mcp_example(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("mcp.server.mcpserver")
    mcp_types = pytest.importorskip("mcp_types")
    resource = "http://localhost:8000/mcp"
    fake = FakeIssuer()
    monkeypatch.setenv("MICROAUTH_ISSUER", fake.issuer)
    monkeypatch.setenv("MICROAUTH_RESOURCE", resource)
    invoices = load("invoices_mcp")
    invoices.auth.verifier._http._client = fake.client()
    meta = {
        mcp_types.PROTOCOL_VERSION_META_KEY: "2026-07-28",
        mcp_types.CLIENT_CAPABILITIES_META_KEY: {},
        mcp_types.CLIENT_INFO_META_KEY: {"name": "tests", "version": "1"},
    }

    async def main() -> None:
        transport = httpx.ASGITransport(app=invoices.app)
        async with (
            invoices.mcp.session_manager.run(),
            httpx.AsyncClient(transport=transport, base_url="http://localhost:8000") as client,
        ):

            async def call(
                tool: str, arguments: dict[str, Any], scope: str, sub: str = "user_1"
            ) -> httpx.Response:
                access = fake.access_token(aud=resource, scope=scope, sub=sub)
                return await client.post(
                    "/mcp",
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": tool, "arguments": arguments, "_meta": meta},
                    },
                    headers={
                        "Authorization": f"Bearer {access}",
                        "MCP-Protocol-Version": "2026-07-28",
                        "Mcp-Method": "tools/call",
                        "Mcp-Name": tool,
                        "Accept": "application/json, text/event-stream",
                    },
                )

            def result(response: httpx.Response) -> Any:
                assert response.status_code == 200, response.text
                body = response.json()["result"]
                assert body["isError"] is False, body
                structured = body["structuredContent"]
                # Lists come back wrapped as {"result": [...]}.
                return structured["result"] if set(structured) == {"result"} else structured

            read_only = await call(
                "create_invoice", {"customer": "Acme", "amount_cents": 5000}, "invoices:read"
            )
            assert read_only.status_code == 403
            assert 'scope="invoices:read invoices:write"' in read_only.headers["www-authenticate"]

            created = result(
                await call(
                    "create_invoice",
                    {"customer": "Acme", "amount_cents": 5000},
                    "invoices:read invoices:write",
                )
            )
            assert created["owner"] == "user_1"
            assert result(await call("list_invoices", {}, "invoices:read")) == [created]
            assert result(await call("list_invoices", {}, "invoices:read", sub="user_2")) == []

            stolen = await call(
                "send_invoice",
                {"invoice_id": created["id"]},
                "invoices:read invoices:send",
                "user_2",
            )
            assert stolen.json()["result"]["isError"] is True
            assert "There is no invoice" in stolen.json()["result"]["content"][0]["text"]

            sent = result(
                await call(
                    "send_invoice", {"invoice_id": created["id"]}, "invoices:read invoices:send"
                )
            )
            assert sent["status"] == "sent"

    asyncio.run(main())
