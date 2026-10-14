from __future__ import annotations

import asyncio
import importlib.util
import re
import time
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import pytest
from oidc_fake import (
    API,
    APP_URL,
    CLIENT_ID,
    CLIENT_SECRET,
    COOKIE_SECRET,
    MCP_CLIENT_ID,
    MCP_SECRET,
    RESOURCE_CLIENT_ID,
    RESOURCE_SECRET,
    Clock,
    FakeIssuer,
    FakeUser,
    sign_in,
)

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
SAME_SITE = {"Origin": APP_URL}
SETTINGS_PAGE = {"Origin": APP_URL, "Referer": f"{APP_URL}/settings/api-keys"}
SECRET = re.compile(r"cms_[0-9A-Za-z]{46}")


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
    monkeypatch.setenv("MICROAUTH_RESOURCE", API)
    monkeypatch.setenv("MICROAUTH_RESOURCE_CLIENT_ID", RESOURCE_CLIENT_ID)
    monkeypatch.setenv("MICROAUTH_RESOURCE_SECRET", RESOURCE_SECRET)
    blog = load("blog_cms")
    blog.auth._http._client = fake.client()
    blog.api.verifier._http._client = fake.client()

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


def test_blog_cms_api_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeIssuer()
    for name, value in {
        "MICROAUTH_ISSUER": fake.issuer,
        "MICROAUTH_CLIENT_ID": CLIENT_ID,
        "MICROAUTH_CLIENT_SECRET": CLIENT_SECRET,
        "MICROAUTH_COOKIE_SECRET": COOKIE_SECRET,
        "MICROAUTH_APP_URL": APP_URL,
        "MICROAUTH_RESOURCE": API,
        "MICROAUTH_RESOURCE_CLIENT_ID": RESOURCE_CLIENT_ID,
        "MICROAUTH_RESOURCE_SECRET": RESOURCE_SECRET,
    }.items():
        monkeypatch.setenv(name, value)
    blog = load("blog_cms")
    blog.auth._http._client = fake.client()
    blog.api.verifier._http._client = fake.client()
    clock = Clock()
    blog.api.key_checks.clock = clock

    def client() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=blog.app), base_url=APP_URL)

    async def main() -> None:
        async with client() as editor:
            assert (await editor.get("/settings/api-keys")).status_code == 303
            await sign_in(editor, fake, next="/settings/api-keys")
            page = await editor.get("/settings/api-keys")
            assert page.status_code == 200
            assert page.headers["cache-control"] == "no-store"
            assert "No keys yet" in page.text
            assert 'value="posts:write"' in page.text
            assert 'value="never"' in page.text

            form = "name=Deploy+script&permission=posts%3Awrite&days=90"
            created = await editor.post(
                "/settings/api-keys",
                content=form,
                headers={**SETTINGS_PAGE, "Content-Type": "application/x-www-form-urlencoded"},
            )
            assert created.status_code == 200, created.text
            found = SECRET.search(created.text)
            assert found is not None
            secret = found.group(0)
            assert "Deploy script" in created.text
            assert secret not in (await editor.get("/settings/api-keys")).text

        post = {"title": "From a script", "body": "Published with an API key"}
        async with client() as script:
            published = await script.post(
                "/api/posts", json=post, headers={"Authorization": f"Bearer {secret}"}
            )
            assert published.status_code == 201, published.text
            assert published.json()["author_id"] == "user_1"
            assert published.json()["author_name"] is None
            mistyped = secret[:-1] + ("x" if secret[-1] != "x" else "y")
            wrong = await script.post(
                "/api/posts", json=post, headers={"Authorization": f"Bearer {mistyped}"}
            )
            assert wrong.status_code == 401

        async with client() as editor:
            await sign_in(editor, fake, next="/settings/api-keys")
            (key_id,) = list(fake.api_keys)
            revoked = await editor.post(
                f"/settings/api-keys/{key_id}/revoke", headers=SETTINGS_PAGE
            )
            assert revoked.status_code == 303
            assert "No keys yet" in (await editor.get("/settings/api-keys")).text

        clock.advance(31)
        async with client() as script:
            refused = await script.post(
                "/api/posts", json=post, headers={"Authorization": f"Bearer {secret}"}
            )
            assert refused.status_code == 401

        fake.last_sign_in = int(time.time()) - 3600
        async with client() as stale:
            await sign_in(stale, fake, next="/settings/api-keys")
            again = await stale.post(
                "/settings/api-keys",
                content="name=Late&permission=posts%3Awrite&days=30",
                headers={**SETTINGS_PAGE, "Content-Type": "application/x-www-form-urlencoded"},
            )
            assert again.status_code == 303
            assert again.headers["location"] == (
                "/auth/login?next=%2Fsettings%2Fapi-keys&max_age=600"
            )

    asyncio.run(main())


def test_api_and_mcp_example(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("mcp.server.mcpserver")
    api_resource = "http://localhost:8000"
    mcp_resource = "http://localhost:8000/mcp"
    fake = FakeIssuer()
    fake.resource_clients = {RESOURCE_CLIENT_ID: api_resource, MCP_CLIENT_ID: mcp_resource}
    fake.resource_names.update({api_resource: "Tasks API", mcp_resource: "Tasks MCP server"})
    for name, value in {
        "MICROAUTH_ISSUER": fake.issuer,
        "TASKS_API_CLIENT_ID": RESOURCE_CLIENT_ID,
        "TASKS_API_SECRET": RESOURCE_SECRET,
        "TASKS_MCP_CLIENT_ID": MCP_CLIENT_ID,
        "TASKS_MCP_SECRET": MCP_SECRET,
    }.items():
        monkeypatch.setenv(name, value)
    # Neither resource may fall back on these.
    monkeypatch.setenv("MICROAUTH_RESOURCE_CLIENT_ID", "rs_wrong")
    monkeypatch.setenv("MICROAUTH_RESOURCE_SECRET", "wrong")
    tasks = load("api_and_mcp")
    tasks.api.verifier._http._client = fake.client()
    tasks.mcp_auth.verifier._http._client = fake.client()
    api_key = fake.add_key(resources=[api_resource], permissions=["tasks:read", "tasks:write"])
    mcp_key = fake.add_key(resources=[mcp_resource], permissions=["tasks:read", "tasks:write"])

    def tool(name: str, arguments: dict[str, Any], credential: str) -> dict[str, Any]:
        return {
            "json": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            },
            "headers": {
                "Authorization": f"Bearer {credential}",
                "Mcp-Method": "tools/call",
                "Mcp-Name": name,
                "Accept": "application/json, text/event-stream",
            },
        }

    async def main() -> None:
        transport = httpx.ASGITransport(app=tasks.app)
        async with (
            tasks.app.router.lifespan_context(tasks.app),
            httpx.AsyncClient(transport=transport, base_url=api_resource) as client,
        ):
            root = await client.get("/.well-known/oauth-protected-resource")
            assert root.json()["resource"] == api_resource
            inserted = await client.get("/.well-known/oauth-protected-resource/mcp")
            assert inserted.json()["resource"] == mcp_resource

            by_key = {"Authorization": f"Bearer {api_key.secret}"}
            added = await client.post("/tasks", json={"title": "Write docs"}, headers=by_key)
            assert added.status_code == 201, added.text
            listed = await client.post("/mcp", **tool("list_tasks", {}, mcp_key.secret))
            assert listed.status_code == 200, listed.text
            assert listed.json()["result"]["structuredContent"] == {"result": ["Write docs"]}
            token = fake.access_token(aud=mcp_resource, scope="tasks:read tasks:write")
            more = await client.post("/mcp", **tool("add_task", {"title": "Ship"}, token))
            assert more.status_code == 200, more.text
            assert (await client.get("/tasks", headers=by_key)).json() == ["Write docs", "Ship"]

            wrong_place = await client.post("/mcp", **tool("list_tasks", {}, api_key.secret))
            assert wrong_place.status_code == 401
            mcp_token = {"Authorization": f"Bearer {token}"}
            assert (await client.get("/tasks", headers=mcp_token)).status_code == 401

    asyncio.run(main())


def test_invoices_mcp_example(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("mcp.server.mcpserver")
    mcp_types = pytest.importorskip("mcp_types")
    resource = "http://localhost:8000/mcp"
    fake = FakeIssuer()
    fake.resource_clients["rs_local_invoices"] = resource
    fake.resource_names[resource] = "Invoices"
    monkeypatch.setenv("MICROAUTH_ISSUER", fake.issuer)
    monkeypatch.setenv("MICROAUTH_RESOURCE", resource)
    monkeypatch.setenv("MICROAUTH_RESOURCE_CLIENT_ID", "rs_local_invoices")
    monkeypatch.setenv("MICROAUTH_RESOURCE_SECRET", RESOURCE_SECRET)
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
            invoices.app.router.lifespan_context(invoices.app),
            httpx.AsyncClient(transport=transport, base_url="http://localhost:8000") as client,
        ):
            assert (await client.get("/")).json() == {"mcp": "/mcp"}
            metadata = await client.get("/.well-known/oauth-protected-resource/mcp")
            assert metadata.json()["resource"] == resource
            assert (await client.get("/.well-known/oauth-protected-resource")).status_code == 404

            async def call(
                tool: str,
                arguments: dict[str, Any],
                scope: str,
                sub: str = "user_1",
                credential: str | None = None,
            ) -> httpx.Response:
                access = credential or fake.access_token(aud=resource, scope=scope, sub=sub)
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

            key = fake.add_key(
                resources=[resource], permissions=["invoices:read", "invoices:write"]
            ).secret
            by_key = result(
                await call(
                    "create_invoice",
                    {"customer": "Globex", "amount_cents": 900},
                    "",
                    credential=key,
                )
            )
            assert by_key["owner"] == "user_1"
            mine = result(await call("list_invoices", {}, "", credential=key))
            assert [invoice["customer"] for invoice in mine] == ["Acme", "Globex"]
            not_allowed = await call(
                "send_invoice", {"invoice_id": by_key["id"]}, "", credential=key
            )
            assert not_allowed.status_code == 403
            assert not_allowed.json()["error"]["message"] == (
                "The send_invoice tool needs the invoices:send permission, and this API key "
                "doesn't have it."
            )

    asyncio.run(main())
