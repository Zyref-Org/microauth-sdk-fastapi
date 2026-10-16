"""API key answers and limits kept in Redis.

Most tests need a real Redis: set ``MICROAUTH_TEST_REDIS_URL``. Each test
uses its own issuer, so its keys live under their own namespace, and deletes
them afterwards. ``SCRIPT FLUSH`` touches the whole server, so that test also
needs ``MICROAUTH_TEST_REDIS_FLUSHABLE=1``, meant for a throwaway Redis.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
from fastapi import Depends, FastAPI
from oidc_fake import API, RESOURCE_CLIENT_ID, RESOURCE_SECRET, Clock, FakeIssuer, make_key

from microauth_fastapi import TokenAuth, TokenClaims
from microauth_fastapi._keys import _namespace
from microauth_fastapi._limits import SCRIPT_SHA

REDIS_URL = os.environ.get("MICROAUTH_TEST_REDIS_URL")
FLUSHABLE = os.environ.get("MICROAUTH_TEST_REDIS_FLUSHABLE") == "1"
needs_redis = pytest.mark.skipif(
    REDIS_URL is None, reason="set MICROAUTH_TEST_REDIS_URL to run against Redis"
)


def build(fake: FakeIssuer, clock: Clock, **options: Any) -> tuple[FastAPI, TokenAuth]:
    app = FastAPI()
    settings: dict[str, Any] = {
        "issuer": fake.issuer,
        "resource": API,
        "http_client": fake.client(),
        "api_keys": True,
        "resource_client_id": RESOURCE_CLIENT_ID,
        "resource_secret": RESOURCE_SECRET,
        "redis_url": REDIS_URL,
    }
    settings.update(options)
    api = TokenAuth(app, **settings)
    assert api.key_checks is not None
    api.key_checks.clock = clock
    fake.now = clock

    @app.get("/posts")
    async def posts(token: TokenClaims = Depends(api.require("posts:read"))) -> dict[str, Any]:
        return {"sub": token.sub, "key_id": token.key_id}

    return app, api


def client_for(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=API)


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def run(test: Callable[[], Any]) -> None:
    asyncio.run(test())


@asynccontextmanager
async def isolated() -> AsyncIterator[tuple[FakeIssuer, Any, str]]:
    """A fake issuer of its own, a Redis client and the namespace its keys use."""
    import redis.asyncio as aioredis

    assert REDIS_URL is not None
    fake = FakeIssuer(f"https://auth-{uuid.uuid4().hex[:12]}.example.com")
    namespace = _namespace(fake.issuer, API)
    client = aioredis.from_url(REDIS_URL)
    try:
        yield fake, client, namespace
    finally:
        names = [name async for name in client.scan_iter(match=f"{namespace}:*")]
        if names:
            await client.delete(*names)
        await client.aclose()


@needs_redis
def test_answers_are_shared_between_workers() -> None:
    async def main() -> None:
        async with isolated() as (fake, _, _):
            clock = Clock()
            first, one = build(fake, clock)
            second, two = build(fake, clock)
            key = fake.add_key()
            unknown = make_key()
            async with client_for(first) as a, client_for(second) as b:
                assert (await a.get("/posts", headers=bearer(key.secret))).status_code == 200
                assert (await b.get("/posts", headers=bearer(key.secret))).status_code == 200
                assert (await a.get("/posts", headers=bearer(unknown))).status_code == 401
                assert (await b.get("/posts", headers=bearer(unknown))).status_code == 401
                assert len(fake.introspections) == 2
                clock.advance(31)
                assert (await b.get("/posts", headers=bearer(key.secret))).status_code == 200
                assert len(fake.introspections) == 3
            await one.aclose()
            await two.aclose()

    run(main)


@needs_redis
def test_microauths_reason_for_a_paused_key_is_shared_between_workers() -> None:
    reason = "Acme API is paused, so its API keys don't work right now."

    async def main() -> None:
        async with isolated() as (fake, client, namespace):
            clock = Clock()
            first, one = build(fake, clock)
            second, two = build(fake, clock)
            key = fake.add_key()
            fake.introspect_edit = lambda document: {
                "active": False,
                "reason": "service_paused",
                "reason_description": reason,
            }
            async with client_for(first) as a, client_for(second) as b:
                for worker in (a, b):
                    refused = await worker.get("/posts", headers=bearer(key.secret))
                    assert refused.json()["detail"] == reason
                assert len(fake.introspections) == 1
                name = f"{namespace}:answer:{hashlib.sha256(key.secret.encode()).hexdigest()}"
                stored = json.loads(await client.get(name))
                assert stored["a"] is None
                assert stored["r"] == reason
                # A reason changed in Redis is checked like MicroAuth's own.
                stored["r"] = "Bad\\reason"
                await client.set(name, json.dumps(stored), px=60_000)
                again = await b.get("/posts", headers=bearer(key.secret))
                assert again.json()["detail"] == "The API key is unknown, revoked or expired"
            await one.aclose()
            await two.aclose()

    run(main)


@needs_redis
def test_limits_are_shared_between_workers() -> None:
    async def main() -> None:
        async with isolated() as (fake, _, _):
            clock = Clock()
            first, _ = build(fake, clock, unknown_key_limit=2)
            second, _ = build(fake, clock, unknown_key_limit=2)
            key = fake.add_key(requests_per_minute=3)
            other = fake.add_key(requests_per_minute=3)
            async with client_for(first) as a, client_for(second) as b:
                assert (await a.get("/posts", headers=bearer(key.secret))).status_code == 200
                assert (await b.get("/posts", headers=bearer(other.secret))).status_code == 200
                assert (await a.get("/posts", headers=bearer(other.secret))).status_code == 200
                over = await b.get("/posts", headers=bearer(key.secret))
                assert over.status_code == 429
                assert over.headers["retry-after"] == "20"
                clock.advance(20)
                assert (await b.get("/posts", headers=bearer(key.secret))).status_code == 200
                assert (await a.get("/posts", headers=bearer(key.secret))).status_code == 429

                assert (await a.get("/posts", headers=bearer(make_key()))).status_code == 401
                assert (await b.get("/posts", headers=bearer("cms_short"))).status_code == 401
                throttled = await a.get("/posts", headers=bearer(make_key()))
                assert throttled.status_code == 429
                assert throttled.headers["retry-after"] == "30"

    run(main)


@needs_redis
def test_redis_keys_are_namespaced_hashed_and_expire() -> None:
    async def main() -> None:
        async with isolated() as (fake, client, namespace):
            clock = Clock()
            app, _ = build(fake, clock)
            key = fake.add_key(requests_per_minute=10)
            async with client_for(app) as http:
                assert (await http.get("/posts", headers=bearer(key.secret))).status_code == 200
                assert (await http.get("/posts", headers=bearer(make_key()))).status_code == 401
            names = sorted(
                [name.decode() async for name in client.scan_iter(match=f"{namespace}:*")]
            )
            digest = hashlib.sha256(key.secret.encode()).hexdigest()
            kinds = sorted(name[len(namespace) + 1 :].split(":")[0] for name in names)
            assert kinds == ["answer", "answer", "rpm", "unknown"]
            assert f"{namespace}:answer:{digest}" in names
            for name in names:
                ttl = await client.pttl(name)
                assert ttl > 0, name
                if ":answer:" in name:
                    assert ttl <= 630_000
                else:
                    assert ttl <= 60_000
                value = await client.get(name)
                assert key.secret.encode() not in value
                assert key.secret not in name
            stored = json.loads(await client.get(f"{namespace}:answer:{digest}"))
            assert stored["v"] == 1
            assert stored["a"]["key_id"] == key.id
            assert stored["s"] - stored["f"] == 600

    run(main)


@needs_redis
def test_a_stale_redis_answer_rides_out_an_outage() -> None:
    async def main() -> None:
        async with isolated() as (fake, _, _):
            clock = Clock()
            first, _ = build(fake, clock)
            second, _ = build(fake, clock)
            key = fake.add_key()
            async with client_for(first) as a, client_for(second) as b:
                assert (await a.get("/posts", headers=bearer(key.secret))).status_code == 200
                fake.introspect_failure = 503
                clock.advance(100)
                assert (await b.get("/posts", headers=bearer(key.secret))).status_code == 200
                clock.advance(600)
                assert (await b.get("/posts", headers=bearer(key.secret))).status_code == 503

    run(main)


@needs_redis
def test_a_tampered_redis_answer_is_checked_again() -> None:
    async def main() -> None:
        async with isolated() as (fake, client, namespace):
            clock = Clock()
            app, _ = build(fake, clock)
            key = fake.add_key()
            async with client_for(app) as http:
                assert (await http.get("/posts", headers=bearer(key.secret))).status_code == 200
                name = f"{namespace}:answer:{hashlib.sha256(key.secret.encode()).hexdigest()}"
                stored = json.loads(await client.get(name))
                stored["a"]["iss"] = "https://evil.example"
                await client.set(name, json.dumps(stored), px=60_000)
                assert (await http.get("/posts", headers=bearer(key.secret))).status_code == 200
                assert len(fake.introspections) == 2
                await client.set(name, b"not json", px=60_000)
                assert (await http.get("/posts", headers=bearer(key.secret))).status_code == 200
                assert len(fake.introspections) == 3

    run(main)


class NoScriptOnce:
    """A Redis client whose first EVALSHA answers NOSCRIPT, like a fresh server."""

    def __init__(self, client: Any) -> None:
        self.client = client
        self.evalsha_calls = 0
        self.eval_calls = 0

    async def evalsha(self, *args: Any) -> Any:
        from redis.exceptions import NoScriptError

        self.evalsha_calls += 1
        if self.evalsha_calls == 1:
            raise NoScriptError("No matching script. Please use EVAL.")
        return await self.client.evalsha(*args)

    async def eval(self, *args: Any) -> Any:
        self.eval_calls += 1
        return await self.client.eval(*args)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.client, name)


@needs_redis
def test_evalsha_falls_back_to_eval_when_the_script_is_missing() -> None:
    async def main() -> None:
        async with isolated() as (fake, client, _):
            clock = Clock()
            wrapped = NoScriptOnce(client)
            app, api = build(fake, clock, redis_url=None, redis_client=wrapped)
            key = fake.add_key(requests_per_minute=5)
            async with client_for(app) as http:
                for _ in range(3):
                    assert (await http.get("/posts", headers=bearer(key.secret))).status_code == 200
            assert wrapped.eval_calls == 1
            assert wrapped.evalsha_calls >= 3
            await api.aclose()
            assert await client.ping()

    run(main)


@needs_redis
@pytest.mark.skipif(not FLUSHABLE, reason="SCRIPT FLUSH needs a throwaway Redis")
def test_limits_survive_a_script_flush() -> None:
    async def main() -> None:
        async with isolated() as (fake, client, _):
            clock = Clock()
            app, _ = build(fake, clock)
            key = fake.add_key(requests_per_minute=5)
            async with client_for(app) as http:
                assert (await http.get("/posts", headers=bearer(key.secret))).status_code == 200
                assert (await client.script_exists(SCRIPT_SHA)) == [True]
                await client.script_flush()
                assert (await client.script_exists(SCRIPT_SHA)) == [False]
                assert (await http.get("/posts", headers=bearer(key.secret))).status_code == 200
                assert (await client.script_exists(SCRIPT_SHA)) == [True]

    run(main)


@needs_redis
def test_an_owned_redis_client_is_closed_at_shutdown() -> None:
    async def main() -> None:
        async with isolated() as (fake, _, _):
            clock = Clock()
            app, api = build(fake, clock)
            key = fake.add_key()
            async with client_for(app) as http:
                assert (await http.get("/posts", headers=bearer(key.secret))).status_code == 200
            assert api.key_checks is not None and api.key_checks.redis is not None
            assert api.key_checks.redis._client is not None
            await lifespan(app)
            assert api.key_checks.redis._client is None
            async with client_for(app) as http:
                assert (await http.get("/posts", headers=bearer(key.secret))).status_code == 200
            await api.aclose()

    run(main)


async def lifespan(app: Any) -> None:
    messages = iter([{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}])
    sent: list[str] = []

    async def receive() -> dict[str, Any]:
        return next(messages)

    async def send(message: dict[str, Any]) -> None:
        sent.append(message["type"])

    await app({"type": "lifespan", "asgi": {"version": "3.0"}, "state": {}}, receive, send)
    assert sent == ["lifespan.startup.complete", "lifespan.shutdown.complete"]


# Without a Redis server

UNREACHABLE = "redis://127.0.0.1:1/0"


def test_unreachable_redis_limits_answer_503(caplog: pytest.LogCaptureFixture) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake, Clock(), redis_url=UNREACHABLE)
        key = fake.add_key()
        async with client_for(app) as http:
            response = await http.get("/posts", headers=bearer(key.secret))
        assert response.status_code == 503
        assert "Redis is unavailable" in caplog.text
        assert key.secret not in caplog.text

    caplog.set_level(logging.WARNING, logger="microauth")
    run(main)


def test_unreachable_redis_only_costs_the_cache_when_no_limit_applies(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def main() -> None:
        fake = FakeIssuer()
        app, _ = build(fake, Clock(), redis_url=UNREACHABLE, unknown_key_limit=0)
        key = fake.add_key()
        limited = fake.add_key(requests_per_minute=10)
        async with client_for(app) as http:
            for _ in range(2):
                assert (await http.get("/posts", headers=bearer(key.secret))).status_code == 200
            assert (await http.get("/posts", headers=bearer(limited.secret))).status_code == 503
        assert len(fake.introspections) == 3
        assert "the API key cache can't be read" in caplog.text

    caplog.set_level(logging.WARNING, logger="microauth")
    run(main)


def test_the_redis_url_comes_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeIssuer()
    monkeypatch.setenv("MICROAUTH_REDIS_URL", UNREACHABLE)
    _, api = build(fake, Clock(), redis_url=None)
    assert api.key_checks is not None and api.key_checks.redis is not None
    monkeypatch.delenv("MICROAUTH_REDIS_URL")
    _, memory = build(fake, Clock(), redis_url=None)
    assert memory.key_checks is not None and memory.key_checks.redis is None


def test_a_redis_client_passed_in_is_never_closed() -> None:
    class Client:
        closed = False

        async def aclose(self) -> None:
            self.closed = True

    async def main() -> None:
        fake = FakeIssuer()
        client = Client()
        _, api = build(fake, Clock(), redis_url=None, redis_client=client)
        await api.aclose()
        assert client.closed is False

    run(main)
