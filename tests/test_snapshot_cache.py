from __future__ import annotations

import asyncio
from typing import Any

import httpx
from test_sdk import ControlPlane, snapshot_payload

from microauth_fastapi import MicroAuth
from microauth_fastapi.snapshot_cache import RedisSnapshotCache


class FakeSnapshotRedis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.closed = False

    async def get(self, key: str) -> str | None:
        return self.values.get(key)

    async def set(
        self,
        key: str,
        value: str,
        *,
        ex: int | None = None,
        px: int | None = None,
        nx: bool = False,
    ) -> bool:
        del ex, px
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    async def eval(
        self,
        script: str,
        number_of_keys: int,
        *args: Any,
    ) -> int:
        del script
        if number_of_keys == 2:
            cache_key, lock_key, token, encoded, _ttl = args
            if self.values.get(lock_key) != token:
                return 0
            self.values[cache_key] = encoded
            return 1
        key, token, *rest = args
        if self.values.get(key) != token:
            return 0
        if rest:
            return 1
        del self.values[key]
        return 1

    async def aclose(self) -> None:
        self.closed = True


def test_concurrent_instances_share_one_control_plane_snapshot() -> None:
    plane = ControlPlane(snapshot_payload())
    redis = FakeSnapshotRedis()

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/sdk/v1/snapshot":
            await asyncio.sleep(0.05)
        return plane(request)

    async def exercise() -> None:
        control = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        first = MicroAuth(
            secret_key="mas_test",
            http_client=control,
            redis_client=redis,
            persist_usage=False,
        )
        second = MicroAuth(
            secret_key="mas_test",
            http_client=control,
            redis_client=redis,
            persist_usage=False,
        )
        await asyncio.gather(first.startup(), second.startup())
        assert first._snapshot.ready
        assert second._snapshot.ready
        await first.aclose()
        await second.aclose()
        await control.aclose()

    asyncio.run(exercise())
    assert plane.snapshot_calls == 1
    assert redis.closed is False


def test_fresh_shared_snapshot_avoids_a_second_cold_start_fetch() -> None:
    plane = ControlPlane(snapshot_payload())
    redis = FakeSnapshotRedis()

    async def exercise() -> None:
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        first = MicroAuth(
            secret_key="mas_test",
            http_client=control,
            redis_client=redis,
            persist_usage=False,
        )
        await first.startup()
        await first.aclose()

        second = MicroAuth(
            secret_key="mas_test",
            http_client=control,
            redis_client=redis,
            persist_usage=False,
        )
        await second.startup()
        assert second._snapshot.ready
        await second.aclose()
        await control.aclose()

    asyncio.run(exercise())
    assert plane.snapshot_calls == 1


def test_concurrent_cold_starts_replace_a_malformed_cached_snapshot() -> None:
    plane = ControlPlane(snapshot_payload())
    redis = FakeSnapshotRedis()

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/sdk/v1/snapshot":
            await asyncio.sleep(0.05)
        return plane(request)

    async def exercise() -> None:
        control = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        first = MicroAuth(
            secret_key="mas_test",
            http_client=control,
            redis_client=redis,
            persist_usage=False,
        )
        second = MicroAuth(
            secret_key="mas_test",
            http_client=control,
            redis_client=redis,
            persist_usage=False,
        )
        assert first._snapshot_cache is not None
        redis.values[first._snapshot_cache._cache_key] = "{not-json"
        await asyncio.gather(first.startup(), second.startup())
        assert first._snapshot.ready
        assert second._snapshot.ready
        await first.aclose()
        await second.aclose()
        await control.aclose()

    asyncio.run(exercise())
    assert plane.snapshot_calls == 1


def test_expired_refresh_owner_cannot_overwrite_a_newer_snapshot() -> None:
    redis = FakeSnapshotRedis()
    cache = RedisSnapshotCache(redis, "tenant", ttl=60)
    older = snapshot_payload()
    newer = snapshot_payload()

    async def exercise() -> None:
        old_token = await cache.acquire_refresh_lock()
        assert old_token is not None
        redis.values[cache._lock_key] = "new-owner"
        assert await cache.store_if_owner(older, old_token) is None
        stored = await cache.store_if_owner(newer, "new-owner")
        assert stored is not None
        loaded = await cache.load()
        assert loaded is not None
        assert loaded.marker == stored.marker

    asyncio.run(exercise())


def test_semantically_invalid_cached_snapshot_is_replaced() -> None:
    plane = ControlPlane(snapshot_payload())
    redis = FakeSnapshotRedis()

    async def exercise() -> None:
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        first = MicroAuth(
            secret_key="mas_test",
            http_client=control,
            redis_client=redis,
            persist_usage=False,
        )
        second = MicroAuth(
            secret_key="mas_test",
            http_client=control,
            redis_client=redis,
            persist_usage=False,
        )
        cache = first._snapshot_cache
        assert cache is not None
        poison = snapshot_payload()
        poison["keys"] = "not-an-array"
        token = await cache.acquire_refresh_lock()
        assert token is not None
        assert await cache.store_if_owner(poison, token) is not None
        await cache.release_refresh_lock(token)

        await asyncio.gather(first.startup(), second.startup())
        assert first._snapshot.ready
        assert second._snapshot.ready
        await first.aclose()
        await second.aclose()
        await control.aclose()

    asyncio.run(exercise())
    assert plane.snapshot_calls == 1


def test_all_cold_followers_wait_for_recovery_after_a_dead_owner() -> None:
    plane = ControlPlane(snapshot_payload())
    redis = FakeSnapshotRedis()

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/sdk/v1/snapshot":
            await asyncio.sleep(0.01)
        return plane(request)

    async def exercise() -> None:
        control = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        workers = [
            MicroAuth(
                secret_key="mas_test",
                http_client=control,
                redis_client=redis,
                persist_usage=False,
            )
            for _ in range(3)
        ]
        cache = workers[0]._snapshot_cache
        assert cache is not None
        redis.values[cache._lock_key] = "dead-owner"
        for worker in workers:
            worker._snapshot_cache_wait = 0.02

        async def expire_dead_owner() -> None:
            await asyncio.sleep(0.015)
            redis.values.pop(cache._lock_key, None)

        await asyncio.gather(
            expire_dead_owner(),
            *(worker.startup() for worker in workers),
        )
        assert all(worker._snapshot.ready for worker in workers)
        for worker in workers:
            await worker.aclose()
        await control.aclose()

    asyncio.run(exercise())
    assert plane.snapshot_calls == 1
