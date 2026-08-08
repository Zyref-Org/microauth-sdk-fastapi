from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from fastapi import FastAPI, Security
from test_sdk import API_KEY, ControlPlane, snapshot_payload

from microauth_fastapi import Customer, MicroAuth
from microauth_fastapi.sdk import _parse_snapshot
from microauth_fastapi.snapshot_cache import RedisSnapshotCache


class FakeSnapshotRedis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.hashes: dict[str, dict[str, str]] = {}
        self.counters: dict[str, int] = {}
        self.closed = False

    async def get(self, key: str) -> str | None:
        return self.values.get(key)

    async def eval(
        self,
        script: str,
        number_of_keys: int,
        *values: Any,
    ) -> int:
        keys = [str(value) for value in values[:number_of_keys]]
        args = list(values[number_of_keys:])
        if "microauth-snapshot-acquire-v3" in script:
            lock_key, fence_key = keys
            if lock_key in self.values:
                return 0
            self.values[lock_key] = str(args[0])
            self.counters[fence_key] = self.counters.get(fence_key, 0) + 1
            return self.counters[fence_key]
        if "microauth-snapshot-store-v3" in script:
            data_key, lock_key, meta_key = keys
            token, encoded, _ttl, fence, generated, force = args
            if self.values.get(lock_key) != str(token):
                return 0
            meta = self.hashes.setdefault(meta_key, {})
            if int(fence) < int(meta.get("fence", -1)):
                return -1
            if not int(force) and int(generated) < int(meta.get("generated", -1)):
                return -2
            self.values[data_key] = str(encoded)
            meta["fence"] = str(fence)
            meta["generated"] = str(generated)
            return 1
        if "microauth-snapshot-release-v3" in script:
            if self.values.get(keys[0]) == str(args[0]):
                del self.values[keys[0]]
                return 1
            return 0
        if "microauth-snapshot-extend-v3" in script:
            return 1 if self.values.get(keys[0]) == str(args[0]) else 0
        if "microauth-snapshot-discard-v3" in script:
            if self.values.get(keys[0]) == str(args[0]):
                del self.values[keys[0]]
                return 1
            return 0
        # Minimal limiter behavior so authenticated requests can flow in
        # tests that focus on snapshot coordination.
        if "microauth-rps-v3" in script:
            return 1
        if "microauth-request-reserve-v3" in script:
            return [0, 1_000_000, -1, 1_000_000]
        if "microauth-request-finalize-v3" in script:
            return 0
        if "microauth-request-acknowledge-v3" in script:
            return 1
        raise AssertionError("unexpected Lua script")

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
    from microauth_fastapi.snapshot_cache import SnapshotLease

    redis = FakeSnapshotRedis()
    cache = RedisSnapshotCache(redis, "tenant", ttl=60)
    now = datetime.now(timezone.utc)
    older = snapshot_payload(generated_at=now - timedelta(seconds=30))
    newer = snapshot_payload(generated_at=now)

    async def exercise() -> None:
        old_lease = await cache.acquire_refresh_lock()
        assert old_lease is not None
        # The first owner's lock lease expires and a new owner takes over.
        del redis.values[cache._lock_key]
        new_lease = await cache.acquire_refresh_lock()
        assert new_lease is not None
        assert new_lease.fence > old_lease.fence
        # The expired owner no longer holds the lock, so its publication is
        # rejected outright.
        assert (
            await cache.store_if_owner(
                older,
                old_lease,
                refresh_started_at=now.timestamp() - 30,
                generated_at_ms=int((now.timestamp() - 30) * 1000),
            )
            is None
        )
        stored = await cache.store_if_owner(
            newer,
            new_lease,
            refresh_started_at=now.timestamp(),
            generated_at_ms=int(now.timestamp() * 1000),
        )
        assert stored is not None
        loaded = await cache.load()
        assert loaded is not None
        assert loaded.marker == stored.marker
        assert loaded.refresh_started_at == stored.refresh_started_at

        # Even a caller that somehow holds the current lock token cannot
        # publish with a stale fence or an older generation.
        stale_fence = SnapshotLease(token=new_lease.token, fence=old_lease.fence)
        assert (
            await cache.store_if_owner(
                older,
                stale_fence,
                refresh_started_at=now.timestamp(),
                generated_at_ms=int(now.timestamp() * 1000),
            )
            is None
        )
        assert (
            await cache.store_if_owner(
                older,
                new_lease,
                refresh_started_at=now.timestamp(),
                generated_at_ms=int((now.timestamp() - 30) * 1000),
            )
            is None
        )
        final = await cache.load()
        assert final is not None
        assert final.marker == stored.marker

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
        lease = await cache.acquire_refresh_lock()
        assert lease is not None
        import time as time_module

        assert (
            await cache.store_if_owner(
                poison,
                lease,
                refresh_started_at=time_module.time(),
                generated_at_ms=int(time_module.time() * 1000),
            )
            is not None
        )
        await cache.release_refresh_lock(lease)

        await asyncio.gather(first.startup(), second.startup())
        assert first._snapshot.ready
        assert second._snapshot.ready
        await first.aclose()
        await second.aclose()
        await control.aclose()

    asyncio.run(exercise())
    assert plane.snapshot_calls == 1


def test_hydrated_snapshots_preserve_the_origin_refresh_cutoff() -> None:
    plane = ControlPlane(snapshot_payload())
    redis = FakeSnapshotRedis()

    async def exercise() -> tuple[float, float]:
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        publisher = MicroAuth(
            secret_key="mas_test",
            http_client=control,
            redis_client=redis,
            persist_usage=False,
        )
        await publisher.startup()
        origin_cutoff = publisher._snapshot.refresh_started_at

        hydrator = MicroAuth(
            secret_key="mas_test",
            http_client=control,
            redis_client=redis,
            persist_usage=False,
        )
        await hydrator.startup()
        hydrated_cutoff = hydrator._snapshot.refresh_started_at
        await publisher.aclose()
        await hydrator.aclose()
        await control.aclose()
        return origin_cutoff, hydrated_cutoff

    origin_cutoff, hydrated_cutoff = asyncio.run(exercise())
    assert plane.snapshot_calls == 1
    # Reconciling acknowledged charges against a later cache-read time would
    # release monetary holds the cached balance has never seen.
    assert hydrated_cutoff == origin_cutoff


def test_different_credentials_do_not_share_a_snapshot_cache() -> None:
    plane = ControlPlane(snapshot_payload())
    redis = FakeSnapshotRedis()

    async def exercise() -> None:
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        first = MicroAuth(
            secret_key="mas_valid",
            http_client=control,
            redis_client=redis,
            persist_usage=False,
        )
        second = MicroAuth(
            secret_key="mas_revoked",
            http_client=control,
            redis_client=redis,
            persist_usage=False,
        )
        assert first._snapshot_cache is not None
        assert second._snapshot_cache is not None
        assert (
            first._snapshot_cache._cache_key
            != second._snapshot_cache._cache_key
        )
        await first.startup()
        await second.startup()
        await first.aclose()
        await second.aclose()
        await control.aclose()

    asyncio.run(exercise())
    # Each credential must validate itself against the control plane; a
    # revoked secret cannot ride on another credential's cached snapshots.
    assert plane.snapshot_calls == 2


def test_older_cached_data_cannot_replace_a_newer_local_snapshot() -> None:
    async def exercise() -> None:
        auth = MicroAuth(secret_key="mas_test", persist_usage=False)
        now = datetime.now(timezone.utc)
        newer = _parse_snapshot(snapshot_payload(generated_at=now))
        older = _parse_snapshot(
            snapshot_payload(generated_at=now - timedelta(seconds=60))
        )
        await auth._apply_snapshot(newer)
        await auth._apply_snapshot(older)
        assert auth._snapshot.generated_at == newer.generated_at
        await auth.aclose()

    asyncio.run(exercise())


def test_cached_data_cannot_clear_an_authoritative_credential_rejection() -> None:
    async def exercise() -> None:
        auth = MicroAuth(secret_key="mas_test", persist_usage=False)
        auth._invalidate_authorization()
        await auth._apply_snapshot(_parse_snapshot(snapshot_payload()))
        assert auth._authorization_invalid is True
        await auth._apply_snapshot(
            _parse_snapshot(snapshot_payload()),
            from_control_plane=True,
        )
        assert auth._authorization_invalid is False
        await auth.aclose()

    asyncio.run(exercise())


def test_frozen_worker_recovers_from_the_shared_cache_on_request() -> None:
    plane = ControlPlane(snapshot_payload())
    redis = FakeSnapshotRedis()

    async def exercise() -> None:
        control = httpx.AsyncClient(transport=httpx.MockTransport(plane))
        publisher = MicroAuth(
            secret_key="mas_test",
            http_client=control,
            redis_client=redis,
            persist_usage=False,
        )
        await publisher.startup()
        await publisher.aclose()

        app = FastAPI()
        frozen = MicroAuth(
            app,
            secret_key="mas_test",
            http_client=control,
            redis_client=redis,
            persist_usage=False,
            enforce_rps=False,
        )
        # Simulate a thawed serverless worker whose local snapshot never
        # became usable because its background loop was frozen.
        frozen._started = True

        @app.get("/protected")
        async def protected(
            customer: Customer = Security(frozen),
        ) -> dict[str, bool]:
            return {"ok": True}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as caller:
            response = await caller.get(
                "/protected",
                headers={"X-API-Key": API_KEY},
            )
        assert response.status_code == 200
        await frozen.aclose()
        await control.aclose()

    asyncio.run(exercise())
    # Recovery used the shared cache, not another control-plane fetch.
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
