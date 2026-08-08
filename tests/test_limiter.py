from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from microauth_fastapi.exceptions import LimitBackendUnavailable
from microauth_fastapi.limiter import (
    DENIED_BALANCE,
    DENIED_PLATFORM,
    DENIED_QUOTA,
    MemoryLimiter,
    RedisLimiter,
    ReservationDenied,
)
from microauth_fastapi.models import (
    CustomerState,
    Effective,
    PlatformMonthlyAllowance,
    Snapshot,
)


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


def make_snapshot(
    *,
    platform_limit: int = 100,
    platform_used: int = 0,
    month_requests: int = 0,
    quota: int | None = 100,
    balance: int = 100,
    price: int = 10,
    generated_at: datetime | None = None,
    refresh_started_at: float | None = None,
) -> tuple[Snapshot, CustomerState]:
    generated_at = generated_at or datetime.now(timezone.utc)
    period_end = datetime(
        generated_at.year + int(generated_at.month == 12),
        1 if generated_at.month == 12 else generated_at.month + 1,
        1,
        tzinfo=timezone.utc,
    )
    customer = CustomerState(
        id="customer-1",
        status="active",
        credit_balance_micro=balance,
        month_requests=month_requests,
        effective=Effective(
            rps=10,
            price_per_request_micro=price,
            monthly_quota=quota,
            billing_model="payg",
            source="plan",
        ),
    )
    snapshot = Snapshot(
        customers={customer.id: customer},
        platform_allowance=PlatformMonthlyAllowance(
            limit=platform_limit,
            used=platform_used,
            remaining=max(0, platform_limit - platform_used),
            period_end=period_end,
            hard_cap=True,
        ),
        generated_at=generated_at,
        fetched_at=1.0,
        refresh_started_at=(
            generated_at.timestamp()
            if refresh_started_at is None
            else refresh_started_at
        ),
    )
    return snapshot, customer


class FakeRedis:
    def __init__(self) -> None:
        self.rps: dict[str, int] = {}
        self.quotas: dict[str, dict[str, int]] = {}
        self.balances: dict[str, dict[str, int]] = {}
        self.platform: dict[str, dict[str, int]] = {}
        self.reservations: dict[str, dict[str, int]] = {}
        self.acknowledgements: dict[str, dict[str, int]] = {}
        self.calls: list[tuple[str, tuple[str, ...], tuple[Any, ...]]] = []
        self.closed = False
        self.fail = False

    async def eval(
        self,
        script: str,
        number_of_keys: int,
        *values: Any,
    ) -> Any:
        keys = tuple(str(value) for value in values[:number_of_keys])
        args = values[number_of_keys:]
        self.calls.append((script, keys, args))
        if self.fail:
            raise OSError("redis down")
        if "microauth-rps-v3" in script:
            key = keys[0]
            self.rps[key] = self.rps.get(key, 0) + 1
            return self.rps[key]
        if "microauth-request-reserve-v3" in script:
            return self._reserve(keys, args)
        if "microauth-request-finalize-v3" in script:
            return self._finalize(keys, args)
        if "microauth-request-acknowledge-v3" in script:
            reservations = self.reservations.setdefault(keys[0], {})
            acknowledgements = self.acknowledgements.setdefault(keys[1], {})
            for token in args[2:]:
                if str(token) in reservations:
                    acknowledgements[str(token)] = int(args[0])
            return 1
        if "microauth-request-restore-v3" in script:
            return self._restore(keys, args)
        raise AssertionError("unexpected Lua script")

    def _reserve(self, keys: tuple[str, ...], args: tuple[Any, ...]) -> list[int]:
        (
            incoming_customer_floor,
            incoming_balance,
            snapshot_version,
            quota_limit,
            incoming_platform_floor,
            platform_limit,
            hard_cap,
            spend,
            enforce_quota,
            enforce_balance,
            enforce_platform,
            token,
            acknowledgement_cutoff,
            _ttl,
            maximum,
        ) = (int(value) if index != 11 else str(value) for index, value in enumerate(args))
        quota = self.quotas.setdefault(
            keys[0],
            {"floor": incoming_customer_floor, "count": incoming_customer_floor},
        )
        quota["floor"] = max(quota["floor"], incoming_customer_floor)
        quota["count"] = max(quota["count"], quota["floor"])
        balance = self.balances.setdefault(
            keys[1],
            {
                "balance": incoming_balance,
                "reserved": 0,
                "version": snapshot_version,
            },
        )
        reservations = self.reservations.setdefault(keys[3], {})
        acknowledgements = self.acknowledgements.setdefault(keys[4], {})
        for acknowledged_token, acknowledged_at in list(acknowledgements.items()):
            if acknowledged_at <= acknowledgement_cutoff:
                balance["reserved"] = max(
                    0,
                    balance["reserved"] - reservations.pop(acknowledged_token, 0),
                )
                del acknowledgements[acknowledged_token]
        if snapshot_version > balance["version"]:
            balance["balance"] = incoming_balance
            balance["version"] = snapshot_version
        platform = self.platform.setdefault(
            keys[2],
            {"floor": incoming_platform_floor, "count": incoming_platform_floor},
        )
        platform["floor"] = max(platform["floor"], incoming_platform_floor)
        platform["count"] = max(platform["count"], platform["floor"])

        reason = 0
        if enforce_quota and quota_limit >= 0 and quota["count"] >= quota_limit:
            reason = 2
        elif (
            enforce_balance
            and spend
            and balance["balance"] - balance["reserved"] < spend
        ):
            reason = 1
        elif (
            enforce_platform
            and hard_cap
            and platform["count"] >= platform_limit
        ):
            reason = 3
        elif (
            quota["count"] >= maximum
            or platform["count"] >= maximum
            or spend > maximum - balance["reserved"]
            or token in reservations
        ):
            reason = 4
        if reason == 0:
            quota["count"] += 1
            platform["count"] += 1
            balance["reserved"] += spend
            reservations[token] = spend
        quota_remaining = (
            -1 if quota_limit < 0 else max(0, quota_limit - quota["count"])
        )
        return [
            reason,
            max(0, balance["balance"] - balance["reserved"]),
            quota_remaining,
            max(0, platform_limit - platform["count"]),
        ]

    def _finalize(self, keys: tuple[str, ...], args: tuple[Any, ...]) -> int:
        token, billable, _ttl = str(args[0]), int(args[1]), int(args[2])
        balance = self.balances[keys[0]]
        reservations = self.reservations[keys[1]]
        if not billable:
            balance["reserved"] = max(
                0,
                balance["reserved"] - reservations.get(token, 0),
            )
            reservations[token] = 0
        return balance["reserved"]

    def _restore(self, keys: tuple[str, ...], args: tuple[Any, ...]) -> int:
        (
            customer_floor,
            incoming_balance,
            snapshot_version,
            platform_floor,
            _platform_limit,
            _hard_cap,
            spend,
            token,
            _ttl,
            maximum,
        ) = (int(value) if index != 7 else str(value) for index, value in enumerate(args))
        reservations = self.reservations.setdefault(keys[3], {})
        if token in reservations:
            return 0
        quota = self.quotas.setdefault(
            keys[0],
            {"floor": customer_floor, "count": customer_floor},
        )
        platform = self.platform.setdefault(
            keys[2],
            {"floor": platform_floor, "count": platform_floor},
        )
        balance = self.balances.setdefault(
            keys[1],
            {
                "balance": incoming_balance,
                "reserved": 0,
                "version": snapshot_version,
            },
        )
        if quota["count"] >= maximum or platform["count"] >= maximum:
            return -1
        quota["count"] += 1
        platform["count"] += 1
        balance["reserved"] += spend
        reservations[token] = spend
        return 1

    async def aclose(self) -> None:
        self.closed = True


def test_memory_rps_uses_same_fixed_window_semantics_as_redis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import microauth_fastapi.limiter as limiter_module

    monkeypatch.setattr(limiter_module.time, "time", lambda: 1000.25)
    limiter = MemoryLimiter()

    async def exercise() -> tuple[bool, bool, bool]:
        first = await limiter.allow("customer", "key-a", 1)
        second = await limiter.allow("customer", "key-a", 1)
        other_key = await limiter.allow("customer", "key-b", 1)
        return first, second, other_key

    assert run(exercise()) == (True, False, True)


def test_memory_reservation_is_atomic_under_concurrency() -> None:
    limiter = MemoryLimiter()
    snapshot, customer = make_snapshot(
        platform_limit=100,
        quota=10,
        balance=1_000,
        price=1,
    )

    async def exercise() -> list[str]:
        async def reserve(index: int) -> str:
            try:
                await limiter.reserve_request(
                    "tenant",
                    customer,
                    snapshot,
                    f"token-{index}",
                    potential_spend_micro=1,
                    enforce_balance=True,
                    enforce_quota=True,
                    enforce_platform=True,
                )
            except ReservationDenied as exc:
                return exc.reason
            return "accepted"

        return await asyncio.gather(*(reserve(index) for index in range(100)))

    outcomes = run(exercise())
    assert outcomes.count("accepted") == 10
    assert outcomes.count(DENIED_QUOTA) == 90


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"balance": 0}, DENIED_BALANCE),
        ({"quota": 0}, DENIED_QUOTA),
        ({"platform_limit": 0}, DENIED_PLATFORM),
    ],
)
def test_memory_atomic_reservation_has_typed_denial(
    kwargs: dict[str, int],
    reason: str,
) -> None:
    limiter = MemoryLimiter()
    snapshot, customer = make_snapshot(**kwargs)
    with pytest.raises(ReservationDenied) as caught:
        run(
            limiter.reserve_request(
                "tenant",
                customer,
                snapshot,
                "token",
                potential_spend_micro=10,
                enforce_balance=True,
                enforce_quota=True,
                enforce_platform=True,
            )
        )
    assert caught.value.reason == reason


def test_nonbillable_releases_only_money_and_refresh_preserves_usage() -> None:
    limiter = MemoryLimiter()
    first_snapshot, customer = make_snapshot(
        quota=1,
        balance=10,
        price=10,
    )

    async def exercise() -> None:
        reservation = await limiter.reserve_request(
            "tenant",
            customer,
            first_snapshot,
            "token",
            potential_spend_micro=10,
            enforce_balance=True,
            enforce_quota=True,
            enforce_platform=True,
        )
        await limiter.finalize_request(reservation, billable=False)
        refreshed, refreshed_customer = make_snapshot(
            quota=1,
            balance=10,
            price=10,
            generated_at=first_snapshot.generated_at + timedelta(seconds=1),  # type: ignore[operator]
            refresh_started_at=time_now(),
        )
        await limiter.sync_snapshot("tenant", refreshed)
        with pytest.raises(ReservationDenied) as caught:
            await limiter.reserve_request(
                "tenant",
                refreshed_customer,
                refreshed,
                "token-2",
                potential_spend_micro=10,
                enforce_balance=True,
                enforce_quota=True,
                enforce_platform=True,
            )
        assert caught.value.reason == DENIED_QUOTA

    run(exercise())


def test_acknowledged_spend_reconciles_only_after_later_snapshot() -> None:
    limiter = MemoryLimiter()
    first_snapshot, customer = make_snapshot(balance=10, price=10, quota=10)

    async def exercise() -> None:
        reservation = await limiter.reserve_request(
            "tenant",
            customer,
            first_snapshot,
            "token",
            potential_spend_micro=10,
            enforce_balance=True,
            enforce_quota=True,
            enforce_platform=True,
        )
        attachment = reservation.attachment(billable=True)
        await limiter.acknowledge([attachment])
        with pytest.raises(ReservationDenied) as caught:
            await limiter.reserve_request(
                "tenant",
                customer,
                first_snapshot,
                "token-2",
                potential_spend_micro=10,
                enforce_balance=True,
                enforce_quota=True,
                enforce_platform=True,
            )
        assert caught.value.reason == DENIED_BALANCE

        refreshed, refreshed_customer = make_snapshot(
            balance=20,
            price=10,
            quota=10,
            generated_at=first_snapshot.generated_at + timedelta(seconds=1),  # type: ignore[operator]
            refresh_started_at=time_now() + 1,
        )
        await limiter.sync_snapshot("tenant", refreshed)
        assert (
            await limiter.reserve_request(
                "tenant",
                refreshed_customer,
                refreshed,
                "token-3",
                potential_spend_micro=10,
                enforce_balance=True,
                enforce_quota=True,
                enforce_platform=True,
            )
        ).credit_remaining_micro == 10

    run(exercise())


def test_acknowledgements_are_batched_per_customer_and_credential() -> None:
    redis = FakeRedis()
    limiter = RedisLimiter(redis_client=redis)
    period_end = datetime.now(timezone.utc) + timedelta(days=1)

    def attachment(token: str, customer: str) -> dict[str, Any]:
        return {
            "token": token,
            "tenant_scope": "tenant",
            "customer_id": customer,
            "period_key": "period",
            "period_end": period_end.isoformat().replace("+00:00", "Z"),
            "spend_micro": 10,
        }

    attachments = [
        attachment(f"token-{index}", "customer-a") for index in range(500)
    ] + [attachment(f"other-{index}", "customer-b") for index in range(500)]

    run(limiter.acknowledge(attachments))

    ack_calls = [
        call
        for call in redis.calls
        if "microauth-request-acknowledge-v3" in call[0]
    ]
    # One round trip per customer/credential pair, not one per event.
    assert len(ack_calls) == 2
    assert {len(call[2]) - 2 for call in ack_calls} == {500}


def test_redis_reservation_is_shared_across_instances() -> None:
    redis = FakeRedis()
    first = RedisLimiter(redis_client=redis)
    second = RedisLimiter(redis_client=redis)
    snapshot, customer = make_snapshot(quota=2, platform_limit=2, balance=20)

    async def exercise() -> None:
        await first.reserve_request(
            "tenant",
            customer,
            snapshot,
            "one",
            potential_spend_micro=10,
            enforce_balance=True,
            enforce_quota=True,
            enforce_platform=True,
        )
        await second.reserve_request(
            "tenant",
            customer,
            snapshot,
            "two",
            potential_spend_micro=10,
            enforce_balance=True,
            enforce_quota=True,
            enforce_platform=True,
        )
        with pytest.raises(ReservationDenied) as caught:
            await first.reserve_request(
                "tenant",
                customer,
                snapshot,
                "three",
                potential_spend_micro=10,
                enforce_balance=True,
                enforce_quota=True,
                enforce_platform=True,
            )
        assert caught.value.reason == DENIED_QUOTA

    run(exercise())
    reserve_calls = [
        call for call in redis.calls if "microauth-request-reserve-v3" in call[0]
    ]
    assert len({call[1][0] for call in reserve_calls}) == 1
    assert all("{" in key and "}" in key for key in reserve_calls[0][1])


def test_redis_concurrent_workers_cannot_oversubscribe() -> None:
    redis = FakeRedis()
    workers = [
        RedisLimiter(redis_client=redis),
        RedisLimiter(redis_client=redis),
        RedisLimiter(redis_client=redis),
    ]
    snapshot, customer = make_snapshot(
        quota=10,
        platform_limit=10,
        balance=1_000,
        price=1,
    )

    async def exercise() -> list[str]:
        async def reserve(index: int) -> str:
            try:
                await workers[index % len(workers)].reserve_request(
                    "tenant",
                    customer,
                    snapshot,
                    f"token-{index}",
                    potential_spend_micro=1,
                    enforce_balance=True,
                    enforce_quota=True,
                    enforce_platform=True,
                )
            except ReservationDenied as exc:
                return exc.reason
            return "accepted"

        return await asyncio.gather(*(reserve(index) for index in range(100)))

    outcomes = run(exercise())
    assert outcomes.count("accepted") == 10
    assert outcomes.count(DENIED_QUOTA) == 90


def test_redis_restore_is_idempotent_and_ttl_exceeds_31_days() -> None:
    redis = FakeRedis()
    limiter = RedisLimiter(redis_client=redis)
    snapshot, customer = make_snapshot(balance=100, quota=100)

    async def exercise() -> None:
        reservation = await limiter.reserve_request(
            "tenant",
            customer,
            snapshot,
            "token",
            potential_spend_micro=10,
            enforce_balance=True,
            enforce_quota=True,
            enforce_platform=True,
        )
        attachment = reservation.attachment(billable=True)
        await limiter.restore([attachment], snapshot)
        await limiter.restore([attachment], snapshot)

    run(exercise())
    restore_calls = [
        call for call in redis.calls if "microauth-request-restore-v3" in call[0]
    ]
    assert restore_calls
    ttl_ms = int(restore_calls[0][2][-2])
    assert ttl_ms > 31 * 24 * 60 * 60 * 1000
    assert sum(state["count"] for state in redis.quotas.values()) == 1


def test_redis_limits_fail_closed_when_backend_is_down() -> None:
    redis = FakeRedis()
    redis.fail = True
    limiter = RedisLimiter(redis_client=redis)
    snapshot, customer = make_snapshot()
    with pytest.raises(LimitBackendUnavailable):
        run(
            limiter.reserve_request(
                "tenant",
                customer,
                snapshot,
                "token",
                potential_spend_micro=10,
                enforce_balance=True,
                enforce_quota=True,
                enforce_platform=True,
            )
        )


def test_redis_rps_fails_open_during_short_outage() -> None:
    redis = FakeRedis()
    redis.fail = True
    limiter = RedisLimiter(redis_client=redis)
    assert run(limiter.allow("customer", "key", 1)) is True
    assert run(limiter.allow("customer", "key", 1)) is True


def test_external_redis_is_not_closed() -> None:
    redis = FakeRedis()
    limiter = RedisLimiter(redis_client=redis)
    run(limiter.aclose())
    assert redis.closed is False


def time_now() -> float:
    return datetime.now(timezone.utc).timestamp()
