"""Committed balances ordered by balance_seq keep local holds exact."""

from __future__ import annotations

import asyncio
import os
import random
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest
from test_limiter import FakeRedis, make_snapshot

from microauth_fastapi.limiter import (
    DENIED_BALANCE,
    Limiter,
    MemoryLimiter,
    RedisLimiter,
    ReservationDenied,
)
from microauth_fastapi.models import CustomerBalance, CustomerState, Snapshot

REDIS_URL = os.environ.get("MICROAUTH_TEST_REDIS_URL")
PRICE = 10
SCOPE = "tenant"


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


@asynccontextmanager
async def memory_limiter() -> AsyncIterator[Limiter]:
    yield MemoryLimiter()


@asynccontextmanager
async def fake_redis_limiter() -> AsyncIterator[Limiter]:
    yield RedisLimiter(redis_client=FakeRedis())


@asynccontextmanager
async def real_redis_limiter() -> AsyncIterator[Limiter]:
    assert REDIS_URL is not None
    prefix = f"ma-test-{uuid.uuid4().hex[:12]}"
    limiter = RedisLimiter(REDIS_URL, key_prefix=prefix, max_connections=4)
    try:
        yield limiter
    finally:
        client = limiter.redis_client
        keys = [key async for key in client.scan_iter(match=f"{prefix}:*")]
        if keys:
            await client.delete(*keys)
        await limiter.aclose()


LIMITERS: list[Any] = [
    pytest.param(memory_limiter, id="memory"),
    pytest.param(fake_redis_limiter, id="fake-redis"),
    pytest.param(
        real_redis_limiter,
        id="redis",
        marks=pytest.mark.skipif(
            REDIS_URL is None,
            reason="set MICROAUTH_TEST_REDIS_URL to run the Lua scripts",
        ),
    ),
]

LimiterFactory = Callable[[], Any]


def snapshot_at(
    base: Snapshot,
    balance: int,
    seq: int | None,
    *,
    step: int,
) -> tuple[Snapshot, CustomerState]:
    customer = replace(
        next(iter(base.customers.values())),
        credit_balance_micro=balance,
        balance_seq=seq,
    )
    assert base.generated_at is not None
    snapshot = replace(
        base,
        customers={customer.id: customer},
        generated_at=base.generated_at + timedelta(milliseconds=step),
        refresh_started_at=base.refresh_started_at + step / 1000,
    )
    return snapshot, customer


async def reserve(
    limiter: Limiter,
    snapshot: Snapshot,
    customer: CustomerState,
    spend: int = PRICE,
) -> Any:
    return await limiter.reserve_request(
        SCOPE,
        customer,
        snapshot,
        str(uuid.uuid4()),
        potential_spend_micro=spend,
        enforce_balance=True,
        enforce_quota=False,
        enforce_platform=False,
    )


async def available(
    limiter: Limiter,
    snapshot: Snapshot,
    customer: CustomerState,
) -> int:
    probe = await reserve(limiter, snapshot, customer, spend=0)
    await limiter.finalize_request(probe, billable=False)
    return int(probe.credit_remaining_micro)


@pytest.mark.parametrize("factory", LIMITERS)
def test_ack_releases_the_hold_and_stale_snapshots_cannot_undo_it(
    factory: LimiterFactory,
) -> None:
    async def exercise() -> None:
        async with factory() as limiter:
            base, _ = make_snapshot(balance=100, price=PRICE, quota=None)
            snapshot, customer = snapshot_at(base, 100, 7, step=0)
            await limiter.sync_snapshot(SCOPE, snapshot)

            first = await reserve(limiter, snapshot, customer)
            assert first.credit_remaining_micro == 90

            # The server charged it: balance 90 at seq 8.
            await limiter.acknowledge(
                [first.attachment(billable=True)],
                [CustomerBalance(customer.id, 90, 8)],
            )
            assert await available(limiter, snapshot, customer) == 90

            # A snapshot read before that charge committed arrives late,
            # with a newer generation time but the older sequence.
            stale, stale_customer = snapshot_at(base, 100, 7, step=5)
            await limiter.sync_snapshot(SCOPE, stale)
            assert await available(limiter, stale, stale_customer) == 90

            # A top-up is a newer sequence and applies immediately, even
            # with holds outstanding.
            second = await reserve(limiter, stale, stale_customer)
            topped_up, topped_customer = snapshot_at(base, 1_090, 9, step=10)
            await limiter.sync_snapshot(SCOPE, topped_up)
            assert await available(limiter, topped_up, topped_customer) == 1_080

            await limiter.acknowledge(
                [second.attachment(billable=True)],
                [CustomerBalance(customer.id, 1_080, 10)],
            )
            assert await available(limiter, topped_up, topped_customer) == 1_080

    run(exercise())


@pytest.mark.parametrize("factory", LIMITERS)
def test_out_of_order_acks_keep_the_newest_committed_balance(
    factory: LimiterFactory,
) -> None:
    async def exercise() -> None:
        async with factory() as limiter:
            base, _ = make_snapshot(balance=100, price=PRICE, quota=None)
            snapshot, customer = snapshot_at(base, 100, 1, step=0)
            first = await reserve(limiter, snapshot, customer)
            second = await reserve(limiter, snapshot, customer)
            assert second.credit_remaining_micro == 80

            await limiter.acknowledge(
                [second.attachment(billable=True)],
                [CustomerBalance(customer.id, 80, 3)],
            )
            # The older ack still releases its own hold, but its balance is
            # older than what the limiter already holds.
            await limiter.acknowledge(
                [first.attachment(billable=True)],
                [CustomerBalance(customer.id, 90, 2)],
            )
            assert await available(limiter, snapshot, customer) == 80

    run(exercise())


@pytest.mark.parametrize("factory", LIMITERS)
def test_balance_denial_uses_committed_balance_after_ack(
    factory: LimiterFactory,
) -> None:
    async def exercise() -> None:
        async with factory() as limiter:
            base, _ = make_snapshot(balance=20, price=PRICE, quota=None)
            snapshot, customer = snapshot_at(base, 20, 4, step=0)
            first = await reserve(limiter, snapshot, customer)
            second = await reserve(limiter, snapshot, customer)
            with pytest.raises(ReservationDenied) as caught:
                await reserve(limiter, snapshot, customer)
            assert caught.value.reason == DENIED_BALANCE

            await limiter.acknowledge(
                [
                    first.attachment(billable=True),
                    second.attachment(billable=True),
                ],
                [CustomerBalance(customer.id, 0, 6)],
            )
            with pytest.raises(ReservationDenied):
                await reserve(limiter, snapshot, customer)

    run(exercise())


@pytest.mark.parametrize("factory", LIMITERS)
@pytest.mark.parametrize("seed", [1, 7, 42])
def test_randomized_delivery_order_leaves_zero_drift(
    factory: LimiterFactory,
    seed: int,
) -> None:
    """Requests, flushes, acks and snapshots interleave in random order.

    Acks and snapshots are delivered late and out of order, and snapshots
    may have been read before charges committed. Once everything settles
    the limiter must agree with the server to the micro-dollar.
    """

    rng = random.Random(seed)

    async def exercise() -> None:
        async with factory() as limiter:
            server_balance = 50_000
            server_seq = 1
            base, _ = make_snapshot(balance=server_balance, price=PRICE, quota=None)
            step = 0
            client_snapshot, client_customer = snapshot_at(
                base, server_balance, server_seq, step=step
            )
            await limiter.sync_snapshot(SCOPE, client_snapshot)

            unflushed: list[dict[str, Any]] = []
            acks_in_flight: list[tuple[list[dict[str, Any]], CustomerBalance]] = []
            snapshots_in_flight: list[tuple[int, int]] = []

            for _ in range(600):
                action = rng.random()
                if action < 0.5:
                    try:
                        held = await reserve(limiter, client_snapshot, client_customer)
                    except ReservationDenied:
                        continue
                    unflushed.append(held.attachment(billable=True))
                elif action < 0.65 and unflushed:
                    count = rng.randint(1, len(unflushed))
                    batch, unflushed = unflushed[:count], unflushed[count:]
                    for _item in batch:
                        server_balance -= PRICE
                        server_seq += 1
                    acks_in_flight.append(
                        (
                            batch,
                            CustomerBalance(client_customer.id, server_balance, server_seq),
                        )
                    )
                elif action < 0.8 and acks_in_flight:
                    attachments, committed = acks_in_flight.pop(rng.randrange(len(acks_in_flight)))
                    await limiter.acknowledge(attachments, [committed])
                elif action < 0.88:
                    snapshots_in_flight.append((server_balance, server_seq))
                elif action < 0.94 and snapshots_in_flight:
                    balance, seq = snapshots_in_flight.pop(rng.randrange(len(snapshots_in_flight)))
                    step += 1
                    client_snapshot, client_customer = snapshot_at(base, balance, seq, step=step)
                    await limiter.sync_snapshot(SCOPE, client_snapshot)
                elif action < 0.97:
                    # An occasional top-up from the billing side.
                    server_balance += 1_000
                    server_seq += 1
                # Overstating credit is the dangerous direction: it lets
                # requests through that the server will refuse to charge.
                spendable = server_balance - PRICE * len(unflushed)
                assert await available(limiter, client_snapshot, client_customer) <= max(
                    0, spendable
                )

            for _item in unflushed:
                server_balance -= PRICE
                server_seq += 1
            if unflushed:
                acks_in_flight.append(
                    (
                        unflushed,
                        CustomerBalance(client_customer.id, server_balance, server_seq),
                    )
                )
            rng.shuffle(acks_in_flight)
            for attachments, committed in acks_in_flight:
                await limiter.acknowledge(attachments, [committed])
            for balance, seq in snapshots_in_flight:
                step += 1
                client_snapshot, client_customer = snapshot_at(base, balance, seq, step=step)
                await limiter.sync_snapshot(SCOPE, client_snapshot)
            step += 1
            final_snapshot, final_customer = snapshot_at(
                base, server_balance, server_seq, step=step
            )
            residual = server_balance - await available(limiter, final_snapshot, final_customer)
            assert residual == 0

    run(exercise())
