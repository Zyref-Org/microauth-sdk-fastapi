"""MicroAuth-aligned time must not depend on this host's clock."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from email.utils import format_datetime

import pytest

import microauth_fastapi._clock as clock_module
from microauth_fastapi._clock import ServerClock


class FakeTime:
    def __init__(self, wall: float = 1_791_711_000.0) -> None:
        self.wall = wall
        self.mono = 500.0

    def advance(self, seconds: float) -> None:
        self.wall += seconds
        self.mono += seconds


@pytest.fixture
def host(monkeypatch: pytest.MonkeyPatch) -> FakeTime:
    fake = FakeTime()
    monkeypatch.setattr(clock_module.time, "time", lambda: fake.wall)
    monkeypatch.setattr(clock_module.time, "monotonic", lambda: fake.mono)
    return fake


def test_the_host_clock_is_used_until_microauth_answers(host: FakeTime) -> None:
    clock = ServerClock()
    assert clock.calibrated is False
    assert clock.time() == host.wall
    assert clock.offset == 0.0
    assert clock.error is None


def test_a_sample_aligns_time_and_extends_it_monotonically(host: FakeTime) -> None:
    clock = ServerClock()
    clock.observe(host.wall + 90.0, host.mono - 0.2, host.mono)
    # The sample is pinned to the middle of the exchange.
    assert clock.time() == pytest.approx(host.wall + 90.1)
    assert clock.offset == pytest.approx(90.1)
    assert clock.error == pytest.approx(0.1, abs=1e-4)

    host.advance(30)
    assert clock.time() == pytest.approx(host.wall + 90.1)
    assert clock.now() == datetime.fromtimestamp(clock.time(), timezone.utc)


def test_a_host_clock_step_does_not_move_microauth_time(host: FakeTime) -> None:
    clock = ServerClock()
    clock.observe(host.wall, host.mono, host.mono)
    before = clock.time()
    host.wall += 3_600  # NTP or an operator steps the wall clock
    assert clock.time() == pytest.approx(before)
    assert clock.offset == pytest.approx(-3_600)


def test_the_tightest_sample_wins_and_old_samples_loosen(host: FakeTime) -> None:
    clock = ServerClock()
    clock.observe(host.wall + 10, host.mono - 0.02, host.mono)  # error 0.01
    clock.observe(host.wall + 50, host.mono - 2.0, host.mono)  # error 1.0, ignored
    assert clock.offset == pytest.approx(10.01)

    host.advance(1_000_000)  # monotonic drift loosens the old sample
    assert clock.error == pytest.approx(0.01 + 1_000_000 * 1e-4)
    clock.observe(host.wall + 20, host.mono - 2.0, host.mono)  # now the better one
    assert clock.offset == pytest.approx(21.0)


def test_date_headers_count_with_their_one_second_resolution(host: FakeTime) -> None:
    clock = ServerClock()
    stamp = datetime.fromtimestamp(int(host.wall) + 40, timezone.utc)
    clock.observe_date_header(format_datetime(stamp, usegmt=True), host.mono, host.mono)
    assert clock.offset == pytest.approx(40.5 - (host.wall - int(host.wall)))
    assert clock.error == pytest.approx(0.5)

    # A generated_at with microseconds is a better sample than any Date.
    clock.observe(host.wall + 41, host.mono - 0.01, host.mono)
    assert clock.offset == pytest.approx(41.005)


@pytest.mark.parametrize(
    ("server_time", "sent", "received"),
    [(float("nan"), 0, 1), (float("inf"), 0, 1), (0.0, 0, 1), (-5.0, 0, 1), (100.0, 2, 1)],
)
def test_unusable_samples_are_ignored(
    host: FakeTime,
    server_time: float,
    sent: float,
    received: float,
) -> None:
    clock = ServerClock()
    clock.observe(server_time, sent, received)
    assert clock.calibrated is False


@pytest.mark.parametrize("header", [None, "", "yesterday", "Sat, 31 Feb 2026 99:00:00"])
def test_unreadable_date_headers_are_ignored(host: FakeTime, header: str | None) -> None:
    clock = ServerClock()
    clock.observe_date_header(header, host.mono, host.mono)
    assert clock.calibrated is False


def test_skew_is_logged_once_until_it_changes(
    host: FakeTime,
    caplog: pytest.LogCaptureFixture,
) -> None:
    clock = ServerClock()
    with caplog.at_level(logging.WARNING, logger="microauth"):
        clock.observe(host.wall + 1.0, host.mono, host.mono)  # within tolerance
        assert caplog.records == []
        clock.observe(host.wall + 12.0, host.mono, host.mono)
        clock.observe(host.wall + 12.2, host.mono, host.mono)
        assert len(caplog.records) == 1
        assert "12.0s behind MicroAuth's" in caplog.records[0].getMessage()
        clock.observe(host.wall - 30.0, host.mono, host.mono)
        assert len(caplog.records) == 2
        assert "30.0s ahead of MicroAuth's" in caplog.records[1].getMessage()
