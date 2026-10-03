from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from microauth_fastapi._time import parse_iso8601

UTC = timezone.utc


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-10-02T10:00:00Z", datetime(2026, 10, 2, 10, tzinfo=UTC)),
        ("2026-10-02T10:00:00.1Z", datetime(2026, 10, 2, 10, 0, 0, 100_000, tzinfo=UTC)),
        ("2026-10-02T10:00:00.12345Z", datetime(2026, 10, 2, 10, 0, 0, 123_450, tzinfo=UTC)),
        ("2026-10-02T10:00:00.123456789Z", datetime(2026, 10, 2, 10, 0, 0, 123_456, tzinfo=UTC)),
        (
            "2026-10-02T15:00:00.5+05:00",
            datetime(2026, 10, 2, 15, 0, 0, 500_000, tzinfo=timezone(timedelta(hours=5))),
        ),
        ("2026-10-02T10:00:00.000001+00:00", datetime(2026, 10, 2, 10, 0, 0, 1, tzinfo=UTC)),
    ],
)
def test_parses_every_fraction_width_go_emits(raw: str, expected: datetime) -> None:
    assert parse_iso8601(raw) == expected


@pytest.mark.parametrize("raw", ["", "Z", "yesterday", "2026-13-01T00:00:00Z"])
def test_rejects_non_timestamps(raw: str) -> None:
    with pytest.raises(ValueError):
        parse_iso8601(raw)
