"""RFC 3339 parsing that accepts every timestamp the MicroAuth API emits."""

from __future__ import annotations

import re
from datetime import datetime

_FRACTION = re.compile(r"\.(\d+)")


def parse_iso8601(raw: str) -> datetime:
    """Parse an RFC 3339 timestamp on every supported Python version.

    Python 3.10's ``datetime.fromisoformat`` accepts neither a ``Z`` suffix
    nor fractional seconds other than 3 or 6 digits, while Go servers emit
    anywhere from 0 to 9. Fractions are normalized to microseconds first.
    Raises ``ValueError`` for anything that is not a timestamp.
    """
    value = raw.strip()
    if value[-1:] in ("Z", "z"):
        value = value[:-1] + "+00:00"
    match = _FRACTION.search(value)
    if match is not None:
        micros = match.group(1)[:6].ljust(6, "0")
        value = f"{value[: match.start()]}.{micros}{value[match.end():]}"
    return datetime.fromisoformat(value)
