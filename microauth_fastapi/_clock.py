"""Wall time aligned with MicroAuth's clock.

Usage timestamps, usage policy expiry and snapshot age are all compared with
times MicroAuth issued, so they must not depend on this host's clock being
right. Every response from MicroAuth is a time sample: a snapshot's
``generated_at`` to the microsecond, any other response's ``Date`` header to
the second. The clock keeps the sample with the smallest error bound (half
the round trip plus the source's resolution) and extends it with the
monotonic clock, so a host clock that is wrong, or that NTP steps while the
process runs, never moves MicroAuth time. The snapshot sync renews the
sample every ``sync_interval``, which also bounds how long a suspended host
can carry a stale reading after it wakes up.
"""

from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

logger = logging.getLogger("microauth")

# Monotonic clocks drift from true time by far less than this rate, so an old
# sample's error bound grows by it until a better sample replaces it.
_DRIFT_RATE = 1e-4
_WARN_SKEW_SECONDS = 2.0
_WARN_INTERVAL_SECONDS = 600.0


@dataclass(frozen=True, slots=True)
class _Sample:
    server_time: float  # MicroAuth epoch seconds at the exchange midpoint
    midpoint: float  # local monotonic seconds at the exchange midpoint
    error: float  # bound on the distance to MicroAuth's true time


class ServerClock:
    """MicroAuth's wall clock as seen from this process."""

    def __init__(self) -> None:
        self._sample: _Sample | None = None
        self._warned_at = -math.inf
        self._warned_offset = 0.0

    @property
    def calibrated(self) -> bool:
        return self._sample is not None

    def time(self) -> float:
        """MicroAuth's current time in epoch seconds.

        Falls back to this host's clock until the first response arrives.
        """

        sample = self._sample
        if sample is None:
            return time.time()
        return sample.server_time + (time.monotonic() - sample.midpoint)

    def now(self) -> datetime:
        return datetime.fromtimestamp(self.time(), timezone.utc)

    @property
    def offset(self) -> float:
        """Seconds to add to this host's clock to read MicroAuth's."""

        if self._sample is None:
            return 0.0
        return self.time() - time.time()

    @property
    def error(self) -> float | None:
        """Current bound on the distance to MicroAuth's time, in seconds."""

        sample = self._sample
        if sample is None:
            return None
        return sample.error + (time.monotonic() - sample.midpoint) * _DRIFT_RATE

    def observe(
        self,
        server_time: float,
        sent: float,
        received: float,
        *,
        resolution: float = 0.0,
    ) -> None:
        """Record that MicroAuth's clock read ``server_time`` at some point
        between the local monotonic instants ``sent`` and ``received``."""

        if not math.isfinite(server_time) or server_time <= 0 or received < sent:
            return
        candidate = _Sample(
            server_time=server_time,
            midpoint=(sent + received) / 2.0,
            error=(received - sent) / 2.0 + resolution,
        )
        current = self.error
        if current is not None and candidate.error > current:
            return
        self._sample = candidate
        self._warn_on_skew()

    def observe_date_header(self, value: str | None, sent: float, received: float) -> None:
        if not value:
            return
        try:
            parsed = parsedate_to_datetime(value)
        except (TypeError, ValueError, IndexError):
            return
        if parsed.tzinfo is None:
            return
        # Date is truncated to whole seconds, so the true time lies in the
        # following second.
        self.observe(parsed.timestamp() + 0.5, sent, received, resolution=0.5)

    def _warn_on_skew(self) -> None:
        offset = self.offset
        if abs(offset) < _WARN_SKEW_SECONDS:
            return
        now = time.monotonic()
        if (
            now - self._warned_at < _WARN_INTERVAL_SECONDS
            and abs(offset - self._warned_offset) < _WARN_SKEW_SECONDS
        ):
            return
        self._warned_at = now
        self._warned_offset = offset
        logger.warning(
            "microauth: this host's clock is %.1fs %s MicroAuth's. Usage "
            "timestamps and expiry checks use MicroAuth's time, but keep the "
            "host synced with NTP",
            abs(offset),
            "behind" if offset > 0 else "ahead of",
        )
