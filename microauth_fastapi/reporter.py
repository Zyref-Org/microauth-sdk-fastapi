"""Batched usage reporting.

Billable requests are counted in memory (one integer per API key per hour
bucket — the server's aggregation granularity) and flushed to MicroAuth in
the background. A worker crash can lose at most ``report_interval`` seconds
of usage; everything else is delivered exactly once thanks to the server's
idempotent hourly upsert.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from .client import APIClient
from .exceptions import MicroAuthAPIError

logger = logging.getLogger("microauth")

_MAX_BUCKETS = 10_000  # safety valve if MicroAuth is unreachable for long
_BATCH = 1000  # server-side max items per report


def _hour_bucket() -> str:
    return datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0).isoformat()


class UsageReporter:
    def __init__(self, client: APIClient, interval: float) -> None:
        self._client = client
        self._interval = interval
        self._pending: dict[tuple[str, str], int] = {}  # (key_id, hour) -> requests
        self._task: asyncio.Task[None] | None = None
        self._flush_lock = asyncio.Lock()

    def record(self, key_id: str) -> None:
        """Count one billable request. O(1), no I/O, safe on the hot path."""
        bucket = (key_id, _hour_bucket())
        if len(self._pending) >= _MAX_BUCKETS and bucket not in self._pending:
            logger.error("microauth: usage buffer full, dropping a bucket — is the API reachable?")
            return
        self._pending[bucket] = self._pending.get(bucket, 0) + 1

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._loop(), name="microauth-usage-reporter")

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(self._interval)
            try:
                await self.flush()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("microauth: usage flush failed; will retry")

    async def flush(self) -> None:
        """Send everything pending. Buffered data is retried on failure."""
        async with self._flush_lock:
            if not self._pending:
                return
            batch, self._pending = self._pending, {}
            items = [
                {"key_id": key_id, "requests": count, "period_start": hour}
                for (key_id, hour), count in batch.items()
                if count > 0
            ]
            for i in range(0, len(items), _BATCH):
                chunk = items[i : i + _BATCH]
                try:
                    res = await self._client.report_usage(chunk)
                    if res.get("rejected"):
                        logger.warning("microauth: %s usage item(s) rejected", res["rejected"])
                except MicroAuthAPIError:
                    # Put the failed chunk back so nothing is lost.
                    for item in chunk:
                        bucket = (item["key_id"], item["period_start"])
                        self._pending[bucket] = self._pending.get(bucket, 0) + item["requests"]
                    raise

    async def aclose(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        try:
            await self.flush()
        except Exception:
            logger.exception("microauth: final usage flush failed; up to %d bucket(s) lost", len(self._pending))
