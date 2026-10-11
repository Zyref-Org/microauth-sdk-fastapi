"""Thin async client for the MicroAuth SDK API.

Three endpoints, all authenticated with the API's SDK secret key:
  GET  /sdk/v1/snapshot      customers, keys and limits
  GET  /sdk/v1/keys/verify   resolve one key hash missing from the snapshot
  POST /sdk/v1/usage         report batched usage, answered with receipts

Transient failures (network errors, 5xx, 429) are retried with a short
exponential backoff that honors ``Retry-After``; everything else raises
``MicroAuthAPIError`` carrying the problem ``detail`` MicroAuth sent.

Snapshots are revalidated with ``If-None-Match``. When nothing changed the
API answers ``304`` with the new generation time, and the client hands back
the previous body stamped with that time, so callers always see a full
snapshot.

Every response also calibrates the shared :class:`ServerClock`.
"""

from __future__ import annotations

import asyncio
import copy
import logging
import math
import platform
import time
from typing import Any

import httpx

from ._clock import ServerClock
from ._time import parse_iso8601
from ._version import __version__
from .exceptions import (
    MicroAuthAPIError,
    MicroAuthAuthorizationError,
    MicroAuthResponseError,
)

logger = logging.getLogger("microauth")

_RETRIES = 2
_BACKOFF = 0.25  # seconds, doubled per retry
_MAX_RETRY_AFTER = 10.0
USER_AGENT = f"microauth-fastapi/{__version__} python/{platform.python_version()}"
GENERATED_AT_HEADER = "X-MicroAuth-Generated-At"


class _NotModified:
    __slots__ = ("generated_at",)

    def __init__(self, generated_at: str) -> None:
        self.generated_at = generated_at


class APIClient:
    def __init__(
        self,
        base_url: str,
        secret_key: str,
        timeout: float,
        *,
        http_client: httpx.AsyncClient | None = None,
        clock: ServerClock | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._authorization = f"Bearer {secret_key}"
        self._timeout = timeout
        self._owns_http = http_client is None
        self._http = http_client or httpx.AsyncClient(
            timeout=timeout,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )
        self.clock = clock or ServerClock()
        self._snapshot_etag: str | None = None
        self._snapshot_body: dict[str, Any] | None = None

    @property
    def base_url(self) -> str:
        return self._base_url

    async def aclose(self) -> None:
        if self._owns_http and not self._http.is_closed:
            await self._http.aclose()

    def forget_snapshot(self) -> None:
        """Drop the revalidation state so the next snapshot is a full fetch."""

        self._snapshot_etag = None
        self._snapshot_body = None

    async def _request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        result = await self._send(method, path, **kwargs)
        if isinstance(result, _NotModified):
            raise MicroAuthResponseError(
                f"MicroAuth API returned 304 for {path} without a validator"
            )
        return result[0]

    async def _send(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> tuple[dict[str, Any], httpx.Headers] | _NotModified:
        last_exc: Exception | None = None
        supplied_headers = kwargs.pop("headers", None)
        headers = dict(supplied_headers or {})
        headers["Authorization"] = self._authorization
        headers.setdefault("User-Agent", USER_AGENT)
        for attempt in range(_RETRIES + 1):
            response: httpx.Response | None = None
            sent = time.monotonic()
            try:
                response = await self._http.request(
                    method,
                    f"{self._base_url}{path}",
                    headers=headers,
                    timeout=self._timeout,
                    **kwargs,
                )
            except httpx.HTTPError as exc:
                last_exc = exc
            else:
                self._observe_clock(response, sent, time.monotonic())
                if response.status_code == 304:
                    generated_at = response.headers.get(GENERATED_AT_HEADER)
                    if not generated_at:
                        raise MicroAuthResponseError(
                            f"MicroAuth API returned 304 for {path} without {GENERATED_AT_HEADER}"
                        )
                    return _NotModified(generated_at)
                if response.status_code < 500 and response.status_code != 429:
                    if response.status_code >= 400:
                        detail = _error_detail(response)
                        if response.status_code in (401, 403):
                            raise MicroAuthAuthorizationError(response.status_code, detail)
                        raise MicroAuthAPIError(response.status_code, detail)
                    try:
                        data = response.json()
                    except ValueError as exc:
                        raise MicroAuthResponseError(
                            f"MicroAuth API returned invalid JSON for {path}"
                        ) from exc
                    if not isinstance(data, dict):
                        raise MicroAuthResponseError(
                            f"MicroAuth API returned a non-object response for {path}"
                        )
                    return data, response.headers
                last_exc = MicroAuthAPIError(response.status_code, _error_detail(response))
            if attempt < _RETRIES:
                delay = _BACKOFF * (2**attempt)
                if response is not None and response.status_code in (429, 503):
                    delay = max(delay, _retry_after(response))
                await asyncio.sleep(delay)
        assert last_exc is not None
        if isinstance(last_exc, MicroAuthAPIError):
            raise last_exc
        raise MicroAuthAPIError(0, _transport_detail(last_exc))

    def _observe_clock(self, response: httpx.Response, sent: float, received: float) -> None:
        generated_at = response.headers.get(GENERATED_AT_HEADER)
        if generated_at:
            try:
                server_time = parse_iso8601(generated_at).timestamp()
            except ValueError:
                pass
            else:
                self.clock.observe(server_time, sent, received)
                return
        self.clock.observe_date_header(response.headers.get("Date"), sent, received)

    async def snapshot(self) -> dict[str, Any]:
        headers: dict[str, str] = {}
        etag = self._snapshot_etag
        body = self._snapshot_body
        if etag is not None and body is not None:
            headers["If-None-Match"] = etag
        result = await self._send("GET", "/sdk/v1/snapshot", headers=headers)
        if isinstance(result, _NotModified):
            if body is None:
                raise MicroAuthResponseError(
                    "MicroAuth API returned 304 for a snapshot this client never received"
                )
            revalidated = copy.copy(body)
            revalidated["generated_at"] = result.generated_at
            self._snapshot_body = revalidated
            return copy.copy(revalidated)
        data, response_headers = result
        new_etag = response_headers.get("ETag")
        if new_etag:
            self._snapshot_etag = new_etag
            self._snapshot_body = data
        else:
            self.forget_snapshot()
        return copy.copy(data)

    async def verify_key(self, key_hash: str) -> dict[str, Any]:
        return await self._request("GET", "/sdk/v1/keys/verify", params={"key_hash": key_hash})

    async def report_usage(self, items: list[dict[str, Any]]) -> dict[str, Any]:
        return await self._request("POST", "/sdk/v1/usage", json={"items": items})


def _error_detail(response: httpx.Response) -> str:
    """The human readable part of an error, from MicroAuth's problem JSON."""

    try:
        body = response.json()
    except ValueError:
        return response.text[:300]
    if isinstance(body, dict):
        for field in ("detail", "title"):
            value = body.get(field)
            if isinstance(value, str) and value:
                return value[:300]
    return response.text[:300]


def _retry_after(response: httpx.Response) -> float:
    try:
        value = float(response.headers.get("Retry-After", ""))
    except ValueError:
        return 0.0
    if not math.isfinite(value) or value < 0:
        return 0.0
    return min(value, _MAX_RETRY_AFTER)


def _transport_detail(exc: Exception) -> str:
    message = str(exc)
    name = type(exc).__name__
    return f"{name}: {message}" if message else name
