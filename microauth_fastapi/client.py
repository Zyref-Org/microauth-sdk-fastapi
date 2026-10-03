"""Thin async client for the MicroAuth SDK API.

Three endpoints, all authenticated with the tenant secret key:
  GET  /sdk/v1/snapshot      full snapshot of customers, keys and limits
  GET  /sdk/v1/keys/verify   resolve one unknown key hash
  POST /sdk/v1/usage         report batched usage

Transient failures (network errors, 5xx, 429) are retried with a short
exponential backoff; everything else raises ``MicroAuthAPIError``.

Snapshots are revalidated with ``If-None-Match``. When nothing changed the
API answers ``304`` with the new generation time, and the client hands back
the previous body stamped with that time, so callers always see a full
snapshot.
"""

from __future__ import annotations

import asyncio
import copy
import logging
import math
import platform
from typing import Any

import httpx

from ._version import __version__
from .exceptions import (
    MicroAuthAPIError,
    MicroAuthAuthorizationError,
    MicroAuthResponseError,
)

logger = logging.getLogger("microauth")

_RETRIES = 2
_BACKOFF = 0.25  # seconds, doubled per retry
USER_AGENT = (
    f"microauth-fastapi/{__version__} "
    f"python/{platform.python_version()}"
)
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
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._authorization = f"Bearer {secret_key}"
        self._timeout = timeout
        self._owns_http = http_client is None
        self._http = http_client or httpx.AsyncClient(
            timeout=timeout,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )
        self._snapshot_etag: str | None = None
        self._snapshot_body: dict[str, Any] | None = None

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
                if response.status_code == 304:
                    generated_at = response.headers.get(GENERATED_AT_HEADER)
                    if not generated_at:
                        raise MicroAuthResponseError(
                            f"MicroAuth API returned 304 for {path} without "
                            f"{GENERATED_AT_HEADER}"
                        )
                    return _NotModified(generated_at)
                if response.status_code < 500 and response.status_code != 429:
                    if response.status_code >= 400:
                        if response.status_code in (401, 403):
                            raise MicroAuthAuthorizationError(
                                response.status_code,
                                response.text[:300],
                            )
                        raise MicroAuthAPIError(response.status_code, response.text[:300])
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
                last_exc = MicroAuthAPIError(response.status_code, response.text[:300])
            if attempt < _RETRIES:
                delay = _BACKOFF * (2**attempt)
                if response is not None and response.status_code == 429:
                    try:
                        retry_after = float(response.headers.get("Retry-After", ""))
                    except ValueError:
                        retry_after = 0.0
                    if math.isfinite(retry_after):
                        delay = max(delay, min(retry_after, 10.0))
                await asyncio.sleep(delay)
        assert last_exc is not None
        if isinstance(last_exc, MicroAuthAPIError):
            raise last_exc
        raise MicroAuthAPIError(0, str(last_exc))

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
                    "MicroAuth API returned 304 for a snapshot this client "
                    "never received"
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
