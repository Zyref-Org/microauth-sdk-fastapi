"""Thin async client for the MicroAuth SDK API.

Three endpoints, all authenticated with the tenant secret key:
  GET  /sdk/v1/snapshot      full snapshot of customers, keys and limits
  GET  /sdk/v1/keys/verify   resolve one unknown key hash
  POST /sdk/v1/usage         report batched usage

Transient failures (network errors, 5xx, 429) are retried with a short
exponential backoff; everything else raises ``MicroAuthAPIError``.
"""

from __future__ import annotations

import asyncio
import logging
import math
from typing import Any

import httpx

from .exceptions import (
    MicroAuthAPIError,
    MicroAuthAuthorizationError,
    MicroAuthResponseError,
)

logger = logging.getLogger("microauth")

_RETRIES = 2
_BACKOFF = 0.25  # seconds, doubled per retry


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

    async def aclose(self) -> None:
        if self._owns_http and not self._http.is_closed:
            await self._http.aclose()

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        last_exc: Exception | None = None
        supplied_headers = kwargs.pop("headers", None)
        headers = dict(supplied_headers or {})
        headers["Authorization"] = self._authorization
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
                    return data
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
        return await self._request("GET", "/sdk/v1/snapshot")

    async def verify_key(self, key_hash: str) -> dict[str, Any]:
        return await self._request("GET", "/sdk/v1/keys/verify", params={"key_hash": key_hash})

    async def report_usage(self, items: list[dict[str, Any]]) -> dict[str, Any]:
        return await self._request("POST", "/sdk/v1/usage", json={"items": items})
