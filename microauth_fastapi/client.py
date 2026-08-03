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
from typing import Any

import httpx

from .exceptions import MicroAuthAPIError

logger = logging.getLogger("microauth")

_RETRIES = 2
_BACKOFF = 0.25  # seconds, doubled per retry


class APIClient:
    def __init__(self, base_url: str, secret_key: str, timeout: float) -> None:
        self._http = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {secret_key}"},
            timeout=timeout,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        last_exc: Exception | None = None
        for attempt in range(_RETRIES + 1):
            try:
                res = await self._http.request(method, path, **kwargs)
            except httpx.HTTPError as exc:
                last_exc = exc
            else:
                if res.status_code < 500 and res.status_code != 429:
                    if res.status_code >= 400:
                        raise MicroAuthAPIError(res.status_code, res.text[:300])
                    return res.json()
                last_exc = MicroAuthAPIError(res.status_code, res.text[:300])
            if attempt < _RETRIES:
                await asyncio.sleep(_BACKOFF * (2**attempt))
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
