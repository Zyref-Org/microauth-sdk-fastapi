"""Close what an SDK object created when the app shuts down."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

logger = logging.getLogger("microauth")


class CloseOnShutdown:
    """ASGI middleware that awaits ``close`` once the app has shut down."""

    def __init__(self, app: Any, close: Callable[[], Awaitable[None]], name: str) -> None:
        self.app = app
        self.close = close
        self.name = name

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "lifespan":
            await self.app(scope, receive, send)
            return

        async def lifespan_send(message: dict[str, Any]) -> None:
            if message["type"] == "lifespan.shutdown.complete":
                try:
                    await self.close()
                except Exception:
                    logger.exception("microauth: closing %s at shutdown failed", self.name)
            await send(message)

        await self.app(scope, receive, lifespan_send)
