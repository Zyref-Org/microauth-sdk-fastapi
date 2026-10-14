"""Problem JSON (RFC 9457) responses for user and token denials.

The body keeps the ``detail`` member FastAPI clients already read, so moving
from the default ``{"detail": ...}`` shape costs nothing.
"""

from __future__ import annotations

from http import HTTPStatus
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse, Response

from .exceptions import (
    CrossSiteRequest,
    InsufficientScope,
    InvalidToken,
    PermissionDenied,
    ReauthenticationRequired,
    SignInRedirect,
    SignInRequired,
    TooManyRequests,
)

USER_DENIALS = (
    SignInRequired,
    PermissionDenied,
    CrossSiteRequest,
    SignInRedirect,
    ReauthenticationRequired,
)
TOKEN_DENIALS = (InvalidToken, InsufficientScope, TooManyRequests)


async def refusal_response(request: Request, exc: Exception) -> Response:
    """The response the SDK sends for one of its refusals.

    Problem JSON (RFC 9457) for most, and a bare redirect for
    ``SignInRedirect``. Call it from your own exception handler for the
    requests you don't render yourself, such as API calls.
    """
    status = getattr(exc, "status_code", 500)
    headers = dict(getattr(exc, "headers", None) or {})
    if isinstance(exc, SignInRedirect):
        headers["Cache-Control"] = "no-store"
        return Response(status_code=status, headers=headers)
    try:
        title = HTTPStatus(status).phrase
    except ValueError:
        title = "Error"
    body: dict[str, Any] = {
        "type": "about:blank",
        "title": title,
        "status": status,
        "detail": getattr(exc, "detail", title),
    }
    if isinstance(exc, InsufficientScope):
        body["scopes"] = sorted(exc.scopes)
    if isinstance(exc, ReauthenticationRequired):
        body["login_url"] = exc.login_url
        headers["Cache-Control"] = "no-store"
    return JSONResponse(
        body, status_code=status, headers=headers, media_type="application/problem+json"
    )


def install_handlers(app: Any, classes: tuple[type[Exception], ...]) -> None:
    """Handle ``classes`` with ``refusal_response``, except the ones the app
    already handles itself."""
    for cls in classes:
        if cls not in app.exception_handlers:
            app.add_exception_handler(cls, refusal_response)
