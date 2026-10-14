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
    SignInRedirect,
    SignInRequired,
)

USER_DENIALS = (SignInRequired, PermissionDenied, CrossSiteRequest, SignInRedirect)
TOKEN_DENIALS = (InvalidToken, InsufficientScope)


async def problem_response(request: Request, exc: Exception) -> Response:
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
    return JSONResponse(
        body, status_code=status, headers=headers, media_type="application/problem+json"
    )


def install_handlers(app: Any, classes: tuple[type[Exception], ...]) -> None:
    for cls in classes:
        app.add_exception_handler(cls, problem_response)
