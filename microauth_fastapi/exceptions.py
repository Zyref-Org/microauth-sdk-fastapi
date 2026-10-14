"""Exceptions raised by the MicroAuth SDK.

All request-denial exceptions subclass ``fastapi.HTTPException`` so FastAPI
renders them as regular JSON error responses and they show up in OpenAPI.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException


class MicroAuthError(Exception):
    """Base class for SDK configuration/transport errors."""


class MicroAuthConfigurationError(MicroAuthError, ValueError):
    """The SDK configuration is invalid."""


class MicroAuthAPIError(MicroAuthError):
    """The MicroAuth API returned an unexpected response."""

    def __init__(self, status_code: int, detail: str = "") -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"MicroAuth API error {status_code}: {detail}")


class MicroAuthAuthorizationError(MicroAuthAPIError):
    """The tenant credential was authoritatively rejected with 401 or 403."""


@dataclass(frozen=True, slots=True)
class ErrorDetail:
    """One entry of a problem's ``errors`` list: what is wrong and where."""

    message: str
    location: str | None = None
    value: Any = None


class AccountAPIError(MicroAuthAPIError):
    """The Account API refused a request to manage API keys, or couldn't be reached.

    ``detail`` is one or more full sentences you can show the person, built
    from MicroAuth's problem JSON (RFC 9457). ``errors`` says which fields
    were wrong, and ``status_code`` is the status MicroAuth answered with.
    """

    def __init__(
        self,
        status_code: int,
        detail: str,
        *,
        title: str | None = None,
        errors: tuple[ErrorDetail, ...] = (),
    ) -> None:
        self.title = title
        self.errors = errors
        super().__init__(status_code, detail)


class AccountAPIUnavailable(AccountAPIError):
    """MicroAuth couldn't be reached, or failed on its side with a 5xx.

    Trying again later may work. ``status_code`` is 503, ready for your app
    to answer with. ``upstream_status`` is the status MicroAuth answered
    with, or None when it couldn't be reached at all.
    """

    def __init__(self, upstream_status: int | None = None) -> None:
        self.upstream_status = upstream_status
        super().__init__(503, "API keys can't be managed right now. Please try again in a moment.")


class MicroAuthResponseError(MicroAuthError):
    """The MicroAuth API returned malformed or unsafe data."""


class SnapshotValidationError(MicroAuthResponseError):
    """A snapshot failed schema or range validation."""


class SnapshotCacheError(MicroAuthError):
    """The shared snapshot cache could not be read or updated."""


class UsageReportingError(MicroAuthError):
    """Base class for durable usage reporting failures."""


class UsageQueueFull(UsageReportingError):
    """The bounded usage queue cannot accept another item."""

    def __init__(self, max_items: int) -> None:
        self.max_items = max_items
        super().__init__(
            f"MicroAuth usage queue is full ({max_items} items); "
            "rejecting work rather than dropping billable usage"
        )


class UsageAcknowledgementError(UsageReportingError):
    """The usage API did not acknowledge every submitted item."""


class UsageStoreError(UsageReportingError):
    """The usage journal or the Redis usage queue could not be read or updated."""


class UsageDrainError(UsageReportingError):
    """Graceful shutdown could not drain all queued usage."""

    def __init__(self, pending_items: int, detail: str = "") -> None:
        self.pending_items = pending_items
        self.detail = detail
        message = f"failed to drain {pending_items} usage item(s) during shutdown"
        if detail:
            message = f"{message}: {detail}"
        super().__init__(message)


class LimitBackendUnavailable(MicroAuthError):
    """A shared limit cannot be enforced because Redis is unavailable."""


class AuthDenied(HTTPException):
    """Base class for all request denials, so users can catch them broadly."""


class InvalidAPIKey(AuthDenied):
    def __init__(self, header_name: str) -> None:
        super().__init__(
            status_code=401,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": f'ApiKey header="{header_name}"'},
        )


class CustomerSuspended(AuthDenied):
    def __init__(self) -> None:
        super().__init__(status_code=403, detail="This account is suspended")


class CustomerPending(AuthDenied):
    """The customer signed up on a portal that approves accounts first."""

    def __init__(self) -> None:
        super().__init__(status_code=403, detail="This account is waiting for approval")


class PaymentRequired(AuthDenied):
    def __init__(self) -> None:
        super().__init__(status_code=402, detail="Insufficient credit balance")


class RateLimited(AuthDenied):
    def __init__(self, retry_after: float = 1.0) -> None:
        super().__init__(
            status_code=429,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(max(1, round(retry_after)))},
        )


class TooManyRequests(RateLimited):
    """A caller of ``TokenAuth`` went over a limit for API keys.

    Either the key's owner used up the requests per minute the API allows
    each person, or this client address sent too many unknown keys.
    ``Retry-After`` says how many seconds to wait.
    """

    def __init__(self, retry_after: float, detail: str) -> None:
        super().__init__(retry_after)
        self.headers = {"Retry-After": str(max(1, math.ceil(retry_after)))}
        self.detail = detail


class QuotaExceeded(AuthDenied):
    def __init__(self) -> None:
        super().__init__(status_code=429, detail="Monthly request quota exceeded")


class PlatformAllowanceExceeded(AuthDenied):
    def __init__(self) -> None:
        super().__init__(status_code=429, detail="Platform monthly request allowance exhausted")


class AuthUnavailable(AuthDenied):
    """MicroAuth couldn't be reached to check the request.

    ``retry_after`` becomes the ``Retry-After`` header, in seconds.
    """

    def __init__(self, retry_after: int | None = None) -> None:
        super().__init__(
            status_code=503,
            detail="Authorization is temporarily unavailable",
            headers=None if retry_after is None else {"Retry-After": str(retry_after)},
        )


class SignInRequired(AuthDenied):
    """Nobody is signed in. Pages can use ``auth.login_required`` to redirect instead."""

    def __init__(self) -> None:
        super().__init__(status_code=401, detail="Sign in to continue")


class SignInRedirect(AuthDenied):
    """Sends a signed out visitor of a page to the sign in route, then back."""

    def __init__(self, location: str) -> None:
        self.location = location
        super().__init__(
            status_code=303, detail="Sign in to continue", headers={"Location": location}
        )


class PermissionDenied(AuthDenied):
    """The signed in user lacks a role or permission the route requires."""

    def __init__(self, missing_roles: frozenset[str], missing_permissions: frozenset[str]) -> None:
        self.missing_roles = missing_roles
        self.missing_permissions = missing_permissions
        super().__init__(status_code=403, detail="You don't have permission to do this")


class CrossSiteRequest(AuthDenied):
    """An unsafe request that uses the session came from another site.

    Raised when neither ``Origin`` nor ``Referer`` matches the app's own
    origin, which is how a cross site form post looks.
    """

    def __init__(self) -> None:
        super().__init__(status_code=403, detail="This request came from another site")


class InvalidToken(AuthDenied):
    """The bearer token is missing, malformed, expired or not meant for this API.

    ``headers`` carries the RFC 6750 ``WWW-Authenticate`` challenge, which
    points clients at the protected resource metadata (RFC 9728).
    """

    def __init__(self, detail: str, www_authenticate: str) -> None:
        super().__init__(
            status_code=401, detail=detail, headers={"WWW-Authenticate": www_authenticate}
        )


class InsufficientScope(AuthDenied):
    """The caller is valid but lacks a scope the route requires.

    ``scopes`` is every scope the route needs, which the challenge lists so a
    client can ask for all of them in one step.
    """

    def __init__(
        self,
        scopes: frozenset[str],
        www_authenticate: str,
        detail: str = "The access token is missing a scope this request needs",
    ) -> None:
        self.scopes = scopes
        super().__init__(
            status_code=403,
            detail=detail,
            headers={"WWW-Authenticate": www_authenticate},
        )


class ReauthenticationRequired(AuthDenied):
    """MicroAuth wants a recent sign in before this action (RFC 9470).

    Send the browser to ``login_url``. It signs the person in again and
    brings them back to the page they were on. Left unhandled, it becomes a
    ``401`` problem JSON response that carries ``login_url``.
    """

    def __init__(self, login_url: str, max_age: int | None = None) -> None:
        self.login_url = login_url
        self.max_age = max_age
        super().__init__(status_code=401, detail="Sign in again to continue")
