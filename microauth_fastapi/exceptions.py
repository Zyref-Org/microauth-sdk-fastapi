"""Exceptions raised by the MicroAuth SDK.

All request-denial exceptions subclass ``fastapi.HTTPException`` so FastAPI
renders them as regular JSON error responses and they show up in OpenAPI.
"""

from __future__ import annotations

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


class QuotaExceeded(AuthDenied):
    def __init__(self) -> None:
        super().__init__(status_code=429, detail="Monthly request quota exceeded")


class PlatformAllowanceExceeded(AuthDenied):
    def __init__(self) -> None:
        super().__init__(status_code=429, detail="Platform monthly request allowance exhausted")


class AuthUnavailable(AuthDenied):
    def __init__(self) -> None:
        super().__init__(status_code=503, detail="Authorization is temporarily unavailable")


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
    """The access token is valid but lacks a scope the route requires.

    ``scopes`` is every scope the route needs, which the challenge lists so a
    client can ask for all of them in one step.
    """

    def __init__(self, scopes: frozenset[str], www_authenticate: str) -> None:
        self.scopes = scopes
        super().__init__(
            status_code=403,
            detail="The access token is missing a scope this request needs",
            headers={"WWW-Authenticate": www_authenticate},
        )
