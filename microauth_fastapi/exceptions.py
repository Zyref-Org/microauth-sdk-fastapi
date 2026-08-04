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


class UsageItemRejected(UsageAcknowledgementError):
    """The usage API explicitly rejected an item."""

    def __init__(self, idempotency_key: str, detail: str = "") -> None:
        self.idempotency_key = idempotency_key
        self.detail = detail
        message = f"usage item {idempotency_key} was rejected"
        if detail:
            message = f"{message}: {detail}"
        super().__init__(message)


class UsageStoreError(UsageReportingError):
    """The durable usage spool could not be read or updated."""


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
