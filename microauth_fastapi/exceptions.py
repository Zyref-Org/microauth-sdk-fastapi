"""Exceptions raised by the MicroAuth SDK.

All request-denial exceptions subclass ``fastapi.HTTPException`` so FastAPI
renders them as regular JSON error responses and they show up in OpenAPI.
"""

from __future__ import annotations

from fastapi import HTTPException


class MicroAuthError(Exception):
    """Base class for SDK configuration/transport errors."""


class MicroAuthAPIError(MicroAuthError):
    """The MicroAuth API returned an unexpected response."""

    def __init__(self, status_code: int, detail: str = "") -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"MicroAuth API error {status_code}: {detail}")


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


class AuthUnavailable(AuthDenied):
    def __init__(self) -> None:
        super().__init__(status_code=503, detail="Authorization is temporarily unavailable")
