"""MicroAuth SDK for FastAPI — API key auth, rate limiting and metered
billing for your API, powered by your MicroAuth tenant."""

from .exceptions import (
    AuthDenied,
    AuthUnavailable,
    CustomerSuspended,
    InvalidAPIKey,
    MicroAuthAPIError,
    MicroAuthError,
    PaymentRequired,
    QuotaExceeded,
    RateLimited,
)
from .models import Customer
from .sdk import MicroAuth

__version__ = "0.1.0"

__all__ = [
    "MicroAuth",
    "Customer",
    "AuthDenied",
    "AuthUnavailable",
    "CustomerSuspended",
    "InvalidAPIKey",
    "MicroAuthAPIError",
    "MicroAuthError",
    "PaymentRequired",
    "QuotaExceeded",
    "RateLimited",
    "__version__",
]
