"""MicroAuth SDK for FastAPI — API key auth, rate limiting and metered
billing for your API, powered by your MicroAuth tenant."""

from .exceptions import (
    AuthDenied,
    AuthUnavailable,
    CustomerSuspended,
    InvalidAPIKey,
    LimitBackendUnavailable,
    MicroAuthAPIError,
    MicroAuthAuthorizationError,
    MicroAuthConfigurationError,
    MicroAuthError,
    MicroAuthResponseError,
    PaymentRequired,
    PlatformAllowanceExceeded,
    QuotaExceeded,
    RateLimited,
    SnapshotCacheError,
    SnapshotValidationError,
    UsageAcknowledgementError,
    UsageDrainError,
    UsageItemRejected,
    UsageQueueFull,
    UsageReportingError,
    UsageStoreError,
)
from .models import Customer, PlatformMonthlyAllowance
from .sdk import MicroAuth

__version__ = "2.7.0"

__all__ = [
    "AuthDenied",
    "AuthUnavailable",
    "Customer",
    "CustomerSuspended",
    "InvalidAPIKey",
    "LimitBackendUnavailable",
    "MicroAuth",
    "MicroAuthAPIError",
    "MicroAuthAuthorizationError",
    "MicroAuthConfigurationError",
    "MicroAuthError",
    "MicroAuthResponseError",
    "PaymentRequired",
    "PlatformAllowanceExceeded",
    "PlatformMonthlyAllowance",
    "QuotaExceeded",
    "RateLimited",
    "SnapshotCacheError",
    "SnapshotValidationError",
    "UsageAcknowledgementError",
    "UsageDrainError",
    "UsageItemRejected",
    "UsageQueueFull",
    "UsageReportingError",
    "UsageStoreError",
    "__version__",
]
