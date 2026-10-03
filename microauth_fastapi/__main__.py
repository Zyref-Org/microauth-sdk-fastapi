"""``python -m microauth_fastapi check``: confirm an integration end to end.

Reads the same environment variables as ``MicroAuth()`` and reports what the
SDK would see at startup, without serving traffic or reporting usage. Pass
``--key`` with one of your customers' API keys to see exactly how a request
with that key would be treated.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

from ._version import __version__
from .client import APIClient
from .exceptions import (
    MicroAuthAPIError,
    MicroAuthAuthorizationError,
    MicroAuthError,
)
from .models import CustomerState, Snapshot

DEFAULT_BASE_URL = "https://api.microauth.com"


class _Report:
    def __init__(self, out: TextIO) -> None:
        self.out = out
        self.failed = False

    def ok(self, message: str) -> None:
        self.out.write(f"  ok    {message}\n")

    def warn(self, message: str) -> None:
        self.out.write(f"  warn  {message}\n")

    def fail(self, message: str) -> None:
        self.failed = True
        self.out.write(f"  fail  {message}\n")

    def info(self, message: str) -> None:
        self.out.write(f"        {message}\n")

    def heading(self, message: str) -> None:
        self.out.write(f"\n{message}\n")


def _money(micro: int) -> str:
    sign = "-" if micro < 0 else ""
    return f"{sign}${abs(micro) / 1_000_000:,.6f}".rstrip("0").rstrip(".")


async def _check(args: argparse.Namespace, out: TextIO) -> int:
    from .sdk import _parse_customer, _parse_snapshot

    report = _Report(out)
    out.write(f"MicroAuth FastAPI SDK {__version__}\n")

    secret = args.secret_key or os.environ.get("MICROAUTH_SECRET_KEY", "")
    base_url = args.base_url or os.environ.get("MICROAUTH_BASE_URL") or DEFAULT_BASE_URL
    report.heading("Configuration")
    if not secret.startswith("mas_"):
        report.fail(
            "MICROAUTH_SECRET_KEY is missing or is not an SDK secret key (mas_...). "
            "Copy it from your API's Overview page in the MicroAuth dashboard."
        )
        return 1
    report.ok(f"SDK secret key mas_...{secret[-4:]}")
    report.ok(f"control plane {base_url}")

    client = APIClient(base_url, secret, args.timeout)
    try:
        report.heading("Control plane")
        try:
            data = await client.snapshot()
        except MicroAuthAuthorizationError:
            report.fail(
                "the API rejected this secret. It may have been rotated; copy the "
                "current one from the dashboard."
            )
            return 1
        except MicroAuthAPIError as exc:
            report.fail(f"snapshot request failed: {exc}")
            return 1
        except MicroAuthError as exc:
            report.fail(f"snapshot response was unusable: {exc}")
            return 1
        try:
            snapshot = _parse_snapshot(data)
        except MicroAuthError as exc:
            report.fail(f"snapshot did not validate: {exc}")
            return 1
        _describe_snapshot(report, snapshot)

        if args.key:
            report.heading("API key")
            await _describe_key(report, client, snapshot, args.key, _parse_customer)
    finally:
        await client.aclose()

    redis_url = args.redis_url or os.environ.get("MICROAUTH_REDIS_URL")
    report.heading("Shared state")
    if redis_url:
        await _check_redis(report, redis_url)
    else:
        report.ok("no Redis configured; each worker enforces limits on its own")

    report.heading("Usage journal")
    _check_spool(report)

    out.write("\n")
    if report.failed:
        out.write("Some checks failed. Fix the items marked fail and run this again.\n")
        return 1
    out.write("Everything looks good. Your API is ready to serve keys.\n")
    return 0


def _describe_snapshot(report: _Report, snapshot: Snapshot) -> None:
    assert snapshot.generated_at is not None
    skew = (datetime.now(timezone.utc) - snapshot.generated_at).total_seconds()
    if snapshot.tenant_name:
        report.ok(f"connected to {snapshot.tenant_name}")
    report.ok(
        f"snapshot loaded: {len(snapshot.customers)} customer(s), "
        f"{len(snapshot.keys)} key(s)"
    )
    if abs(skew) > 30:
        report.warn(
            f"this machine's clock differs from MicroAuth by about {abs(skew):.0f}s; "
            "keep it synced with NTP so policy expiry is accurate"
        )
    statuses = ", ".join(str(code) for code in sorted(snapshot.billable_statuses))
    report.info(f"billable status codes: {statuses or 'none'}")
    allowance = snapshot.platform_allowance
    if allowance is not None:
        report.info(
            f"platform allowance: {allowance.used:,} of {allowance.limit:,} "
            f"requests used this month"
        )
        if allowance.hard_cap and allowance.remaining == 0:
            report.fail(
                "the monthly platform allowance is used up; requests are refused "
                "until it resets or you upgrade the plan"
            )
    if not snapshot.customers:
        report.warn(
            "no customers yet. Open your developer portal, sign up as a test "
            "customer and create a key to try a first request."
        )


async def _describe_key(
    report: _Report,
    client: APIClient,
    snapshot: Snapshot,
    api_key: str,
    parse_customer: Any,
) -> None:
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    record = snapshot.keys.get(key_hash)
    customer: CustomerState | None = None
    if record is not None:
        customer = snapshot.customers.get(record.customer_id)
    else:
        try:
            verified = await client.verify_key(key_hash)
        except MicroAuthError as exc:
            report.fail(f"could not verify the key: {exc}")
            return
        if verified.get("valid") is True and isinstance(verified.get("customer"), dict):
            customer = parse_customer(verified["customer"], "verify.customer")
    if customer is None:
        report.fail(
            "this key is not valid for this API. Check that it was created in "
            "this API's portal and has not been revoked."
        )
        return
    report.ok(f"key belongs to customer {customer.id}")
    effective = customer.effective
    if customer.status != "active":
        report.fail(f"customer status is {customer.status}; requests get 403")
        return
    report.info(f"plan source: {effective.source or 'default'}, billing: {effective.billing_model}")
    report.info(f"balance: {_money(customer.credit_balance_micro)}")
    if effective.billing_model != "none" and effective.price_per_request_micro > 0:
        report.info(f"price per billable request: {_money(effective.price_per_request_micro)}")
        if customer.credit_balance_micro < effective.price_per_request_micro:
            report.fail(
                "the balance cannot cover one billable request, so requests get 402. "
                "Add credit from the portal or grant a welcome credit."
            )
            return
    if effective.monthly_quota is not None:
        report.info(
            f"monthly quota: {customer.month_requests:,} of {effective.monthly_quota:,} used"
        )
        if customer.month_requests >= effective.monthly_quota:
            report.fail("the monthly quota is used up, so requests get 429")
            return
    if effective.rps:
        report.info(f"rate limit: {effective.rps} requests per second")
    report.ok("a request with this key would be allowed")


async def _check_redis(report: _Report, redis_url: str) -> None:
    try:
        import redis.asyncio as aioredis
    except ImportError:
        report.fail(
            "MICROAUTH_REDIS_URL is set but the redis package is missing. "
            "Install with: pip install 'microauth-fastapi[redis]'"
        )
        return
    client = aioredis.from_url(redis_url, socket_timeout=2.0, socket_connect_timeout=2.0)
    try:
        await client.ping()
        await client.eval("return 1", 0)
    except Exception as exc:  # noqa: BLE001
        report.fail(f"Redis is unreachable or refuses Lua scripts: {exc}")
    else:
        report.ok("Redis reachable; limits and usage are shared across workers")
    finally:
        await client.aclose()


def _check_spool(report: _Report) -> None:
    configured = os.environ.get("MICROAUTH_USAGE_SPOOL_PATH")
    directory = Path(configured).expanduser().parent if configured else Path(tempfile.gettempdir())
    try:
        directory.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=directory, prefix=".microauth-check-"):
            pass
    except OSError as exc:
        report.fail(f"cannot write the usage journal in {directory}: {exc}")
        return
    report.ok(f"usage journal directory is writable ({directory})")


def main(argv: list[str] | None = None, out: TextIO | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m microauth_fastapi",
        description="Tools for the MicroAuth FastAPI SDK.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser(
        "check",
        help="verify the secret key, snapshot, Redis and journal",
        description=(
            "Verify that this environment can run MicroAuth. Reads "
            "MICROAUTH_SECRET_KEY, MICROAUTH_BASE_URL and MICROAUTH_REDIS_URL."
        ),
    )
    check.add_argument("--key", help="a customer API key to evaluate")
    check.add_argument("--secret-key", help="your API's SDK secret key, mas_... (defaults to MICROAUTH_SECRET_KEY)")
    check.add_argument("--base-url", help="control plane URL (defaults to MICROAUTH_BASE_URL)")
    check.add_argument("--redis-url", help="Redis URL (defaults to MICROAUTH_REDIS_URL)")
    check.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds")
    args = parser.parse_args(argv)
    stream = out or sys.stdout
    if args.command == "check":
        return asyncio.run(_check(args, stream))
    return 2  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
