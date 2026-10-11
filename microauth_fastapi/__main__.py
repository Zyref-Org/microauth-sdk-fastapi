"""Command line tools for the MicroAuth FastAPI SDK.

``python -m microauth_fastapi check`` confirms an integration end to end:
it reads the same environment variables (or ``.env`` file) as ``MicroAuth()``
and reports what the SDK would see at startup, without serving traffic or
reporting usage. Pass ``--key`` with one of your customers' API keys to see
exactly how a request with that key would be treated.

``python -m microauth_fastapi usage`` shows the usage still queued for
delivery and every item MicroAuth refused, from the journal and from Redis.
It only reads; nothing is delivered or deleted.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

from ._clock import ServerClock
from ._env import from_dotenv, getenv
from ._version import __version__
from .client import APIClient
from .exceptions import (
    MicroAuthAPIError,
    MicroAuthAuthorizationError,
    MicroAuthConfigurationError,
    MicroAuthError,
)
from .journal import JournalReport, inspect_directory, read_api_metadata
from .models import CustomerState, Snapshot

DEFAULT_BASE_URL = "https://api.microauth.com"
DASHBOARD_URL = "https://microauth.com/app"
TROUBLESHOOTING_URL = "https://microauth.com/docs/troubleshooting#sdk-not-connecting"
USAGE_DOCS_URL = "https://microauth.com/docs/fastapi#receipts"


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


def _when(value: str | None, unknown: str = "unknown time") -> str:
    """An ISO timestamp from a report, as people read it."""

    if not value:
        return unknown
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _settings(args: argparse.Namespace) -> tuple[str, str]:
    secret = (args.secret_key or getenv("MICROAUTH_SECRET_KEY") or "").strip()
    base_url = (args.base_url or getenv("MICROAUTH_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
    return secret, base_url


async def _fetch_snapshot(
    secret: str,
    base_url: str,
    timeout: float,
) -> tuple[Snapshot, APIClient]:
    from .sdk import _parse_snapshot

    clock = ServerClock()
    client = APIClient(base_url, secret, timeout, clock=clock)
    try:
        data = await client.snapshot()
        return _parse_snapshot(data, now=clock.time()), client
    except BaseException:
        await client.aclose()
        raise


# ------------------------------------------------------------------- check


async def _check(args: argparse.Namespace, out: TextIO) -> int:
    from .sdk import _SECRET_PATTERN, _parse_customer

    report = _Report(out)
    out.write(f"MicroAuth FastAPI SDK {__version__}\n")

    secret, base_url = _settings(args)
    report.heading("Configuration")
    if not _SECRET_PATTERN.fullmatch(secret):
        report.fail(
            "MICROAUTH_SECRET_KEY is missing or is not an SDK secret (mas_...). "
            f"Copy it from your API's Connect tab at {DASHBOARD_URL}, then "
            "export it or put it in a .env file in this directory."
        )
        return 1
    secret_source = (
        " (from .env)" if not args.secret_key and from_dotenv("MICROAUTH_SECRET_KEY") else ""
    )
    report.ok(f"SDK secret mas_...{secret[-4:]}{secret_source}")
    report.ok(f"MicroAuth API {base_url}")

    report.heading("MicroAuth")
    try:
        snapshot, client = await _fetch_snapshot(secret, base_url, args.timeout)
    except MicroAuthAuthorizationError as exc:
        reason = f" ({exc.detail})" if exc.detail else ""
        report.fail(
            f"MicroAuth rejected this secret{reason}. It may have been rotated; "
            f"copy the current one from your API's Connect tab at {DASHBOARD_URL}"
        )
        return 1
    except MicroAuthAPIError as exc:
        report.fail(f"snapshot request failed: {exc}")
        return 1
    except MicroAuthError as exc:
        report.fail(f"snapshot was unusable: {exc}")
        return 1
    try:
        _describe_snapshot(report, snapshot, client.clock)
        if args.key:
            report.heading("API key")
            await _describe_key(report, client, snapshot, args.key, _parse_customer)
    finally:
        await client.aclose()

    redis_url = args.redis_url or getenv("MICROAUTH_REDIS_URL")
    report.heading("Shared state")
    if redis_url:
        await _check_redis(report, redis_url)
    else:
        report.ok("no Redis configured; each worker enforces limits on its own")

    report.heading("Usage journal")
    _check_journal(report, args.journal_dir, base_url, snapshot.tenant_id)

    out.write("\n")
    if report.failed:
        out.write("Some checks failed. Fix the items marked fail and run this again.\n")
        return 1
    out.write("Everything looks good. Your API is ready to serve keys.\n")
    return 0


def _describe_snapshot(report: _Report, snapshot: Snapshot, clock: ServerClock) -> None:
    name = snapshot.tenant_name or "your API"
    report.ok(f"connected to {name} ({snapshot.tenant_id})")
    report.ok(
        f"snapshot loaded: {len(snapshot.customers)} customer(s), {len(snapshot.keys)} key(s)"
    )
    offset = clock.offset
    if abs(offset) >= 2.0:
        report.warn(
            f"this machine's clock is {abs(offset):.1f}s "
            f"{'behind' if offset > 0 else 'ahead of'} MicroAuth's. The SDK "
            "uses MicroAuth's time for usage and policy expiry, but keep NTP "
            "running here"
        )
    else:
        report.ok(f"clock agrees with MicroAuth within {max(abs(offset), 0.001):.3f}s")
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
    if customer.status == "pending":
        report.fail(
            "the customer is waiting for approval, so requests get 403. "
            "Approve them on the Customers page."
        )
        return
    if customer.status != "active":
        report.fail(f"customer status is {customer.status}, so requests get 403")
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


def _check_journal(
    report: _Report,
    configured: str | None,
    base_url: str,
    tenant_id: str,
) -> None:
    from .sdk import _is_serverless_environment, _stable_scope, resolve_journal_dir

    try:
        base = resolve_journal_dir(configured)
    except MicroAuthConfigurationError as exc:
        report.fail(str(exc))
        return
    directory = base / _stable_scope(base_url, tenant_id)
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.NamedTemporaryFile(dir=directory, prefix=".microauth-check-"):
            pass
    except OSError as exc:
        report.fail(f"cannot write the usage journal in {directory}: {exc}")
        return
    report.ok(f"journal directory is writable ({directory})")
    temporary = Path(tempfile.gettempdir()).resolve()
    if not _is_serverless_environment() and temporary in directory.resolve().parents:
        chosen = configured or os.environ.get("MICROAUTH_JOURNAL_DIR")
        advice = (
            "Move it to a persistent directory"
            if chosen
            else "Set MICROAUTH_JOURNAL_DIR to a persistent directory"
        )
        report.warn(
            f"the journal is in the temp directory, which some hosts clear on reboot. {advice}"
        )
    journal = inspect_directory(directory)
    if journal.queued_items:
        report.info(
            f"{journal.queued_items:,} item(s) covering {journal.queued_requests:,} "
            "request(s) are queued for delivery"
        )
    if journal.dead_letters:
        report.warn(
            f"MicroAuth refused {len(journal.dead_letters):,} usage item(s) from "
            "this host. Run `python -m microauth_fastapi usage` to see why"
        )
    if journal.corrupt_copies:
        report.warn(
            f"{len(journal.corrupt_copies)} damaged journal file(s) were set aside in {directory}"
        )


# ------------------------------------------------------------------- usage


async def _usage(args: argparse.Namespace, out: TextIO) -> int:
    from .sdk import _stable_scope, resolve_journal_dir

    secret, base_url = _settings(args)
    try:
        base = resolve_journal_dir(args.journal_dir)
    except MicroAuthConfigurationError as exc:
        out.write(f"{exc}\n")
        return 1

    api: dict[str, Any] | None = None
    lookup_error: str | None = None
    if secret:
        try:
            snapshot, client = await _fetch_snapshot(secret, base_url, args.timeout)
        except MicroAuthError as exc:
            lookup_error = str(exc)
        else:
            await client.aclose()
            api = {
                "tenant_id": snapshot.tenant_id,
                "tenant_name": snapshot.tenant_name,
                "base_url": base_url,
                "scope": _stable_scope(base_url, snapshot.tenant_id),
            }

    if api is not None:
        directories = [base / api["scope"]]
    else:
        # Without MicroAuth, every labeled API directory on this host is shown.
        directories = (
            sorted(path for path in base.iterdir() if path.is_dir()) if base.is_dir() else []
        )

    sections: list[dict[str, Any]] = []
    for directory in directories:
        metadata = read_api_metadata(directory)
        journal = inspect_directory(directory) if directory.is_dir() else None
        section: dict[str, Any] = {
            "tenant_id": (api or metadata).get("tenant_id"),
            "tenant_name": (api or metadata).get("tenant_name"),
            "journal_dir": str(directory),
            "journal": _journal_json(journal, args.limit),
            "redis": None,
        }
        sections.append(section)

    redis_url = args.redis_url or getenv("MICROAUTH_REDIS_URL")
    redis_note: str | None = None
    if redis_url and api is not None and sections:
        try:
            sections[0]["redis"] = await _redis_usage(redis_url, api["scope"], args.limit)
        except Exception as exc:  # noqa: BLE001 - report, don't crash
            redis_note = f"Redis could not be read: {exc}"
    elif redis_url:
        redis_note = "Redis was not read because the API could not be identified"

    if args.json:
        json.dump(
            {
                "base_url": base_url,
                "journal_base": str(base),
                "lookup_error": lookup_error,
                "redis_note": redis_note,
                "apis": sections,
            },
            out,
            indent=2,
            sort_keys=True,
            default=str,
        )
        out.write("\n")
        return 0

    out.write(f"MicroAuth FastAPI SDK {__version__}\n")
    if lookup_error is not None:
        out.write(
            f"\nMicroAuth could not be reached ({lookup_error}), so every API "
            f"journal in {base} is shown.\n"
        )
    elif api is None:
        out.write(f"\nNo SDK secret was given, so every API journal in {base} is shown.\n")
    if not sections:
        out.write(f"\nNo usage journals found in {base}.\n")
    for section in sections:
        _print_section(out, section)
    if redis_note:
        out.write(f"\n{redis_note}\n")
    out.write(f"\nWhat these mean: {USAGE_DOCS_URL}\n")
    return 0


def _journal_json(journal: JournalReport | None, limit: int) -> dict[str, Any] | None:
    if journal is None:
        return None
    return {
        "queued_items": journal.queued_items,
        "queued_requests": journal.queued_requests,
        "oldest_queued_at": _iso(journal.oldest_queued_at),
        "files": [
            {
                "name": file.name,
                "items": file.items,
                "requests": file.requests,
                "oldest_queued_at": _iso(file.oldest_queued_at),
                "modified_at": _iso(file.modified_at),
                "damaged_records": file.damaged_records,
                "torn_tail": file.torn_tail,
            }
            for file in journal.files
        ],
        "dead_letter_count": len(journal.dead_letters),
        "dead_letters": [_dead_letter_json(record) for record in journal.dead_letters[-limit:]],
        "damaged_dead_letters": journal.damaged_dead_letters,
        "corrupt_copies": journal.corrupt_copies,
    }


async def _redis_usage(redis_url: str, scope: str, limit: int) -> dict[str, Any]:
    import redis.asyncio as aioredis

    from .usage_store import RedisUsageStore

    client = aioredis.from_url(redis_url, socket_timeout=3.0, socket_connect_timeout=3.0)
    try:
        store = RedisUsageStore(client, scope, max_items=1)
        letters = await store.dead_letters(limit)
        return {
            "queued_items": await store.pending_count(),
            "dead_letter_count": await store.dead_letter_count(),
            "dead_letters": [
                _dead_letter_json({"idempotency_key": event_id, **record})
                for event_id, record in letters
            ],
        }
    finally:
        await client.aclose()


def _dead_letter_json(record: dict[str, Any]) -> dict[str, Any]:
    event = record.get("event")
    item = event.get("item") if isinstance(event, dict) else None
    item = item if isinstance(item, dict) else {}
    return {
        "idempotency_key": record.get("idempotency_key"),
        "rejected_at": record.get("rejected_at"),
        "http_status": record.get("http_status"),
        "detail": record.get("detail"),
        "api_key_id": item.get("api_key_id"),
        "usage_policy_id": item.get("usage_policy_id"),
        "status_code": item.get("status_code"),
        "count": item.get("count"),
        "period_start": item.get("period_start"),
        "unit_charge_micro": item.get("unit_charge_micro"),
    }


def _print_section(out: TextIO, section: dict[str, Any]) -> None:
    name = section.get("tenant_name") or "Unlabeled API"
    tenant = section.get("tenant_id")
    out.write(f"\n{name}{f' ({tenant})' if tenant else ''}\n")
    out.write(f"  journal: {section['journal_dir']}\n")
    journal = section.get("journal")
    if journal is None:
        out.write("  nothing has been journaled on this host yet\n")
    else:
        _print_queue(out, "journal", journal)
    redis = section.get("redis")
    if redis is not None:
        out.write(f"  Redis queue: {redis['queued_items']:,} item(s) waiting\n")
        _print_dead_letters(out, "Redis", redis["dead_letter_count"], redis["dead_letters"])


def _print_queue(out: TextIO, label: str, journal: dict[str, Any]) -> None:
    if journal["queued_items"]:
        out.write(
            f"  queued in the {label}: {journal['queued_items']:,} item(s) covering "
            f"{journal['queued_requests']:,} request(s), oldest queued "
            f"{_when(journal['oldest_queued_at'])}\n"
        )
        for file in journal["files"]:
            if file["items"]:
                out.write(
                    f"    {file['name']}: {file['items']:,} item(s), last written "
                    f"{_when(file['modified_at'])}\n"
                )
    else:
        out.write(f"  nothing queued in the {label}\n")
    damaged = sum(file["damaged_records"] for file in journal["files"])
    if damaged:
        out.write(f"  {damaged} damaged record(s) were skipped while reading\n")
    out.writelines(f"  set aside after damage: {name}\n" for name in journal["corrupt_copies"])
    _print_dead_letters(out, label, journal["dead_letter_count"], journal["dead_letters"])


def _print_dead_letters(
    out: TextIO,
    label: str,
    total: int,
    letters: list[dict[str, Any]],
) -> None:
    if not total:
        out.write(f"  no refused usage in the {label}\n")
        return
    out.write(f"  refused by MicroAuth ({label}): {total:,} item(s)")
    out.write(f", newest {len(letters)} shown\n" if len(letters) < total else "\n")
    for letter in letters:
        status = f"HTTP {letter['http_status']}" if letter.get("http_status") else "not sent"
        out.write(
            f"    {_when(letter.get('rejected_at'))}  {status}  "
            f"{letter.get('count') or '?'} request(s) with status "
            f"{letter.get('status_code') or '?'} in the hour of "
            f"{_when(letter.get('period_start'), '?')}\n"
            f"      {letter.get('detail') or 'no reason given'}\n"
            f"      item {letter.get('idempotency_key')}, key {letter.get('api_key_id')}\n"
        )


def _iso(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")


# -------------------------------------------------------------------- main


def _add_connection_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--secret-key",
        help="your API's SDK secret, mas_... (defaults to MICROAUTH_SECRET_KEY)",
    )
    parser.add_argument("--base-url", help="MicroAuth API URL (defaults to MICROAUTH_BASE_URL)")
    parser.add_argument("--redis-url", help="Redis URL (defaults to MICROAUTH_REDIS_URL)")
    parser.add_argument(
        "--journal-dir",
        help="usage journal directory (defaults to MICROAUTH_JOURNAL_DIR)",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds")


def main(argv: list[str] | None = None, out: TextIO | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m microauth_fastapi",
        description="Tools for the MicroAuth FastAPI SDK.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser(
        "check",
        help="verify the secret, snapshot, clock, Redis and journal",
        description=(
            "Verify that this environment can run MicroAuth. Reads "
            "MICROAUTH_SECRET_KEY, MICROAUTH_BASE_URL, MICROAUTH_REDIS_URL and "
            "MICROAUTH_JOURNAL_DIR from the environment, or from a .env file "
            "in this directory."
        ),
    )
    check.add_argument("--key", help="a customer API key to evaluate")
    _add_connection_options(check)
    usage = commands.add_parser(
        "usage",
        help="show queued usage and usage MicroAuth refused",
        description=(
            "Show the usage this host still has to deliver and every item "
            "MicroAuth refused, from the journal and Redis. Read only."
        ),
    )
    usage.add_argument("--json", action="store_true", help="print JSON instead of text")
    usage.add_argument(
        "--limit",
        type=int,
        default=50,
        help="how many refused items to list per queue (default 50)",
    )
    _add_connection_options(usage)
    args = parser.parse_args(argv)
    stream = out or sys.stdout
    if args.command == "check":
        code = asyncio.run(_check(args, stream))
        if code:
            stream.write(f"Help: {TROUBLESHOOTING_URL}\n")
        return code
    if args.command == "usage":
        if args.limit < 1:
            parser.error("--limit must be at least 1")
        return asyncio.run(_usage(args, stream))
    return 2  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
