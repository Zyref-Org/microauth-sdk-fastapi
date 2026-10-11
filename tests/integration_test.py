"""End-to-end test against a running MicroAuth platform.

Serve tests/app.py with uvicorn, then run this file. It needs:

  MICROAUTH_BASE_URL    the platform, for example http://localhost:8300
  MICROAUTH_SECRET_KEY  the API's SDK secret, the same one the app uses
  TEST_API_KEY          a customer key with some credit
  APP_URL               where tests/app.py is served
  EXPECT_RPS            the key's rate limit (default 25)
  FRESH_API_KEY         optional, a key created after the app started

Exit code 0 means every assertion passed.
"""

import asyncio
import hashlib
import os
import sys
import time
from typing import Any

import httpx

APP = ""
MA = ""
SECRET = ""
API_KEY = ""
EXPECT_RPS = 25

PASS = 0


def ok(name: str, cond: bool, extra: str = "") -> None:
    global PASS
    status = "PASS" if cond else "FAIL"
    print(f"  [{status}] {name}" + (f"  ({extra})" if extra else ""))
    if not cond:
        sys.exit(1)
    PASS += 1


async def customer_of(client: httpx.AsyncClient, key: str) -> dict[str, Any]:
    """The key's customer as MicroAuth sees it right now."""

    res = await client.get(f"{MA}/sdk/v1/snapshot", headers={"Authorization": f"Bearer {SECRET}"})
    res.raise_for_status()
    snapshot = res.json()
    digest = hashlib.sha256(key.encode()).hexdigest()
    owner = next(k["customer_id"] for k in snapshot["keys"] if k["key_hash"] == digest)
    return next(c for c in snapshot["customers"] if c["id"] == owner)


async def settled_ledger(client: httpx.AsyncClient) -> dict[str, Any]:
    """Waits until the app has nothing queued and no new receipts arrive."""

    deadline = time.time() + 30
    previous = -1
    while True:
        ledger = (await client.get(f"{APP}/_ledger")).json()
        count = len(ledger["receipts"])
        if ledger["stats"]["queued_items"] == 0 and count == previous:
            return ledger
        if time.time() > deadline:
            return ledger
        previous = count
        await asyncio.sleep(2.5)


async def main() -> None:
    global APP, MA, SECRET, API_KEY, EXPECT_RPS
    APP = os.environ["APP_URL"].rstrip("/")
    MA = os.environ["MICROAUTH_BASE_URL"].rstrip("/")
    SECRET = os.environ["MICROAUTH_SECRET_KEY"]
    API_KEY = os.environ["TEST_API_KEY"]
    EXPECT_RPS = int(os.environ.get("EXPECT_RPS", "25"))

    async with httpx.AsyncClient(timeout=10) as c:
        start = await customer_of(c, API_KEY)
        customer_id = start["id"]

        # --- basics ---
        r = await c.get(f"{APP}/public")
        ok("public route needs no key", r.status_code == 200)

        r = await c.get(f"{APP}/hello")
        ok("missing key -> 401", r.status_code == 401)
        ok("401 sets WWW-Authenticate", "ApiKey" in r.headers.get("www-authenticate", ""))

        r = await c.get(f"{APP}/hello", headers={"X-API-Key": "map_definitely_not_real"})
        ok("invalid key -> 401", r.status_code == 401)

        r = await c.get(f"{APP}/hello", headers={"X-API-Key": API_KEY})
        ok("valid key -> 200", r.status_code == 200, r.text[:80])
        ok("the key resolves to its customer", r.json()["customer"] == customer_id)

        # --- brand-new key resolves on demand (not in the cached snapshot) ---
        new_key = os.environ.get("FRESH_API_KEY")
        if new_key:
            r = await c.get(f"{APP}/hello", headers={"X-API-Key": new_key})
            ok("fresh key verified on demand", r.status_code == 200, r.text[:60])

        # --- optional auth ---
        r = await c.get(f"{APP}/maybe")
        ok(
            "optional: anonymous passes",
            r.status_code == 200 and r.json() == {"authenticated": False},
        )
        r = await c.get(f"{APP}/maybe", headers={"X-API-Key": API_KEY})
        ok("optional: key recognised", r.json() == {"authenticated": True})

        # --- OpenAPI magic ---
        spec = (await c.get(f"{APP}/openapi.json")).json()
        schemes = spec.get("components", {}).get("securitySchemes", {})
        ok(
            "OpenAPI documents the API key scheme",
            any(
                s.get("type") == "apiKey" and s.get("name") == "X-API-Key" for s in schemes.values()
            ),
        )
        hello_sec = spec["paths"]["/hello"]["get"].get("security", [])
        ok("route carries the security requirement", len(hello_sec) > 0)
        ok("public route carries none", not spec["paths"]["/public"]["get"].get("security"))

        # --- rate limiting: burst 2x the limit within one bucket ---
        burst = EXPECT_RPS * 2
        results = await asyncio.gather(
            *(c.get(f"{APP}/hello", headers={"X-API-Key": API_KEY}) for _ in range(burst))
        )
        codes = [r.status_code for r in results]
        n200, n429 = codes.count(200), codes.count(429)
        ok(
            "burst is rate limited",
            n429 > 0 and n200 <= EXPECT_RPS + 2,
            f"{n200}x200 {n429}x429 of {burst}",
        )
        retry = next((r for r in results if r.status_code == 429), None)
        ok("429 carries Retry-After", retry is not None and "retry-after" in retry.headers)

        # --- usage: every status counts, only configured statuses charge ---
        await settled_ledger(c)
        base = (await customer_of(c, API_KEY))["month_requests"]

        await asyncio.sleep(1.1)  # fresh rate limit window
        for _ in range(5):
            r = await c.get(f"{APP}/hello", headers={"X-API-Key": API_KEY})
            assert r.status_code == 200, r.text
        for _ in range(3):
            r = await c.get(f"{APP}/notfound", headers={"X-API-Key": API_KEY})
            assert r.status_code == 404, r.text

        deadline = time.time() + 15
        delta = 0
        while time.time() < deadline:
            await asyncio.sleep(1.5)
            delta = (await customer_of(c, API_KEY))["month_requests"] - base
            if delta >= 8:
                break
        ok("all 8 authenticated requests were reported", delta == 8, f"delta={delta}")

        # --- receipts: what MicroAuth charged reconciles with the balance ---
        ledger = await settled_ledger(c)
        stats = ledger["stats"]
        delivered = ledger["receipts"]
        unique = {r["idempotency_key"]: r for r in delivered}
        mine = [r for r in unique.values() if r["customer_id"] == customer_id]
        ok(
            "no usage was rejected",
            stats["rejected_items"] == 0 and not ledger["rejections"],
            f"{len(ledger['rejections'])} rejected",
        )
        ok("nothing is left in the queue", stats["queued_items"] == 0)
        ok(
            "every receipt names the customer, the charge and the time",
            bool(delivered)
            and all(
                r["customer_id"] and r["charged_micro"] is not None and r["recorded_at"]
                for r in delivered
            ),
        )
        mismatched = [r for r in delivered if r["charge_matches"] is not True]
        ok(
            "every charge matches the price the SDK enforced",
            not mismatched,
            f"{len(mismatched)} of {len(delivered)} differ",
        )
        ok(
            "usage_stats agrees with the receipts",
            stats["charge_mismatches"] == 0
            and stats["charged_micro"] == sum(r["charged_micro"] for r in delivered)
            and stats["delivered_requests"] == sum(r["count"] for r in delivered),
            f"charged={stats['charged_micro']} requests={stats['delivered_requests']}",
        )
        end = await customer_of(c, API_KEY)
        charged = sum(r["charged_micro"] for r in mine)
        spent = start["credit_balance_micro"] - end["credit_balance_micro"]
        ok(
            "the balance moved by exactly what the receipts charged",
            spent == charged and charged > 0,
            f"spent={spent} charged={charged}",
        )
        recorded = end["month_requests"] - start["month_requests"]
        ok(
            "every recorded request has a receipt",
            recorded == sum(r["count"] for r in mine),
            f"recorded={recorded}",
        )

    print(f"\nAll {PASS} assertions passed.")


if __name__ == "__main__":
    asyncio.run(main())
