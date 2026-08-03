"""End-to-end integration test against a locally running MicroAuth API.

Prereqs (see tests/run.sh):
  * MicroAuth API running with the target tenant
  * tests/app.py served by uvicorn on $APP_URL
  * env: MICROAUTH_SECRET_KEY (tenant), TEST_API_KEY (a customer key),
    MICROAUTH_BASE_URL, APP_URL, optional EXPECT_RPS

Exit code 0 = all assertions passed.
"""

import asyncio
import hashlib
import os
import sys
import time

import httpx

APP = os.environ["APP_URL"].rstrip("/")
MA = os.environ["MICROAUTH_BASE_URL"].rstrip("/")
SECRET = os.environ["MICROAUTH_SECRET_KEY"]
API_KEY = os.environ["TEST_API_KEY"]
EXPECT_RPS = int(os.environ.get("EXPECT_RPS", "25"))

PASS = 0


def ok(name: str, cond: bool, extra: str = "") -> None:
    global PASS
    status = "PASS" if cond else "FAIL"
    print(f"  [{status}] {name}" + (f"  ({extra})" if extra else ""))
    if not cond:
        sys.exit(1)
    PASS += 1


async def month_requests(client: httpx.AsyncClient, customer_id: str) -> int:
    res = await client.get(f"{MA}/sdk/v1/snapshot", headers={"Authorization": f"Bearer {SECRET}"})
    res.raise_for_status()
    for c in res.json()["customers"]:
        if c["id"] == customer_id:
            return c["month_requests"]
    raise RuntimeError("customer not in snapshot")


async def main() -> None:
    async with httpx.AsyncClient(timeout=10) as c:
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
        customer_id = r.json()["customer"]

        # --- optional auth ---
        r = await c.get(f"{APP}/maybe")
        ok("optional: anonymous passes", r.status_code == 200 and r.json() == {"authenticated": False})
        r = await c.get(f"{APP}/maybe", headers={"X-API-Key": API_KEY})
        ok("optional: key recognised", r.json() == {"authenticated": True})

        # --- OpenAPI magic ---
        spec = (await c.get(f"{APP}/openapi.json")).json()
        schemes = spec.get("components", {}).get("securitySchemes", {})
        ok("OpenAPI documents the API key scheme",
           any(s.get("type") == "apiKey" and s.get("name") == "X-API-Key" for s in schemes.values()))
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
        ok("burst is rate limited", n429 > 0 and n200 <= EXPECT_RPS + 2, f"{n200}x200 {n429}x429 of {burst}")
        retry = next((r for r in results if r.status_code == 429), None)
        ok("429 carries Retry-After", retry is not None and "retry-after" in retry.headers)

        # --- billing: 200s billable, 404s not ---
        await asyncio.sleep(4)  # let the reporter flush the burst
        base = await month_requests(c, customer_id)

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
            delta = await month_requests(c, customer_id) - base
            if delta >= 5:
                break
        ok("exactly the 5 billable requests were reported", delta == 5, f"delta={delta}")

        # --- brand-new key resolves on demand (not in the cached snapshot) ---
        new_key = os.environ.get("FRESH_API_KEY")
        if new_key:
            r = await c.get(f"{APP}/hello", headers={"X-API-Key": new_key})
            ok("fresh key verified on demand", r.status_code == 200, r.text[:60])

    print(f"\nAll {PASS} assertions passed.")


asyncio.run(main())
