# MicroAuth SDK for FastAPI

API key authentication, per-customer rate limiting and metered billing for
your FastAPI API — powered by your [MicroAuth](https://microauth.com) tenant,
in one dependency.

```python
from fastapi import FastAPI, Security
from microauth_fastapi import MicroAuth, Customer

app = FastAPI()
auth = MicroAuth(app)  # tenant secret from MICROAUTH_SECRET_KEY

@app.get("/forecast")
async def forecast(customer: Customer = Security(auth)):
    return {"hello": customer.id}
```

That's the whole integration. Your customers sign up on your MicroAuth
developer portal, create API keys, pick a plan or top up credits — and every
request to `/forecast` is now authenticated, rate-limited and billed.

## What it does

- **API key auth** via the `X-API-Key` header (configurable), including the
  security scheme in your OpenAPI docs — the Swagger "Authorize" button just
  works.
- **Suspension, balance and quota enforcement** — suspended customers get
  `403`, customers who ran out of prepaid credit get `402`, customers over
  their monthly quota get `429`.
- **Per-customer rate limiting** at each customer's effective RPS (custom
  override → plan → pay-as-you-go default), scoped to each API credential,
  with `429` and `Retry-After`.
- **Atomic request reservations** for customer quota, possible prepaid spend,
  and the platform monthly allowance before your endpoint starts. Redis
  coordinates the complete decision across workers.
- **Complete usage reporting** for every completed authenticated request,
  grouped by API key and exact response status. Only configured billable
  statuses consume prepaid credit.

## Designed for the hot path

The SDK never calls MicroAuth while serving a request:

- A **snapshot** of your customers, keys and limits is cached in memory and
  refreshed in the background (default every 30s).
- Keys not in the snapshot yet (created seconds ago) are resolved once via
  a **single-flight** on-demand lookup; invalid keys are negatively cached
  so a flood of bad keys can't reach MicroAuth.
- Usage is journaled to SQLite as each request completes, then sent in
  background batches (default every 15s). Every item is immutable and keeps
  one idempotency key across transport retries, requeues, concurrent workers,
  and process restarts.
- Authentication itself is a SHA-256 and a couple of dict lookups.

If MicroAuth is briefly unreachable, your API keeps serving with the last
known data (`fail_open=True`, the default), but never forever. Stale data has
an absolute `max_stale_snapshot_age` limit. Set `fail_open=False` to return
`503` at the earlier `max_snapshot_age` threshold. An expired usage policy is
always refreshed before another request is authorized; if that refresh fails,
the SDK returns `503` rather than creating usage under stale billing terms.

## Multiple workers? Add Redis

In-memory request limits are exact within one process. With 4 uvicorn workers,
each process has independent RPS, quota, balance, and platform reservation
state. Point the SDK at Redis for one atomic shared reservation across every
worker and machine:

```python
auth = MicroAuth(app, redis_url="redis://localhost:6379/0")
```

```bash
pip install 'microauth-fastapi[redis]'
```

RPS uses a fixed one-second window in both backends. Its key includes both the
customer and credential, so traffic on one key does not throttle another key
owned by the same customer. RPS fails open briefly if Redis is down. Quota,
potential spend, and platform reservations fail closed because serving
without an atomic decision could oversubscribe a hard limit.

## Optional authentication

For endpoints that serve both anonymous and authenticated traffic:

```python
@app.get("/status")
async def status(customer: Customer | None = Security(auth.optional)):
    return {"authenticated": customer is not None}
```

## Settings

Everything has a sensible default; override only what you need.

| Setting | Default | What it does |
| --- | --- | --- |
| `secret_key` | `$MICROAUTH_SECRET_KEY` | Tenant secret key (`mas_...`) |
| `base_url` | `https://api.microauth.com` | MicroAuth API (`$MICROAUTH_BASE_URL`) |
| `header_name` | `X-API-Key` | Header customers send their key in |
| `redis_url` | `$MICROAUTH_REDIS_URL` | Enable exact cross-worker rate limiting |
| `sync_interval` | `30` | Seconds between snapshot refreshes |
| `report_interval` | `15` | Seconds between usage report flushes |
| `max_snapshot_age` | `300` | Fail-closed staleness threshold |
| `max_stale_snapshot_age` | `3 × max_snapshot_age` | Absolute stale-data ceiling |
| `fail_open` | `True` | Serve stale data only up to the absolute ceiling |
| `enforce_balance` | `True` | `402` when prepaid credit is exhausted |
| `enforce_quota` | `True` | `429` when the monthly quota is used up |
| `enforce_rps` | `True` | Per-customer RPS limiting |
| `enforce_platform_allowance` | `True` | Enforce the platform monthly hard cap |
| `verify_negative_ttl` | `30` | Seconds an invalid key is cached |
| `timeout` | `5` | HTTP timeout for MicroAuth calls |
| `usage_spool_path` | Tenant-specific temp file | SQLite journal for completed usage |
| `persistence_namespace` | Snapshot tenant ID or secret fingerprint | Stable Redis and journal namespace |
| `persist_usage` | `True` | Keep stable IDs across process restarts |
| `max_usage_queue` | `10000` | Bounded journaled usage item count |
| `shutdown_timeout` | `10` | Maximum seconds for final usage drain |
| `http_client` | `None` | Optional externally owned async HTTP client |
| `redis_client` | `None` | Optional externally owned async Redis client |

## Error responses

| Status | When |
| --- | --- |
| `401` | Missing or invalid API key |
| `402` | Prepaid balance exhausted |
| `403` | Customer suspended |
| `429` | RPS, customer quota, or platform monthly hard cap exceeded |
| `503` | Snapshot too stale, shared hard-cap backend down, or usage queue full |

All request denials subclass `microauth_fastapi.AuthDenied` (itself a
FastAPI `HTTPException`), so you can add your own exception handler to
reshape response bodies. Configuration, snapshot validation, API transport,
usage acknowledgement, spool and shutdown-drain failures also have exported
typed exceptions.

## Consistency notes

- Redis provides one atomic shared decision for quota, possible spend, and
  the platform hard cap. Without Redis, each process enforces independently.
- Every request reserves customer and platform capacity before the endpoint
  starts. Those reservations remain consumed for every final status because
  the control plane counts every request. A nonbillable result releases only
  its monetary reservation.
- Completed usage is written to SQLite before it enters the delivery queue.
  Put `usage_spool_path` on a durable volume when host replacement must also
  be survived.
- A stable tenant identifier from the snapshot is used for persistence when
  available. Set `persistence_namespace` or an explicit `usage_spool_path`
  when the control plane does not expose one and secret rotation must retain
  the same journal.
- Graceful shutdown drains the queue within `shutdown_timeout`. If delivery
  cannot complete, shutdown fails with `UsageDrainError`; persisted items are
  retained for the next process.
- Suspensions and key revocations propagate within one `sync_interval`.

## SDK API contract

The SDK expects `GET /sdk/v1/snapshot` to return this shape:

```json
{
  "generated_at": "2026-08-04T00:15:00Z",
  "billable_status_codes": [200, 201, 207],
  "platform_monthly_limit": 1000000,
  "platform_monthly_used": 125000,
  "platform_monthly_remaining": 875000,
  "platform_period_end": "2026-09-01T00:00:00Z",
  "platform_hard_cap": true,
  "customers": [
    {
      "id": "cus_123",
      "status": "active",
      "credit_balance_micro": 25000000,
      "month_requests": 1250,
      "effective": {
        "rps": 25,
        "price_per_request_micro": 1000,
        "monthly_quota": 100000,
        "billing_model": "plan",
        "source": "plan"
      }
    }
  ],
  "keys": [
    {
      "id": "key_123",
      "customer_id": "cus_123",
      "key_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ]
}
```

`generated_at` and `platform_period_end` must be offset-aware ISO 8601.
`platform_monthly_remaining` must equal
`max(0, platform_monthly_limit - platform_monthly_used)`. Counts and
micro-unit amounts must be JSON integers in the inclusive range
`0..9007199254740991`, except a credit balance may be negative down to
`-9007199254740991`. Status codes must be integers from `100` through `599`.

The SDK sends `POST /sdk/v1/usage` with up to 1000 items:

```json
{
  "items": [
    {
      "idempotency_key": "bb02a6a7-10f4-4ab7-bf9c-8936770b67b7",
      "api_key_id": "11111111-1111-4111-8111-111111111111",
      "status_code": 207,
      "count": 42,
      "period_start": "2026-08-04T00:00:00Z"
    }
  ]
}
```

The API must return exactly one result per submitted idempotency key:

```json
{
  "results": [
    {
      "idempotency_key": "bb02a6a7-10f4-4ab7-bf9c-8936770b67b7",
      "status": "accepted"
    }
  ]
}
```

Successful statuses are `accepted` and `duplicate`. The reporter also handles
a per-item `rejected` status with an optional string `detail`. The current Go
API returns terminal item failures as an HTTP error, so the SDK bisects a
failed batch to isolate and dead-letter only the terminal item. Network
failures, `429`, and `5xx` responses retain the original payload for retry.
Missing, repeated, unknown, or unsupported results are treated as transient
acknowledgement failures.

## Example app

See [`examples/weather_api.py`](examples/weather_api.py):

```bash
MICROAUTH_SECRET_KEY=mas_... uvicorn examples.weather_api:app --reload
```
