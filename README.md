# MicroAuth SDK for FastAPI

API key authentication, per-customer rate limiting and metered billing for
your FastAPI API, powered by [MicroAuth](https://microauth.com), in one
dependency.

```bash
pip install microauth-fastapi
```

```python
from fastapi import FastAPI, Security
from microauth_fastapi import MicroAuth, Customer

app = FastAPI()
auth = MicroAuth(app)  # reads MICROAUTH_SECRET_KEY

@app.get("/forecast")
async def forecast(customer: Customer = Security(auth)):
    return {"hello": customer.id}
```

```bash
# .env, next to your app
MICROAUTH_SECRET_KEY=mas_...
```

That's the whole integration. The SDK secret key is on your API's Overview
page in the [MicroAuth dashboard](https://app.microauth.com). Settings come
from the environment, and any `MICROAUTH_*` value that is not set there is
read from a `.env` file in the working directory.

Your customers sign up on your developer portal, create API keys, and pick a
plan or top up credits. Every request to `/forecast` is then authenticated,
rate-limited and billed.

## Check your setup

Before you deploy, run the built-in check from the same directory and
environment your app uses:

```bash
python -m microauth_fastapi check
```

It confirms the secret works, loads a snapshot, pings Redis when
`MICROAUTH_REDIS_URL` is set, and makes sure the usage journal directory is
writable. Add `--key` with one of your customers' API keys to see exactly how
a request with that key would be treated, and why:

```text
$ python -m microauth_fastapi check --key map_...
API key
  ok    key belongs to customer 2b7c1f8e-...
        balance: $0
        price per billable request: $0.001
  fail  the balance cannot cover one billable request, so requests get 402.
```

The check also registers your SDK with MicroAuth, so the dashboard's setup
checklist turns green as soon as it succeeds. Every flag is in the
[SDK reference](https://docs.microauth.com/sdk/reference#check-command), and
[troubleshooting](https://docs.microauth.com/troubleshooting#sdk-not-connecting)
covers what to do when a check fails.

## What it does

- **API key auth** via the `X-API-Key` header (configurable), including the
  security scheme in your OpenAPI docs, so the Swagger "Authorize" button
  just works.
- **Suspension, balance and quota enforcement.** Suspended customers get
  `403`, customers who ran out of prepaid credit get `402`, and customers over
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

- A **snapshot** of your customers, keys and limits is cached in memory and
  refreshed in the background (default every 30s). With Redis, validated
  snapshots are shared across instances and one distributed refresh lock
  prevents autoscaling cold starts from stampeding the control plane.
- Keys not in the snapshot yet (created seconds ago) are resolved once via
  a **single-flight** on-demand lookup; invalid keys are negatively cached
  so a flood of bad keys can't reach MicroAuth.
- Usage is durably journaled as each request completes: to a Redis-backed
  shared queue when Redis is configured, otherwise to a per-process
  append-only journal file (one fsynced line per request, group-committed
  across concurrent requests). Requests sharing an API key, policy, status
  and hour merge into one counted item (up to 10,000). Deliveries are
  batched: a flush happens when 500 requests accumulate or `report_interval`
  (default 5s) elapses since the last flush, whichever comes first, so a
  high-concurrency burst becomes one usage call with one counted item. Every
  item is immutable once delivery starts and keeps one idempotency key
  across transport retries, requeues, concurrent workers, and process
  restarts.
- Authentication itself is a SHA-256 and a couple of dict lookups.

Long-lived processes report usage in background batches and do not call
MicroAuth on the normal authentication hot path. On Vercel and AWS Lambda, the
SDK journals usage before the final response frame, sends that frame, and then
drains the event while the serverless invocation remains active. Set
`flush_on_response` explicitly to override environment detection.

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
worker and machine. The same Redis connection also shares snapshots and
coordinates refreshes:

```python
auth = MicroAuth(app, redis_url="redis://localhost:6379/0")
```

```bash
pip install 'microauth-fastapi[redis]'
```

RPS uses a fixed one-second window in both backends. Its key includes both the
customer and credential, so traffic on one key does not throttle another key
owned by the same customer. The RPS check rides inside the same atomic
reservation script as quota, spend, and platform decisions, so the entire
admission decision costs one Redis round trip per request and a rate-limited
request consumes no quota or balance. Like those decisions, it fails closed
(503) if Redis is down, because serving without an atomic decision could
oversubscribe a hard limit.

With Redis configured (and `persist_usage=True`), completed usage also enters
a **durable shared queue**: each event is enqueued before the final response
body is released and delivered under a per-worker lease. If a worker dies,
including serverless instance replacement, its leases expire and any other
worker sharing the queue recovers and delivers its events exactly once from
the API's perspective (idempotency keys are preserved). Durability is bounded
by your Redis deployment's persistence: managed offerings such as Upstash
persist by default; self-hosted Redis should enable AOF.

Connections are bounded. With `redis_url`, the SDK builds a blocking pool of
at most `redis_max_connections` (default 64) per worker, with one-second
socket timeouts. Under a burst, requests wait up to a second for a free
connection instead of opening new ones, so autoscaling cannot exhaust a
managed plan's connection cap. Size it so instances × pool stays under your
plan's limit:

```python
auth = MicroAuth(app, redis_url=redis_url, redis_max_connections=10)
```

For full control, pass your own client with `redis_client=`. A passed client
is externally owned: the SDK uses it but never closes it. The
[FastAPI guide](https://docs.microauth.com/guides/fastapi-sdk) has the full
sizing discussion and the warning signs to watch for in logs.

## Serverless runtimes

On Vercel and AWS Lambda, `flush_on_response` defaults to `True`. This fixes the
case where the report timer is frozen after a low-traffic request and only runs
when the next invocation arrives. The completed event is journaled before the
final body is released; after that frame is sent, the batching rule is
evaluated while the invocation is still active. A due batch (500 events, or
`report_interval` since the last flush) is delivered, and anything else stays
durably queued for a later batch, so control-plane accounting neither adds to
the caller's response latency nor produces one usage call per request.

A batch that is not yet due when the last response of a burst completes stays
durably queued, and the frozen timer cannot deliver it until another
invocation arrives. If traffic stops entirely, that trailing batch waits
indefinitely. Set `trailing_flush=True` to close this gap: a response whose
batch is not due holds the still-active invocation until the batching
deadline (at most `report_interval` seconds) and then delivers. Concurrent
responses coalesce onto one waiter, which makes at most one delivery attempt;
a failure arms the normal backoff and leaves every event durably queued. It
is opt-in because runtimes that buffer the whole response (for example AWS
Lambda behind an adapter without response streaming) would surface the hold
as caller latency; on Vercel with Fluid Compute the hold happens after the
response is sent and is invisible to callers.

This relies on a runtime that keeps the invocation alive for ASGI background
work (for example, Vercel Fluid Compute). Without Redis, journal files are
local to each instance; they protect retries within that instance but cannot
survive host replacement. **Configure `redis_url` in serverless deployments**:
the durable shared usage queue survives instance replacement, snapshots and
limit reservations are shared across instances, and a thawed worker recovers a
fresh snapshot from the shared cache on its next request instead of failing.

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
| `secret_key` | `$MICROAUTH_SECRET_KEY` | SDK secret key (`mas_...`) |
| `base_url` | `https://api.microauth.com` | MicroAuth API (`$MICROAUTH_BASE_URL`) |
| `header_name` | `X-API-Key` | Header customers send their key in |
| `redis_url` | `$MICROAUTH_REDIS_URL` | Share snapshots and enforce exact cross-worker limits |
| `shared_snapshot_cache` | `True` | Share snapshots and refresh locks when Redis is configured |
| `sync_interval` | `30` | Seconds between snapshot refreshes |
| `report_interval` | `5` | Flush when 500 events accumulate or this many seconds pass since the last flush |
| `flush_on_response` | Auto on Vercel/Lambda | Evaluate the batching rule after the final response frame |
| `trailing_flush` | `False` | Hold the invocation until the batching deadline so the last burst before traffic stops is delivered |
| `max_snapshot_age` | `300` | Fail-closed staleness threshold |
| `max_stale_snapshot_age` | `3 × max_snapshot_age` | Absolute stale-data ceiling |
| `fail_open` | `True` | Serve stale data only up to the absolute ceiling |
| `enforce_balance` | `True` | `402` when prepaid credit is exhausted |
| `enforce_quota` | `True` | `429` when the monthly quota is used up |
| `enforce_rps` | `True` | Per-customer RPS limiting |
| `enforce_platform_allowance` | `True` | Enforce the platform monthly hard cap |
| `verify_negative_ttl` | `30` | Seconds an invalid key is cached |
| `timeout` | `5` | HTTP timeout for MicroAuth calls |
| `usage_spool_path` | Tenant-specific temp path | Base path for the append-only usage journal |
| `persistence_namespace` | Snapshot tenant ID or secret fingerprint | Stable Redis and journal namespace |
| `persist_usage` | `True` | Keep stable IDs across process restarts |
| `max_usage_queue` | `10000` | Bounded journaled usage item count |
| `shutdown_timeout` | `10` | Maximum seconds for final usage drain |
| `http_client` | `None` | Optional externally owned async HTTP client |
| `redis_client` | `None` | Optional externally owned async Redis client |
| `redis_max_connections` | `64` | Connection cap for the pool built from `redis_url` |

## Error responses

Every denial is a JSON body of the form `{"detail": "..."}` with one of these
statuses. The fix column is what you, or your customer, can do about it.

| Status | Detail | Why | Fix |
| --- | --- | --- | --- |
| `401` | `Invalid or missing API key` | No key in the header, or the key is unknown or revoked | Send the key in `X-API-Key` (or your `header_name`); create a new key in the portal |
| `402` | `Insufficient credit balance` | The customer's prepaid balance cannot cover one billable request | The customer tops up in the portal. Give new customers a welcome credit so the first request works |
| `403` | `This account is suspended` | The customer is suspended, or billing suspended them after a failed payment | Reactivate the customer in the dashboard, or the customer fixes their payment method |
| `429` | `Rate limit exceeded` | More requests per second than the customer's RPS. Has `Retry-After` | Slow down, or raise the plan's RPS |
| `429` | `Monthly request quota exceeded` | The customer used their monthly request quota | Wait for the next period or upgrade the plan |
| `429` | `Platform monthly request allowance exhausted` | Your MicroAuth plan's monthly allowance is used up | Upgrade your MicroAuth plan |
| `503` | `Authorization is temporarily unavailable` | Snapshot too stale, Redis down while enforcing shared limits, or usage queue full | Check connectivity to MicroAuth and Redis. Run `python -m microauth_fastapi check` |

Customers never see your MicroAuth secret or internal state in these
messages. Server logs under the `microauth` logger explain every `503`.

All request denials subclass `microauth_fastapi.AuthDenied` (itself a
FastAPI `HTTPException`), so you can add your own exception handler to
reshape response bodies:

```python
from fastapi import Request
from fastapi.responses import JSONResponse
from microauth_fastapi import AuthDenied, PaymentRequired

@app.exception_handler(AuthDenied)
async def denied(request: Request, exc: AuthDenied):
    body = {"error": exc.detail}
    if isinstance(exc, PaymentRequired):
        body["top_up_url"] = "https://developers.example.com/billing"
    return JSONResponse(body, status_code=exc.status_code, headers=exc.headers)
```

Configuration, snapshot validation, API transport, usage acknowledgement,
spool and shutdown-drain failures also have exported typed exceptions.

## Consistency notes

- Redis provides one atomic shared decision for quota, possible spend, and
  the platform hard cap. Without Redis, each process enforces independently.
- Every request reserves customer and platform capacity before the endpoint
  starts. Those reservations remain consumed for every final status because
  the control plane counts every request. A nonbillable result releases only
  its monetary reservation.
- Completed usage is durably written before it enters the delivery queue: to
  the Redis shared queue when Redis is configured (surviving host
  replacement), otherwise to a per-process append-only journal file. Each
  process writes its own file; files abandoned by a dead process are adopted
  atomically by any surviving process on the host after a short grace, and a
  journal left behind by a pre-2.5 SQLite spool is migrated automatically.
  Without Redis, put `usage_spool_path` on a durable volume when host
  replacement must also be survived.
- Usage older than the API's 45-day acceptance window is dead-lettered with
  its reservation released instead of being retried into a guaranteed
  rejection.
- A stable tenant identifier from the snapshot is used for persistence when
  available. Set `persistence_namespace` or an explicit `usage_spool_path`
  when the control plane does not expose one and secret rotation must retain
  the same journal.
- Graceful shutdown drains the queue within `shutdown_timeout`. With the
  Redis durable queue, undeliverable items are handed back to the shared
  queue for other workers and shutdown succeeds; without it, shutdown fails
  with `UsageDrainError` and persisted items are retained for the next
  process.
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
      "balance_seq": 41,
      "month_requests": 1250,
      "effective": {
        "rps": 25,
        "price_per_request_micro": 1000,
        "monthly_quota": 100000,
        "billing_model": "subscription",
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

`status` is `active` for customers who may call your API. Any other value
(`suspended`, `billing_suspended`, or a status a future API adds) denies that
customer's keys with `403` without affecting anyone else. `balance_seq` is a
per-customer counter the API bumps on every committed balance change; the SDK
uses it to order balances exactly and accepts snapshots without it.

The snapshot is revalidated with `If-None-Match`. When nothing changed the
API may answer `304 Not Modified` with an `X-MicroAuth-Generated-At` header,
and the SDK reuses its previous snapshot stamped with that time. Every call
sends `User-Agent: microauth-fastapi/<version> python/<version>`.

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

The API must return exactly one result per submitted idempotency key, plus
the committed balance of every customer whose usage it charged:

```json
{
  "results": [
    {
      "idempotency_key": "bb02a6a7-10f4-4ab7-bf9c-8936770b67b7",
      "status": "accepted"
    }
  ],
  "customers": [
    { "id": "cus_123", "credit_balance_micro": 24958000, "balance_seq": 42 }
  ]
}
```

Per-item statuses:

- `accepted` and `duplicate` are successes. The SDK releases those requests'
  spend holds immediately and adopts the committed balance when its
  `balance_seq` is newer than what it has. A snapshot read before the charge
  committed can no longer roll the balance back.
- `rejected` (with an optional `detail`) is terminal. The item is
  dead-lettered and its hold released.
- `retry` is a transient failure for that item only. It stays queued with an
  unchanged payload and ships with the next flush.

Without `customers` (older APIs), holds are released once a later snapshot
proves the charge landed. If a whole batch fails with a terminal HTTP error,
the SDK bisects it to isolate and dead-letter only the bad item. Network
failures, `429`, and `5xx` responses keep the original payload for retry.
Missing, repeated or unknown results are treated as transient
acknowledgement failures.

The API repository generates golden fixtures for both shapes. The SDK tests
parse its copies in `tests/contract`, and compare them byte for byte with the
API's originals when both repositories are checked out side by side.

## Example app

See [`examples/weather_api.py`](examples/weather_api.py):

```bash
MICROAUTH_SECRET_KEY=mas_... uvicorn examples.weather_api:app --reload
```
