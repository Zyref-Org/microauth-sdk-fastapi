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
  override → plan → pay-as-you-go default), `429` with `Retry-After`.
- **Metered billing** — responses with a billable status code (you choose
  them in your tenant settings; default `200` only) are counted per API key
  and reported to MicroAuth in efficient batches.

## Designed for the hot path

The SDK never calls MicroAuth while serving a request:

- A **snapshot** of your customers, keys and limits is cached in memory and
  refreshed in the background (default every 30s).
- Keys not in the snapshot yet (created seconds ago) are resolved once via
  a **single-flight** on-demand lookup; invalid keys are negatively cached
  so a flood of bad keys can't reach MicroAuth.
- Usage is aggregated in memory (one counter per key per hour) and flushed
  in the background (default every 15s), surviving MicroAuth outages with
  buffering and retries.
- Authentication itself is a SHA-256 and a couple of dict lookups.

If MicroAuth is briefly unreachable, your API keeps serving with the last
known data (`fail_open=True`, the default). Set `fail_open=False` if you'd
rather return `503` once the snapshot is older than `max_snapshot_age`.

## Multiple workers? Add Redis

In-memory rate limiting is per-process: with 4 uvicorn workers a customer
could reach ~4× their RPS. If that matters to you, point the SDK at Redis
and limits are enforced exactly across every worker and machine:

```python
auth = MicroAuth(app, redis_url="redis://localhost:6379/0")
```

```bash
pip install 'microauth-fastapi[redis]'
```

One Redis round trip per request (pipelined `INCR`+`EXPIRE`), and if Redis
goes down the limiter fails open so your API stays up.

Billing does **not** need Redis: each worker reports its own counts and
MicroAuth sums them idempotently per hour bucket.

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
| `max_snapshot_age` | `300` | Staleness threshold for `fail_open` |
| `fail_open` | `True` | Keep serving with stale data vs. `503` |
| `enforce_balance` | `True` | `402` when prepaid credit is exhausted |
| `enforce_quota` | `True` | `429` when the monthly quota is used up |
| `enforce_rps` | `True` | Per-customer RPS limiting |
| `verify_negative_ttl` | `30` | Seconds an invalid key is cached |
| `timeout` | `5` | HTTP timeout for MicroAuth calls |

## Error responses

| Status | When |
| --- | --- |
| `401` | Missing or invalid API key |
| `402` | Prepaid balance exhausted |
| `403` | Customer suspended |
| `429` | RPS limit (`Retry-After` header) or monthly quota exceeded |
| `503` | Only with `fail_open=False` and stale data |

All of these subclass `microauth_fastapi.AuthDenied` (itself a FastAPI
`HTTPException`), so you can add your own exception handler to reshape the
response bodies.

## Consistency notes (the honest fine print)

- Balance and quota enforcement use the cached snapshot plus locally counted
  activity, corrected on every refresh. A customer racing their last credits
  across many workers can overshoot by at most ~one `sync_interval` of
  traffic — the industry-standard tradeoff that keeps your latency flat.
- A crashed worker loses at most `report_interval` seconds of unreported
  usage. Graceful shutdowns flush everything.
- Suspensions and key revocations propagate within one `sync_interval`
  (30s by default) to every worker.

## Example app

See [`examples/weather_api.py`](examples/weather_api.py):

```bash
MICROAUTH_SECRET_KEY=mas_... uvicorn examples.weather_api:app --reload
```
