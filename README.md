# MicroAuth SDK for FastAPI

Everything a FastAPI app needs from [MicroAuth](https://microauth.com), in
one dependency:

- **Sign users in** to your web app, with sessions, roles and permissions
  (`UserAuth`).
- **Protect an API** that other apps call with MicroAuth access tokens
  (`TokenAuth`).
- **Protect an MCP server** so AI agents act for a user with only the scopes
  that user approved (`McpAuth`).
- **Sell your API** with API keys, per customer rate limits and metered
  billing, with a receipt for every charge (`MicroAuth`).

```bash
pip install microauth-fastapi
pip install "microauth-fastapi[mcp]"  # adds the MCP SDK for McpAuth
```

Settings come from the environment, and any `MICROAUTH_*` value that is not
set there is read from a `.env` file in the working directory. The SDK needs
Python 3.10 or newer.

## Sign users in

`UserAuth` adds sign in, sign up and sign out to a FastAPI web app. Your
server runs the OpenID Connect code flow against your MicroAuth service and
keeps the session in an encrypted, HttpOnly cookie, so browser JavaScript
never holds a token and a cross site scripting bug can't steal one.

```python
from fastapi import Depends, FastAPI
from microauth_fastapi import User, UserAuth

app = FastAPI()
auth = UserAuth(app)


@app.get("/dashboard")
async def dashboard(user: User = Depends(auth.login_required)):
    return {"hello": user.name}


@app.post("/api/posts")
async def create_post(user: User = Depends(auth.require(permissions="posts:write"))): ...
```

```bash
# .env, next to your app
MICROAUTH_ISSUER=https://auth.example.com
MICROAUTH_CLIENT_ID=...
MICROAUTH_CLIENT_SECRET=...
MICROAUTH_COOKIE_SECRET=...
MICROAUTH_APP_URL=https://app.example.com
```

Create a web application in the MicroAuth dashboard with the redirect URI
`https://app.example.com/auth/callback` and the sign out URL
`https://app.example.com/`. The cookie secret is yours to make: at least 32
random bytes, for example from
`python -c 'import secrets; print(secrets.token_urlsafe(32))'`. For local
development, `http://localhost:8000` works as the app URL.

`UserAuth(app)` adds these routes:

- `GET /auth/login?next=/path` starts sign in and comes back to `next`,
  which must be a path on your site.
- `GET /auth/signup?next=/path` does the same, opening on the sign up
  screen.
- `GET /auth/callback` is where MicroAuth sends the browser back after sign
  in.
- `POST /auth/logout` signs out here and at MicroAuth. Send it from a form
  or `fetch` on your own site.
- `GET /auth/me` returns the signed in user as JSON, or `401`.

Use these as dependencies:

- `auth.user` gives the `User`, or answers `401`.
- `auth.optional` gives the `User`, or `None` when nobody is signed in.
- `auth.login_required` gives the `User`, or redirects to sign in and back.
  Use it for pages.
- `auth.require(permissions=..., roles=...)` gives the `User` when they hold
  every permission and role listed, and answers `403` otherwise. Add
  `redirect=True` for pages.

`User` has `id`, `email`, `email_verified`, `name`, `picture`, `roles`,
`permissions`, `session_id` and the raw `claims`, plus `has_role()` and
`has_permission()`. Roles and permissions come from the `roles` scope.
`401` and `403` answers are problem JSON (RFC 9457) that keeps the `detail`
field FastAPI clients already read.

How sessions work:

- Sign in uses PKCE, state and nonce, and pushed authorization requests when
  MicroAuth offers them. The response must name your issuer in `iss`
  (RFC 9207), and the ID token must be RS256, issued to this app and
  unexpired.
- The session cookie is `__Host-microauth` on https and `microauth` on plain
  http: HttpOnly, `SameSite=Lax`, `Path=/`, and encrypted with AES-256-GCM.
  A large session is split into `__Host-microauth.0`, `.1` and so on. A
  cookie that doesn't decrypt counts as signed out.
- Access tokens are short lived. The SDK refreshes them just before they
  expire, once per session even under parallel requests, and writes the new
  cookie on whatever response your route returns. That is when role changes
  and suspensions reach your app. When MicroAuth ends the session, the user
  is signed out.
- POST, PUT, PATCH and DELETE requests that carry the session must come from
  your own origin, checked with `Origin` or `Referer`. That stops cross site
  form posts.
- To rotate the cookie secret, set `MICROAUTH_COOKIE_SECRET=new,old`. The
  first secret encrypts and all of them decrypt. Remove the old one once
  sessions have been rewritten.

`UserAuth` settings, with their defaults in brackets:

- `issuer` (`$MICROAUTH_ISSUER`): your MicroAuth service, such as
  `https://auth.example.com`.
- `client_id` (`$MICROAUTH_CLIENT_ID`) and `client_secret`
  (`$MICROAUTH_CLIENT_SECRET`): the web application's credentials.
- `cookie_secret` (`$MICROAUTH_COOKIE_SECRET`): 32 or more random bytes,
  comma separated to rotate.
- `app_url` (`$MICROAUTH_APP_URL`): your app's public origin. The redirect
  URI is built from it.
- `scopes` (`openid profile email roles`): the scopes to ask for.
- `resource` (`None`) and `keep_access_token` (`False`): get an access token
  for one of your APIs and keep it, so `await auth.access_token(request)`
  can call that API from your server.
- `prefix` (`/auth`): where the routes live.
- `after_sign_in` (`/`): where people land when the sign in link had no
  `next`.
- `after_sign_out` (`/`): where MicroAuth sends people after signing out.
- `cookie_name` (`microauth`): the base name of the cookies.
- `session_max_age` (30 days): the longest a session lasts, however often
  it is refreshed.
- `max_age` (`None`): make people sign in again when their last sign in is
  older than this many seconds.

## Protect an API with access tokens

`TokenAuth` checks MicroAuth access tokens on an API that other apps,
scripts or services call with `Authorization: Bearer <token>`.

```python
from fastapi import Depends, FastAPI
from microauth_fastapi import TokenAuth, TokenClaims

app = FastAPI()
api = TokenAuth(app)  # reads MICROAUTH_ISSUER and MICROAUTH_RESOURCE


@app.get("/posts")
async def posts(token: TokenClaims = Depends(api.require("posts:read"))):
    return {"user": token.sub, "app": token.client_id}
```

`MICROAUTH_RESOURCE` is the API's identifier exactly as you registered it in
MicroAuth, such as `https://api.example.com`.

- A token must be an RS256 JWT of type `at+jwt` from your issuer, with your
  resource in `aud`. A token minted for a different API is refused even
  when the same MicroAuth service issued it.
- Signing keys are cached and refreshed every 15 minutes, and fetched again
  right away (at most once a minute) when a token names a key the SDK hasn't
  seen.
- A missing or bad token gets `401` with
  `WWW-Authenticate: Bearer resource_metadata="..."`, plus
  `error="invalid_token"` when a token was sent. A token without a required
  scope gets `403` with `error="insufficient_scope"` and every scope the
  route needs.
- The protected resource metadata (RFC 9728) is served at
  `/.well-known/oauth-protected-resource`, followed by the resource's path
  when it has one: `/.well-known/oauth-protected-resource/v1` for
  `https://api.example.com/v1`.
- `TokenClaims` has `sub`, `client_id`, `scopes`, `audience`, `expires_at`,
  `issued_at`, `token_id`, `session_id`, `auth_time` and the raw `claims`.
- `TokenAuth(scopes=...)` adds scopes every route needs, and
  `Depends(api.require())` with no scopes needs only a valid token.

## Protect an MCP server

`McpAuth` puts MicroAuth in front of a remote MCP server built with the
official MCP Python SDK, following the MCP 2026-07-28 authorization spec.
Install it with `pip install "microauth-fastapi[mcp]"`.

```python
from mcp.server.mcpserver import MCPServer
from microauth_fastapi import McpAuth, current_identity

mcp = MCPServer("Invoices")
auth = McpAuth(scopes=["invoices:read"])  # reads MICROAUTH_ISSUER and MICROAUTH_RESOURCE


@mcp.tool()
@auth.tool("invoices:read")
def list_invoices() -> list[dict]:
    return invoices_owned_by(current_identity().sub)


@mcp.tool()
@auth.tool("invoices:write")
def create_invoice(customer: str, amount_cents: int) -> dict: ...


app = auth.wrap(mcp.streamable_http_app(stateless_http=True, json_response=True))
```

Serve `app` at the root of its host, with `MICROAUTH_RESOURCE` set to the
server's URL, such as `https://mcp.example.com/mcp`.

- Every request needs a valid token for that resource holding the `scopes`
  given to `McpAuth`. Without one the client gets `401` with a challenge
  that names the metadata URL and those scopes, which is how MCP clients
  find out where to sign in.
- A `tools/call` also needs the scopes declared for that tool, with
  `@auth.tool(...)` (named after the function, or pass `name=`) or with
  `McpAuth(tool_scopes={"create_invoice": ["invoices:write"]})`. A token
  missing one gets `403` with `error="insufficient_scope"` and every scope
  the tool needs, so the client asks the user once. Tools without declared
  scopes need only the base scopes, and the SDK logs a warning the first
  time one is called.
- The protected resource metadata is served at both
  `/.well-known/oauth-protected-resource/mcp` and
  `/.well-known/oauth-protected-resource`.
- Each POST must carry one JSON-RPC message, as the 2026-07-28 transport
  sends them. Batches are refused, and the `Mcp-Method` and `Mcp-Name`
  headers must match the body.
- Inside a tool, `current_identity()` returns the caller's `TokenClaims`.
  The MCP SDK's own `get_access_token()` works too.
- Scopes decide what kind of action a client may take, not which records it
  may touch. Check ownership in the tool, as
  [`examples/invoices_mcp.py`](https://github.com/Zyref-Org/microauth-sdk-fastapi/blob/main/examples/invoices_mcp.py)
  does.

If you would rather use the MCP SDK's own auth settings,
`MicroAuthTokenVerifier` is a `TokenVerifier` that checks tokens exactly like
`TokenAuth`:

```python
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from microauth_fastapi import MicroAuthTokenVerifier

mcp = MCPServer(
    "Invoices",
    token_verifier=MicroAuthTokenVerifier(),
    auth=AuthSettings(
        issuer_url="https://auth.example.com",
        resource_server_url="https://mcp.example.com/mcp",
        required_scopes=["invoices:read"],
    ),
)
```

## Sell your API with API keys

`MicroAuth` adds API key authentication, per customer rate limiting and
metered billing to your API.

```python
from fastapi import FastAPI, Security
from microauth_fastapi import Customer, MicroAuth

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

That's the whole integration. Your API's SDK secret is on its **Connect** tab
in the [MicroAuth dashboard](https://microauth.com/app).

Your customers sign up on your developer portal, create API keys, and pick a
plan or add credit. Every request to `/forecast` is then authenticated, rate
limited and billed, and MicroAuth answers every charge with a receipt.

The [FastAPI guide](https://microauth.com/docs/fastapi) explains each part in
more depth, and the [SDK reference](https://microauth.com/docs/fastapi-reference)
lists every option, field and error.

## Check your setup

Before you deploy, run the built in check from the same directory and
environment your app uses:

```bash
python -m microauth_fastapi check
```

It confirms the secret works, loads a snapshot, measures this machine's clock
against MicroAuth's, pings Redis when `MICROAUTH_REDIS_URL` is set, and makes
sure the usage journal is writable and somewhere a reboot won't clear. Add
`--key` with one of your customers' API keys to see exactly how a request
with that key would be treated, and why:

```text
$ python -m microauth_fastapi check --key map_...
API key
  ok    key belongs to customer 2b7c1f8e-...
        plan source: payg, billing: payg
        balance: $0
        price per billable request: $0.001
  fail  the balance cannot cover one billable request, so requests get 402. Add credit from the portal or grant a welcome credit.
```

The check also registers your SDK with MicroAuth, so the dashboard's setup
checklist turns green as soon as it succeeds. Every flag is in the
[SDK reference](https://microauth.com/docs/fastapi-reference#check-command), and
[troubleshooting](https://microauth.com/docs/troubleshooting#sdk-not-connecting)
covers what to do when a check fails.

## What it does

- **API key auth** via the `X-API-Key` header (configurable), including the
  security scheme in your OpenAPI docs, so the Swagger "Authorize" button
  just works.
- **Account, balance and quota enforcement.** Suspended customers and
  customers still waiting for your approval get `403`, customers who ran out
  of prepaid credit get `402`, and customers over their monthly quota get
  `429`.
- **Per customer rate limiting** at each customer's effective RPS (a custom
  override first, then the plan, then the pay as you go default), scoped to
  each API key, with `429` and `Retry-After`.
- **Atomic request reservations** for customer quota, possible prepaid spend
  and the platform monthly allowance before your endpoint starts. Redis
  coordinates the complete decision across workers.
- **Complete usage reporting** for every completed authenticated request,
  grouped by API key and exact response status. Only configured billable
  statuses consume prepaid credit.
- **Receipts and reconciliation.** MicroAuth answers every report with a
  receipt per item: which customer was charged, how much and when. The SDK
  checks each charge against the price it enforced and can hand every
  receipt to your own records.

## Receipts and reconciliation

Pass hooks to keep your own record of every charge and every refusal:

```python
from microauth_fastapi import MicroAuth, UsageReceipt, UsageRejection


async def keep_receipts(receipts: list[UsageReceipt]) -> None:
    for receipt in receipts:
        await ledger.save(receipt.idempotency_key, receipt)


async def flag_rejections(rejections: list[UsageRejection]) -> None:
    for rejection in rejections:
        alerts.send(f"MicroAuth refused {rejection.count} request(s): {rejection.detail}")


auth = MicroAuth(app, on_receipts=keep_receipts, on_rejections=flag_rejections)
```

- A receipt's `outcome` is `accepted` when that delivery recorded the item
  and `duplicate` when MicroAuth had recorded it already, for example after a
  retry whose first answer was lost. The customer is charged once either way.
- `charged_micro` is what MicroAuth charged, `expected_charge_micro` is what
  the SDK expected from the prices it enforced, and `charge_matches` says
  whether they agree. The SDK logs every mismatch at error level.
- Hooks run before an item leaves the queue, so a crash can't skip a
  receipt. A receipt can arrive twice instead, so store them by
  `idempotency_key`.
- Hooks can be async. A plain function runs in a worker thread so it can't
  stall your requests. Each call gets five seconds, and failures are logged
  and counted without holding up delivery.
- Refused usage is never charged. It is kept as a dead letter in the journal
  (and in Redis when configured) with MicroAuth's reason.

`auth.usage_stats()` returns the delivery health of the process: what is
queued and since when, what was delivered, refused and charged, how many
charges differed from the expected amount, the latest error, and the offset
between this machine's clock and MicroAuth's. Export it to your metrics and
alert on `rejected_items`, `charge_mismatches`, a growing
`consecutive_failures` and an `oldest_queued_at` that keeps aging.

To look at what a host still has to deliver, and everything MicroAuth
refused, run the read only usage command where your API runs:

```bash
python -m microauth_fastapi usage
python -m microauth_fastapi usage --json
```

## Designed for the hot path

- A **snapshot** of your customers, keys and limits is cached in memory and
  refreshed in the background (default every 30s). With Redis, validated
  snapshots are shared across instances and one distributed refresh lock
  prevents autoscaling cold starts from stampeding MicroAuth.
- Keys not in the snapshot yet (created seconds ago) are resolved once via
  a **single flight** on demand lookup; invalid keys are negatively cached
  so a flood of bad keys can't reach MicroAuth.
- Usage is durably written as each request completes, before its response
  finishes: to a shared Redis queue when Redis is configured, otherwise to a
  per process journal file with one checksummed, fsynced line per request,
  group committed across concurrent requests. Requests sharing an API key,
  usage policy, status and hour merge into one counted item. A delivery
  happens when 500 requests accumulate or `report_interval` (default 5s)
  passes since the last one, whichever comes first, so a burst becomes one
  usage call. Every item is immutable once delivery starts and keeps one
  idempotency key across retries, workers and restarts.
- Authentication itself is a SHA-256 and a couple of dict lookups.

Long lived processes report usage in background batches and do not call
MicroAuth on the normal authentication hot path. The middleware loads the
first snapshot when the app starts, so the first request is served from
memory too.

If MicroAuth is briefly unreachable, your API keeps serving with the last
known data (`fail_open=True`, the default), but never forever. Stale data has
an absolute `max_stale_snapshot_age` limit. Set `fail_open=False` to return
`503` at the earlier `max_snapshot_age` threshold. An expired usage policy is
always refreshed before another request is authorized; if that refresh fails,
the SDK returns `503` rather than creating usage under stale billing terms.

## Multiple workers? Add Redis

In memory request limits are exact within one process. With 4 uvicorn
workers, each process has independent RPS, quota, balance and platform
reservation state. Point the SDK at Redis for one atomic shared reservation
across every worker and machine. The same Redis connection also shares
snapshots and coordinates refreshes:

```python
auth = MicroAuth(app, redis_url="redis://localhost:6379/0")
```

```bash
pip install 'microauth-fastapi[redis]'
```

RPS uses a fixed one second window in both backends. Its key includes both
the customer and the API key, so traffic on one key does not throttle another
key owned by the same customer. The RPS check rides inside the same atomic
reservation script as quota, spend and platform decisions, so the entire
admission decision costs one Redis round trip per request and a rate limited
request consumes no quota or balance. Like those decisions, it fails closed
(`503`) if Redis is down, because serving without an atomic decision could
oversubscribe a hard limit.

With Redis configured, completed usage also enters a **durable shared
queue**: each item is enqueued before the final response body is released
and delivered under a per worker lease. If a worker dies, including
serverless instance replacement, its leases expire and any other worker
sharing the queue recovers and delivers its items exactly once from
MicroAuth's point of view, because idempotency keys are preserved.
Durability is bounded by your Redis deployment's persistence: managed
offerings such as Upstash persist by default; self hosted Redis should enable
AOF.

Connections are bounded. With `redis_url`, the SDK builds a blocking pool of
at most `redis_max_connections` (default 64) per worker, with one second
socket timeouts. Under a burst, requests wait up to a second for a free
connection instead of opening new ones, so autoscaling cannot exhaust a
managed plan's connection cap. Size it so instances times pool size stays
under your plan's limit:

```python
auth = MicroAuth(app, redis_url=redis_url, redis_max_connections=10)
```

For full control, pass your own client with `redis_client=`. A passed client
is externally owned: the SDK uses it but never closes it. The
[FastAPI guide](https://microauth.com/docs/fastapi#redis-connections) has the
full sizing discussion and the warning signs to watch for in logs.

## Serverless runtimes

On Vercel and AWS Lambda, `flush_on_response` defaults to `True`. This fixes
the case where the report timer is frozen after a low traffic request and
only runs when the next invocation arrives. The completed usage is written
before the final body is released; after that frame is sent, the batching
rule is evaluated while the invocation is still active. A due batch is
delivered, and anything else stays durably queued for a later batch, so
usage accounting neither adds to the caller's response latency nor produces
one usage call per request.

A batch that is not yet due when the last response of a burst completes
stays queued, and the frozen timer cannot deliver it until another
invocation arrives. Set `trailing_flush=True` to close this gap: a response
whose batch is not due holds the still active invocation until the batching
deadline (at most `report_interval` seconds) and then delivers. Concurrent
responses share one waiter, which makes at most one delivery attempt. It is
opt in because runtimes that buffer the whole response (for example AWS
Lambda behind an adapter without response streaming) would surface the hold
as caller latency; on Vercel with Fluid Compute the hold happens after the
response is sent and is invisible to callers.

Without Redis, journal files are local to each instance; they protect
retries within that instance but cannot survive host replacement.
**Configure `redis_url` in serverless deployments**: the durable shared
usage queue survives instance replacement, snapshots and limit reservations
are shared across instances, and a thawed worker recovers a fresh snapshot
from the shared cache instead of failing. The
[serverless guide](https://microauth.com/docs/fastapi#serverless) has a
starting configuration.

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
| `redis_url` | `$MICROAUTH_REDIS_URL` | Share snapshots and enforce exact cross worker limits |
| `shared_snapshot_cache` | `True` | Share snapshots and refresh locks when Redis is configured |
| `sync_interval` | `30` | Seconds between snapshot refreshes |
| `report_interval` | `5` | Deliver when 500 requests are queued or this many seconds pass since the last delivery |
| `flush_on_response` | Auto on Vercel and Lambda | Evaluate the batching rule after the final response frame |
| `trailing_flush` | `False` | Hold the invocation until the batching deadline so the last burst before traffic stops is delivered |
| `max_snapshot_age` | `300` | Fail closed staleness threshold |
| `max_stale_snapshot_age` | `3 × max_snapshot_age` | Absolute stale data ceiling |
| `fail_open` | `True` | Serve stale data only up to the absolute ceiling |
| `enforce_balance` | `True` | `402` when prepaid credit is exhausted |
| `enforce_quota` | `True` | `429` when the monthly quota is used up |
| `enforce_rps` | `True` | Per customer RPS limiting |
| `enforce_platform_allowance` | `True` | Enforce the platform monthly hard cap |
| `verify_negative_ttl` | `30` | Seconds an invalid key is cached |
| `timeout` | `5` | HTTP timeout for MicroAuth calls |
| `journal_dir` | `$MICROAUTH_JOURNAL_DIR`, else a per user state directory | Where queued usage is kept on disk. Each API gets its own subdirectory |
| `persist_usage` | `True` | Keep queued usage across restarts. Turn off only in tests |
| `max_usage_queue` | `10000` | Most reserved and queued usage items at once |
| `shutdown_timeout` | `10` | Maximum seconds for the final usage drain |
| `on_receipts` | `None` | Called with the receipts of each delivery |
| `on_rejections` | `None` | Called with usage MicroAuth refused for good |
| `http_client` | `None` | Optional externally owned async HTTP client |
| `redis_client` | `None` | Optional externally owned async Redis client |
| `redis_max_connections` | `64` | Connection cap for the pool built from `redis_url` |

The default journal directory is `~/.local/state/microauth/journal` on Linux
(or `$XDG_STATE_HOME/microauth/journal`), `~/Library/Application
Support/microauth/journal` on macOS and `%LOCALAPPDATA%\microauth\journal` on
Windows. On serverless platforms it is the temp directory. In containers,
mount a volume and point `MICROAUTH_JOURNAL_DIR` at it.

## Error responses

Every denial is a JSON body of the form `{"detail": "..."}` with one of these
statuses. The fix column is what you, or your customer, can do about it.

| Status | Detail | Why | Fix |
| --- | --- | --- | --- |
| `401` | `Invalid or missing API key` | No key in the header, or the key is unknown or revoked | Send the key in `X-API-Key` (or your `header_name`); create a new key in the portal |
| `402` | `Insufficient credit balance` | The customer's prepaid balance cannot cover one billable request | The customer tops up in the portal. Give new customers a welcome credit so the first request works |
| `403` | `This account is suspended` | You suspended the customer | Reactivate the customer in the dashboard |
| `403` | `This account is waiting for approval` | Sign ups need your approval and this customer is still waiting | Approve the customer in the dashboard |
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
journal and shutdown drain failures raise exported subclasses of
`MicroAuthError` in your logs instead.

## Durability and consistency

- Redis provides one atomic shared decision for quota, possible spend and
  the platform hard cap. Without Redis, each process enforces independently.
- Every request reserves customer and platform capacity before the endpoint
  starts. Those reservations stay consumed for every final status, because
  MicroAuth counts every request. A nonbillable result releases only its
  monetary reservation.
- Each request is charged under the usage policy it was admitted with, which
  fixes its price, billing model and billable status codes, so usage
  delivered late is still charged at the prices that applied when it was
  served.
- Every journal line carries a checksum. A line cut short by a crash belongs
  to a response that never finished, so it is dropped; damage anywhere else
  is logged and a copy of the file is kept for inspection. Refused usage is
  written to the dead letters before the journal forgets it.
- Each process writes its own journal file and refreshes it while it runs.
  When a process dies, the app on the same directory adopts its file once it
  has been idle for two minutes, even without traffic, and delivers its
  usage with the original idempotency keys.
- Usage hours, usage policy expiry and snapshot age follow MicroAuth's
  clock, measured on every response, so a server whose clock drifts still
  reports usage in the right hour. `check` shows the offset, and the SDK
  warns when it reaches two seconds.
- One process serves one API. Queued usage is kept per API, so two APIs on a
  host never mix their usage, and rotating the secret keeps the same journal
  and Redis queue.
- Usage older than MicroAuth's 45 day acceptance window is dead lettered with
  its reservation released instead of being retried into a certain refusal.
- Graceful shutdown drains the queue within `shutdown_timeout`. Usage that
  can't be delivered in time is handed back, to the Redis queue for other
  workers or to the journal for the next process, and shutdown succeeds;
  only usage that nothing could take back raises `UsageDrainError`.
- Suspensions and key revocations propagate within one `sync_interval`.

## Platform contract

`MicroAuth` talks to three endpoints: `GET /sdk/v1/snapshot`,
`GET /sdk/v1/keys/verify` and `POST /sdk/v1/usage`. They are documented in
the [HTTP API guide](https://microauth.com/docs/http-api). Every call sends
`User-Agent: microauth-fastapi/<version> python/<version>`, which lets the
dashboard show which SDK version is connected.

`UserAuth`, `TokenAuth` and `McpAuth` only talk to your issuer, through the
endpoints its `/.well-known/openid-configuration` document lists: the
signing keys, and for `UserAuth` the pushed authorization, token,
revocation and end session endpoints. The discovery document is cached for
an hour and must name exactly the issuer you configured.

MicroAuth generates golden fixtures of each response from its own types. The
SDK's tests parse copies of them in `tests/contract`, and compare them byte
for byte with the originals when both repositories are checked out side by
side.

## Example apps

See [`examples/weather_api.py`](https://github.com/Zyref-Org/microauth-sdk-fastapi/blob/main/examples/weather_api.py):

```bash
MICROAUTH_SECRET_KEY=mas_... uvicorn examples.weather_api:app --reload
```

[`examples/blog_cms.py`](https://github.com/Zyref-Org/microauth-sdk-fastapi/blob/main/examples/blog_cms.py)
signs people in with `UserAuth`: anyone reads posts, editors write them and
admins delete them.
[`examples/invoices_mcp.py`](https://github.com/Zyref-Org/microauth-sdk-fastapi/blob/main/examples/invoices_mcp.py)
is an MCP server with a scope per tool and an ownership check in each one.
Their docstrings say how to set them up.
