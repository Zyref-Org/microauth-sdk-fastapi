# MicroAuth SDK for FastAPI

Everything a FastAPI app needs from [MicroAuth](https://microauth.com), in
one dependency:

- **Sign users in** to your web app, with sessions, roles and permissions
  (`UserAuth`).
- **Protect an API** that other apps call with MicroAuth access tokens, and
  that your users call with API keys they make for their own accounts
  (`TokenAuth`).
- **Protect an MCP server** so AI agents act for a user with only the scopes
  that user approved (`McpAuth`).
- **Sell your API** with API keys, per customer rate limits and metered
  billing, with a receipt for every charge (`MicroAuth`).

```bash
pip install microauth-fastapi
pip install "microauth-fastapi[mcp]"  # adds the MCP SDK for McpAuth
```

The SDK needs Python 3.10 or newer.

## Configuration

Every setting can be passed to the constructor. Most also have a
`MICROAUTH_*` environment variable, listed with each class below, that is
used when you don't pass the argument. The SDK looks for those variables in
two places:

1. The process environment. A variable set there always wins, even when it
   is empty.
2. A `.env` file in the working directory, which is the directory the
   server was started from. Only `MICROAUTH_*` lines are read. Other lines
   are ignored, and nothing is copied into `os.environ`.

The file takes `NAME=value` lines, optionally starting with `export`, with
`#` comments and single or double quotes around values. Settings are read
when each object is created, so a change to the file needs a restart. Keep
`.env` out of version control, since it holds secrets. If you already load
it with python-dotenv, Docker or your process manager, nothing changes:
those values are in the environment, so they win.

Pass arguments instead when one app needs two values for the same setting,
such as an API and an MCP server that each have their own server
credentials. See
[An API and an MCP server in one app](#an-api-and-an-mcp-server-in-one-app).

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
  which must be a path on your site. Add `max_age=600` to make people sign
  in again unless they did in the last 10 minutes.
- `GET /auth/signup?next=/path` does the same, opening on the sign up
  screen.
- `GET /auth/callback` is where MicroAuth sends the browser back after sign
  in.
- `POST /auth/logout` signs out here and at MicroAuth. Send it from a form
  or `fetch` on your own site.
- `GET /auth/me` returns the signed in user as JSON, or `401`.

Use these as dependencies:

- `auth.user` gives the `User`, or answers `401`.
- `auth.optional` gives the `User`, or `None` when nobody is signed in. A
  POST, PUT, PATCH or DELETE from another site also gives `None`, so the
  route runs as it would for a signed out visitor instead of failing.
- `auth.login_required` gives the `User`, or redirects to sign in and back.
  Use it for pages.
- `auth.require(permissions=..., roles=...)` gives the `User` when they hold
  every permission and role listed, and answers `403` otherwise. Add
  `redirect=True` for pages.

`auth.user`, `auth.login_required` and `auth.require` refuse a cross site
POST, PUT, PATCH or DELETE with `403`.

`User` has `id`, `email`, `email_verified`, `name`, `picture`, `roles`,
`permissions`, `session_id`, `amr`, `auth_time` and the raw `claims`, plus
`has_role()` and `has_permission()`. Roles and permissions come from the
`roles` scope. `amr` is the set of ways the person proved who they are at
sign in, with RFC 8176 values such as `pwd` and `otp`, and `auth_time` is
when that sign in happened, in Unix seconds. Refreshing the session doesn't
change either, so `auth_time` tells you how long ago the person last
actually signed in.

`401` and `403` answers are problem JSON (RFC 9457) that keeps the `detail`
field FastAPI clients already read.

### Your own refusal pages

To show your own page for a refusal, register an exception handler for that
class, before or after `UserAuth(app)`. The SDK never replaces a handler
your app registered. `refusal_response(request, exc)` builds the answer the
SDK would have sent, so your handler can still use it for API calls:

```python
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from microauth_fastapi import PermissionDenied, UserAuth, refusal_response

app = FastAPI()
auth = UserAuth(app)


@app.exception_handler(PermissionDenied)
async def permission_denied(request: Request, exc: PermissionDenied):
    if "text/html" in request.headers.get("accept", ""):
        return HTMLResponse("<h1>You can't open this page</h1>", status_code=403)
    return await refusal_response(request, exc)
```

The classes are `SignInRequired` (401), `PermissionDenied` (403),
`CrossSiteRequest` (403), `SignInRedirect` (303 to the sign in route) and
`ReauthenticationRequired` (401 with `login_url`), and with `TokenAuth` also
`InvalidToken` (401), `InsufficientScope` (403) and `TooManyRequests` (429).
When you build your own response, copy `exc.headers` onto it, since they
carry `WWW-Authenticate`, `Retry-After` and `Location`.

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
- `api_keys` (`False`): let signed in people manage their own API keys from
  your app with `auth.api_keys`. See
  [Let people manage their keys from your app](#let-people-manage-their-keys-from-your-app).
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
- When the issuer can't be reached to check a token, the answer is `503`
  with `Retry-After: 5`.
- The protected resource metadata (RFC 9728) is served at
  `/.well-known/oauth-protected-resource`, followed by the resource's path
  when it has one: `/.well-known/oauth-protected-resource/v1` for
  `https://api.example.com/v1`. Only a resource without a path uses the
  bare root URL, so several resources on one host each keep their own
  document.
- `TokenClaims` has `sub`, `via`, `client_id`, `scopes`, `audience`,
  `expires_at`, `issued_at`, `token_id`, `session_id`, `auth_time`, `key_id`
  and the raw `claims`. For an access token, `via` is `"access_token"`.
- `TokenAuth(scopes=...)` adds scopes every route needs, and
  `Depends(api.require())` with no scopes needs only a valid token.
- `TokenAuth(app)` closes the HTTP client it made when the app shuts down.

## Protect an MCP server

`McpAuth` puts MicroAuth in front of a remote MCP server built with the
official MCP Python SDK, following the MCP 2026-07-28 authorization spec.
Install it with `pip install "microauth-fastapi[mcp]"`.

```python
from fastapi import FastAPI
from mcp.server.mcpserver import MCPServer
from microauth_fastapi import McpAuth, current_identity

mcp = MCPServer("Invoices", log_level="WARNING")
auth = McpAuth(scopes=["invoices:read"])  # reads MICROAUTH_ISSUER and MICROAUTH_RESOURCE
INVOICES: list[dict] = []  # your database


@mcp.tool()
@auth.tool("invoices:read")
def list_invoices() -> list[dict]:
    me = current_identity().sub
    return [invoice for invoice in INVOICES if invoice["owner"] == me]


@mcp.tool()
@auth.tool("invoices:write")
def create_invoice(customer: str, amount_cents: int) -> dict:
    invoice = {"owner": current_identity().sub, "customer": customer, "amount_cents": amount_cents}
    INVOICES.append(invoice)
    return invoice


app = FastAPI()
auth.mount(app, mcp)
```

Set `MICROAUTH_RESOURCE` to the server's public URL, such as
`https://mcp.example.com/mcp`. `auth.mount(app, mcp)` then does everything
needed to serve the MCP server inside your app, next to its other routes:

- It serves the MCP endpoint at the resource's path (`/mcp` here, and also
  `/mcp` for a resource without a path), or at `path=` if you pass one.
- It serves the protected resource metadata, described below.
- It starts the MCP server's session manager when your app starts and stops
  it at shutdown. Your app's own lifespan still runs around it.
- It closes the HTTP and Redis clients `McpAuth` made when the app shuts
  down.

Call it once, before the app starts. An `MCPServer` is served statelessly
with JSON responses, and the MCP SDK is told to accept only the Host and
Origin headers of your resource URL. Without that the MCP SDK accepts only
`localhost`, and every request to a real domain gets `421`. For other
transport settings, build the app yourself and pass it instead:
`auth.mount(app, mcp.streamable_http_app(streamable_http_path="/mcp", ...))`.
When the MCP server is the whole site, `app = auth.wrap(mcp.streamable_http_app(...))`
still works. Serve that at the root of its host.

`log_level="WARNING"` matters. `MCPServer` configures Python's root logger
at `INFO` unless you say otherwise, which makes the MCP SDK and httpx log a
line for every request, including the calls `McpAuth` makes to MicroAuth.
The level you pass only applies when the root logger has no handlers yet,
so if your app sets up logging itself, do that before creating the
`MCPServer`. The SDK itself never logs tokens, API keys or secrets, at any
level.

How requests are checked:

- Every request, whatever its JSON-RPC method, needs a valid token for that
  resource holding the `scopes` given to `McpAuth`. Without a token the
  client gets `401` with a challenge that names the metadata URL and those
  scopes, which is how MCP clients find out where to sign in. A token
  without them gets `403`.
- A `tools/call` also needs the scopes declared for that tool, with
  `@auth.tool(...)` (named after the function, or pass `name=`) or with
  `McpAuth(tool_scopes={"create_invoice": ["invoices:write"]})`. Tools
  without declared scopes need only the base scopes, and the SDK logs a
  warning the first time one is called.
- A `403` names what is missing three ways. `WWW-Authenticate` has
  `error="insufficient_scope"`, a `scope` with every scope the request needs
  (so the client asks the user once) and an `error_description` such as
  `The create_invoice tool needs the invoices:write scope, and this access
  token doesn't have it`. The body is a JSON-RPC error with the same
  sentence as its `message`, code `403`, and `error` and `scope` in `data`.
  API keys get the same, with "permission" and "API key" in the wording.
- When the issuer can't be reached the answer is `503`, and a caller over a
  key limit gets `429`, both with `Retry-After`.
- Each POST must carry one JSON-RPC message, as the 2026-07-28 transport
  sends them. Batches are refused, and the `Mcp-Method` and `Mcp-Name`
  headers must match the body.
- Inside a tool, `current_identity()` returns the caller's `TokenClaims`.
  The MCP SDK's own `get_access_token()` works too.
- Scopes decide what kind of action a client may take, not which records it
  may touch. Check ownership in the tool, as
  [`examples/invoices_mcp.py`](https://github.com/Zyref-Org/microauth-sdk-fastapi/blob/main/examples/invoices_mcp.py)
  does.

The protected resource metadata (RFC 9728) is served at the path inserted
URL for the resource, `/.well-known/oauth-protected-resource/mcp` for
`https://mcp.example.com/mcp`, and the `401` challenge points there. Only a
resource without a path uses the bare `/.well-known/oauth-protected-resource`,
so an API on the same host keeps its own document. MCP clients find it
either way: the official Python client (2.3.0) tries the URL in the
challenge first, then the path inserted URL, then the root.

What MCP clients show when a request is refused:

- The official Python client (2.3.0), when it signed in with OAuth, treats
  the `403` as a step up. It asks the user to approve the scopes in the
  challenge, along with the ones it already had, and retries the request.
- When it can't step up, for example because it sends an API key or a fixed
  token, or when the retried request is refused again, it raises `MCPError`
  with the sentence from the body. It reads the body only because it is a
  JSON-RPC error. For any other body it can only say
  `Server returned an error response`.
- Other clients show either the `error_description` from the header or the
  `message` from the body, which say the same thing.
- A POST refused with `401`, `429` or `503` also gets a JSON-RPC error body,
  with the HTTP status as its `code`, the reason as its `message` and the
  OAuth `error` in `data`. Its `id` is `null`, since the message wasn't read.
  So a client that can't sign in, such as one sending a revoked API key,
  shows `The API key is unknown, revoked or expired.` A request that sent no
  token at all gets no `data`, just as its `WWW-Authenticate` header names
  no `error` (RFC 6750 section 3.1). The `401` still starts OAuth discovery
  as before, because clients look only at its status and `WWW-Authenticate`
  header. A GET or DELETE gets a plain OAuth error body with `error` and
  `error_description`.

### An API and an MCP server in one app

An API and an MCP server can share one FastAPI app while staying separate
MicroAuth resources, each with its own permissions and server credentials.
Pass each one its resource and credentials, since the `MICROAUTH_RESOURCE*`
variables can hold only one of each:

```python
import os

from fastapi import FastAPI
from mcp.server.mcpserver import MCPServer
from microauth_fastapi import McpAuth, TokenAuth

app = FastAPI()
api = TokenAuth(
    app,
    resource="https://example.com",
    api_keys=True,
    resource_client_id=os.environ["API_CLIENT_ID"],
    resource_secret=os.environ["API_SECRET"],
)
mcp = MCPServer("Tasks", log_level="WARNING")
mcp_auth = McpAuth(
    resource="https://example.com/mcp",
    scopes=["tasks:read"],
    api_keys=True,
    resource_client_id=os.environ["MCP_CLIENT_ID"],
    resource_secret=os.environ["MCP_SECRET"],
)
# Routes use api.require(...), and tools use @mcp.tool() with @mcp_auth.tool(...).
mcp_auth.mount(app, mcp)
```

A token or key made for one is refused by the other, and each serves its
own metadata: the API at `/.well-known/oauth-protected-resource` and the
MCP server at `/.well-known/oauth-protected-resource/mcp`. Pass
`resource_client_id` and `resource_secret` together or not at all. One
argument never pairs with the other's environment variable, since that could
match one resource's ID with another resource's secret.
[`examples/api_and_mcp.py`](https://github.com/Zyref-Org/microauth-sdk-fastapi/blob/main/examples/api_and_mcp.py)
is the whole app.

### The MCP SDK's own auth settings

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
        validate_token_resource=True,
    ),
)
```

`validate_token_resource=True` makes the MCP SDK check that each token was
issued for this server. MCP 2.3.0 warns when it is left out.

The MCP SDK lets a verifier only accept or refuse a token, so some of what
`McpAuth` does isn't possible this way. An issuer outage looks like a bad
token (`401` instead of `503` with `Retry-After`), per tool scopes aren't
checked, and with `api_keys=True` neither the per person key limit nor the
unknown key throttle applies. Use `McpAuth` when you need any of those.

## Accept your users' API keys

Some of your users want to call your API from a script, a CI job or a tool
that can't do OAuth. Turn on "API keys for your users" in the dashboard and
people can make keys for their own accounts, on MicroAuth's account page or
inside your app, each carrying the permissions they pick. `TokenAuth` and
`McpAuth` accept them next to access tokens:

```python
from fastapi import Depends, FastAPI
from microauth_fastapi import TokenAuth, TokenClaims

app = FastAPI()
api = TokenAuth(app, api_keys=True)


@app.post("/posts")
async def create_post(caller: TokenClaims = Depends(api.require("posts:write"))):
    return {"author": caller.sub, "via": caller.via}
```

```bash
# .env, next to your app
MICROAUTH_RESOURCE_CLIENT_ID=...
MICROAUTH_RESOURCE_SECRET=...
```

These are the API's server credentials, shown on its page under APIs and MCP
servers in the dashboard. They let the SDK ask MicroAuth about keys and
nothing else. Without them `TokenAuth(api_keys=True)` refuses to start.
When one app has several resources, give each its own with
`resource_client_id=` and `resource_secret=`, as in
[An API and an MCP server in one app](#an-api-and-an-mcp-server-in-one-app).
Callers send a key the way they send a token:

```bash
curl https://api.example.com/posts -H "Authorization: Bearer cms_..."
```

These keys belong to people who sign in to your app. They are not the keys
`MicroAuth` checks when you [sell your API](#sell-your-api-with-api-keys),
which belong to your paying customers and come with plans and billing.

How a key is checked:

- A bearer value with a dot is a JWT and is checked locally as before.
  Anything else is treated as a key.
- A key is your prefix, an underscore, 40 random characters and a 6
  character checksum, such as `cms_` followed by 46 letters and digits. A
  value with the wrong shape or checksum gets `401` without a call to
  MicroAuth.
- A well formed key is checked with token introspection (RFC 7662) at your
  issuer, using the server credentials. MicroAuth answers whether the key
  works at this API, whose it is, which permissions it carries right now,
  and how many requests a minute you allow each person.
- Answers are cached by the key's SHA-256, never the key itself, for as long
  as MicroAuth's `Cache-Control` allows: 30 seconds today and never more
  than 5 minutes. A revoked key, or a person who lost a role, stops working
  within that time. Parallel requests with the same key share one check.
- When MicroAuth can't be reached, a key that was active keeps working for
  `stale_if_error` seconds past its cached answer: 10 minutes by default, and
  0 turns this off. A key the SDK hasn't seen before gets `503` with
  `Retry-After: 5`. Errors are never cached.
- When MicroAuth refuses the server credentials, callers with keys get `503`
  and the SDK logs an error naming where the credentials came from: the two
  environment variables, or the arguments.
- Raw keys never reach logs, caches or Redis.

`TokenClaims` for a key has `via="api_key"`. `sub` is the person who made the
key and `scopes` are its permissions, so `api.require(...)` works the same
for keys and tokens, and a key missing a permission gets `403` with
`error="insufficient_scope"`. `key_id` identifies the key, `client_id` is
`None`, and `expires_at` is `None` for a key that never expires.

Limits:

- When you set "requests per minute for each person's keys" on the API, the
  SDK enforces it across all of a person's keys, so making more keys doesn't
  raise anyone's limit. A quiet person can use the whole minute's worth at
  once, then gets one request every 60 / limit seconds. A caller over it
  gets `429` with `Retry-After`. Access tokens don't count toward it.
- After 20 unknown, revoked or mistyped keys from one client address in a
  minute, that address gets `429` without MicroAuth being asked, so your API
  can't be used to test stolen or guessed keys. Change the number with
  `unknown_key_limit`, or set it to 0 to turn this off.
- The client address is the connection's peer address. Behind a proxy, pass
  `client_address=` a function that takes the request and returns the real
  address, read from a header only your proxy sets.
- With several workers, set `MICROAUTH_REDIS_URL` (or pass `redis_url=` or
  `redis_client=`) and every worker shares the cached answers and both
  limits. Each limit decision is one Lua script call and every key has a
  TTL. If Redis goes down, answers are fetched from MicroAuth instead, but
  limits can't be checked, so callers with keys get `503` unless both
  limits are off.

MCP servers take the same settings with `McpAuth(api_keys=True)`, using the
MCP server's own server credentials: in the dashboard, open APIs and MCP
servers, then the server, then Server credentials. Without them `McpAuth`
refuses to start and its error says where to find them. A key's
permissions act as its scopes, so per tool scopes apply to keys too, and
`current_identity().via` is `"api_key"`. The MCP SDK's `AccessToken` gets the
key's id as its `client_id`. `MicroAuthTokenVerifier(api_keys=True)` accepts
keys as well, but the MCP SDK hands it only the token, so neither limit
applies there. Use `McpAuth` when you need them.

Settings for keys, with their defaults in brackets:

- `api_keys` (`False`): accept keys.
- `resource_client_id` (`$MICROAUTH_RESOURCE_CLIENT_ID`) and
  `resource_secret` (`$MICROAUTH_RESOURCE_SECRET`): the server credentials.
  Pass both or neither. Passing only one is refused at startup.
- `stale_if_error` (`600`): seconds an active key outlives its cached answer
  during an outage.
- `unknown_key_limit` (`20`): unknown keys one address may send per minute.
- `client_address` (the peer address): a function of the request.
- `redis_url` (`$MICROAUTH_REDIS_URL`) and `redis_client` (`None`): share
  answers and limits between workers. A client you pass is never closed.

## One route for sessions and keys

A CMS's own pages and its users' scripts often need the same API.
`TokenAuth(sessions=auth)` lets one route accept a browser signed in with
`UserAuth` along with access tokens and keys:

```python
from fastapi import Depends, FastAPI
from microauth_fastapi import TokenAuth, TokenClaims, UserAuth

app = FastAPI()
auth = UserAuth(app)
api = TokenAuth(app, api_keys=True, sessions=auth)


@app.post("/api/posts")
async def create_post(caller: TokenClaims = Depends(api.require("posts:write"))): ...
```

- A request without an `Authorization` header and with a valid session is a
  caller with `via="session"`. `sub` is the user's id and `scopes` are their
  permissions, so `require("posts:write")` checks the same permission for
  everyone.
- A request with an `Authorization` header is judged by that header alone,
  even when it also carries the session cookie.
- Unsafe requests that use the session must come from your own origin, as
  with `UserAuth`.
- Permissions come with the `roles` scope, so `UserAuth` must ask for it (it
  does by default), and both must use the same issuer.

## Let people manage their keys from your app

People can always manage their keys on MicroAuth's account page. To offer
the same in your app, turn on `api_keys` in `UserAuth`:

```python
import html

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from microauth_fastapi import ReauthenticationRequired, User, UserAuth

app = FastAPI()
auth = UserAuth(app, api_keys=True)


@app.post("/settings/api-keys")
async def create_key(request: Request, user: User = Depends(auth.login_required)):
    try:
        new = await auth.api_keys.create(
            request,
            name="CI deploys",
            resources=["https://api.example.com"],
            permissions=["posts:write"],
            expires_in_days=90,
        )
    except ReauthenticationRequired as exc:
        return RedirectResponse(exc.login_url, status_code=303)
    return HTMLResponse(
        f"<p>Copy your key now, it won't be shown again:</p><pre>{html.escape(new.secret)}</pre>",
        headers={"Cache-Control": "no-store"},
    )
```

`UserAuth(api_keys=True)` asks for the reserved `microauth:api_keys` scope and
keeps the access token in the session. `auth.api_keys` calls MicroAuth's
Account API with that token, so your app can only ever touch the signed in
person's keys. Only web applications can get the scope, and it can't be
combined with `resource=`. Sessions from before you turned it on didn't ask
for the scope, so the helpers raise `ReauthenticationRequired` for them.

Every method takes the request and acts for whoever is signed in on it:

- `options(request)`: the servers, permissions and lifetimes this person may
  put on a key, as `APIKeyOptions`.
- `list(request)`: their keys as `APIKey` objects, without secrets.
- `create(request, name=..., resources=[...], permissions=[...],
  expires_in_days=...)`: a `NewAPIKey` with the key and its secret.
  `resources` are server identifiers and `permissions` permission names,
  both from `options()`. `expires_in_days=None` asks for a key that never
  expires, which you may not allow.
- `rename(request, key_id, name)`: the renamed `APIKey`.
- `roll(request, key_id, old_secret_lasts_hours=0)`: a new secret with the
  same settings. The old one keeps working for 0, 1 or 24 hours, so a CI job
  can switch over without downtime.
- `revoke(request, key_id)` and `revoke_all(request)`.

The secret is shown once, in `NewAPIKey.secret`. MicroAuth keeps only its
hash, so show it to the person right away, send that page with
`Cache-Control: no-store`, and never store or log it. Call the helpers from
routes on your own site: unsafe requests pass the same origin check as
everything else that uses the session.

When something goes wrong:

- Creating and rolling a key needs a sign in from the last 10 minutes. When
  it is older, MicroAuth answers with RFC 9470
  `insufficient_user_authentication` and the helper raises
  `ReauthenticationRequired`. Its `login_url` signs the person in again with
  `max_age` and brings them back to the page they were on. Left unhandled,
  it becomes a `401` problem JSON response that carries `login_url`.
- Nobody signed in, or a session MicroAuth no longer accepts, raises
  `SignInRequired`, and a stale session is cleared.
- A refusal, such as an unknown key id, a name that's too long or a
  permission the person can't give, raises `AccountAPIError` with
  `status_code`, `detail` and `errors`, one per problem field. `detail` is
  written to be shown to the person as it is: one or more full sentences,
  such as `posts:delete can't be given to a key for Blog MCP server.
  Expected number <= 365.`
- When MicroAuth can't be reached, or fails with a `5xx` of its own, the
  helper raises `AccountAPIUnavailable`, a subclass of `AccountAPIError`
  with `status_code` 503 and the `detail` `API keys can't be managed right
  now. Please try again in a moment.` Its `upstream_status` is the status
  MicroAuth answered, or `None` when it couldn't be reached. The SDK logs a
  warning with the reason. Catch it before `AccountAPIError` if you want to
  treat outages differently.
- When MicroAuth won't let this app manage keys at all, the helper raises
  `MicroAuthConfigurationError`.

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
import logging

from fastapi import FastAPI
from microauth_fastapi import MicroAuth, UsageReceipt, UsageRejection

logger = logging.getLogger("billing")
LEDGER: dict[str, UsageReceipt] = {}  # your database


async def keep_receipts(receipts: list[UsageReceipt]) -> None:
    for receipt in receipts:
        LEDGER[receipt.idempotency_key] = receipt


async def flag_rejections(rejections: list[UsageRejection]) -> None:
    for rejection in rejections:
        logger.error("MicroAuth refused %d request(s): %s", rejection.count, rejection.detail)


app = FastAPI()
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
from fastapi import FastAPI
from microauth_fastapi import MicroAuth

app = FastAPI()
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
from fastapi import FastAPI
from microauth_fastapi import MicroAuth

app = FastAPI()
auth = MicroAuth(app, redis_url="redis://localhost:6379/0", redis_max_connections=10)
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
from fastapi import FastAPI, Security
from microauth_fastapi import Customer, MicroAuth

app = FastAPI()
auth = MicroAuth(app)


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
| `429` | `Monthly request quota exceeded. It resets on 2026-11-01 at 00:00 UTC` | The customer used their monthly request quota, which resets at the end of the calendar month in UTC. `Retry-After` is the seconds until then | Wait for the reset, or upgrade the plan |
| `429` | `Platform monthly request allowance exhausted. It resets on 2026-11-01 at 00:00 UTC` | Your MicroAuth plan's monthly allowance is used up, or the API is paused. `Retry-After` is the seconds until the month resets, though a paused API stays paused | Upgrade your MicroAuth plan |
| `503` | `Authorization is temporarily unavailable` | Snapshot too stale, Redis down while enforcing shared limits, or usage queue full | Check connectivity to MicroAuth and Redis. Run `python -m microauth_fastapi check` |

Customers never see your MicroAuth secret or internal state in these
messages. Server logs under the `microauth` logger explain every `503`.

All request denials subclass `microauth_fastapi.AuthDenied` (itself a
FastAPI `HTTPException`), so you can add your own exception handler to
reshape response bodies:

```python
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from microauth_fastapi import AuthDenied, MicroAuth, PaymentRequired

app = FastAPI()
auth = MicroAuth(app)


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
signing keys, the introspection endpoint for API keys, and for `UserAuth`
the pushed authorization, token, revocation and end session endpoints. The
discovery document is cached for an hour and must name exactly the issuer
you configured. `auth.api_keys` also calls the Account API at
`/api/v1/me/api-keys` on your issuer.

MicroAuth generates golden fixtures of each response from its own types. The
SDK's tests parse copies of them in `tests/contract`, and compare them byte
for byte with the originals when both repositories are checked out side by
side. The API key fixtures there (`introspect_*.json` and `account_*.json`)
are the reference for what MicroAuth answers about keys.

## Example apps

See [`examples/weather_api.py`](https://github.com/Zyref-Org/microauth-sdk-fastapi/blob/main/examples/weather_api.py):

```bash
MICROAUTH_SECRET_KEY=mas_... uvicorn examples.weather_api:app --reload
```

[`examples/blog_cms.py`](https://github.com/Zyref-Org/microauth-sdk-fastapi/blob/main/examples/blog_cms.py)
signs people in with `UserAuth`: anyone reads posts, editors write them and
admins delete them. Its `/api/posts` takes the editor page's session and API
keys alike, and `/settings/api-keys` lets people make keys with
`auth.api_keys`.
[`examples/invoices_mcp.py`](https://github.com/Zyref-Org/microauth-sdk-fastapi/blob/main/examples/invoices_mcp.py)
is an MCP server mounted in a FastAPI app, with a scope per tool and an
ownership check in each one, and it takes API keys too.
[`examples/api_and_mcp.py`](https://github.com/Zyref-Org/microauth-sdk-fastapi/blob/main/examples/api_and_mcp.py)
serves an API and an MCP server from one app, each its own resource with
its own server credentials. Their docstrings say how to set them up.
