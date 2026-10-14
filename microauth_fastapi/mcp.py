"""Protect a remote MCP server with MicroAuth access tokens.

Quickstart::

    from fastapi import FastAPI
    from mcp.server.mcpserver import MCPServer
    from microauth_fastapi import McpAuth, current_identity

    mcp = MCPServer("Invoices", log_level="WARNING")
    auth = McpAuth(scopes=["invoices:read"])  # MICROAUTH_ISSUER and MICROAUTH_RESOURCE

    @mcp.tool()
    @auth.tool("invoices:read")
    async def list_invoices() -> list[dict]:
        return invoices_owned_by(current_identity().sub)

    app = FastAPI()
    auth.mount(app, mcp)

This follows the MCP 2026-07-28 authorization spec. The protected server is
an OAuth resource server: it publishes protected resource metadata (RFC 9728)
at the well-known URL for its resource, answers requests without a valid
token with ``401`` and a challenge that tells the client where to get one,
and checks every request against ``scopes`` and every ``tools/call`` against
the scopes declared for that tool. A token that is missing one gets ``403``
with ``error="insufficient_scope"`` and every scope the request needs, so
the client can step up in one round trip.

Scopes only say what kind of thing a client may do. Whether this user may
touch this record is still your code's call: read ``current_identity().sub``
inside the tool and check ownership there.

Clients that can't do OAuth can send an API key their user made instead,
with ``McpAuth(api_keys=True)``. The key's permissions act as its scopes, so
per tool scopes apply to it the same way.
"""

from __future__ import annotations

import base64
import binascii
import functools
import json
import logging
import math
import re
from collections.abc import AsyncIterator, Callable, Iterable, Mapping
from contextlib import asynccontextmanager
from contextvars import ContextVar
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, TypeVar
from urllib.parse import urlsplit

import httpx
from starlette.authentication import AuthCredentials
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.routing import Route

from ._env import getenv
from ._keys import DEFAULT_STALE_IF_ERROR, DEFAULT_UNKNOWN_KEY_LIMIT, KeyCheckUnavailable
from ._limits import RequestThrottled
from ._oidc import (
    LEEWAY_SECONDS,
    OUTAGE_RETRY_AFTER,
    TokenRejected,
    validate_issuer,
    validate_resource,
)
from .exceptions import MicroAuthConfigurationError, MicroAuthError
from .tokens import (
    ClientAddress,
    TokenClaims,
    Via,
    bearer_challenge,
    bearer_token,
    bearer_verifier,
    metadata_document,
    metadata_path,
    metadata_url,
    normalize_scopes,
)

if TYPE_CHECKING:
    from mcp.server.auth.provider import AccessToken

logger = logging.getLogger("microauth")

F = TypeVar("F", bound=Callable[..., Any])

DEFAULT_MAX_BODY_SIZE = 4 * 1024 * 1024
_MAX_WARNED_TOOLS = 100
_PARSE_ERROR = -32700
_INVALID_REQUEST = -32600
_INVALID_PARAMS = -32602
_HEADER_MISMATCH = -32020
# MCP 2026-07-28 asks for codes outside the JSON-RPC reserved range when the
# spec defines none, and it defines none for a missing scope.
_INSUFFICIENT_SCOPE = 403
# RFC 6750 error_description allows no quotes or backslashes, and the MCP
# spec's own tool names are 1 to 128 of these characters.
_SAFE_TOOL_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_NO_MESSAGE = object()

_identity: ContextVar[TokenClaims | None] = ContextVar("microauth_mcp_identity", default=None)


def current_identity() -> TokenClaims:
    """Who is calling, inside a tool (or any handler) behind ``McpAuth``.

    Raises ``LookupError`` outside a request that McpAuth let through.
    """
    claims = _identity.get()
    if claims is None:
        raise LookupError("current_identity() only works inside a request McpAuth let through")
    return claims


@functools.lru_cache(maxsize=1)
def _mcp_auth_types() -> tuple[Any, Any, Any] | None:
    """The MCP SDK's AccessToken, AuthenticatedUser and AuthContextMiddleware.

    Imported lazily so the core install doesn't need the MCP SDK.
    """
    try:
        from mcp.server.auth.middleware.auth_context import AuthContextMiddleware
        from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
        from mcp.server.auth.provider import AccessToken
    except ImportError:
        return None
    return AccessToken, AuthenticatedUser, AuthContextMiddleware


def _mcp_access_token(cls: Any, token: str, claims: TokenClaims, resource: str) -> Any:
    fields = getattr(cls, "model_fields", {})
    values: dict[str, Any] = {
        "token": token,
        # The MCP SDK requires a client_id and binds sessions to it. An API key
        # has no OAuth client, so the key's id stands in.
        "client_id": claims.client_id if claims.client_id is not None else claims.key_id,
        "scopes": sorted(claims.scopes),
        "expires_at": claims.expires_at,
        "resource": resource,
    }
    # Newer MCP SDKs bind sessions and request state to the user with these.
    if "subject" in fields:
        values["subject"] = claims.sub
    if "claims" in fields:
        values["claims"] = dict(claims.claims)
    return cls(**values)


class _ClientGone(Exception):
    pass


class _Reject(Exception):
    """A response McpAuth sends itself instead of calling the MCP server."""

    def __init__(
        self, status: int, body: dict[str, Any], headers: Iterable[tuple[str, str]] = ()
    ) -> None:
        super().__init__(status)
        self.status = status
        self.body = body
        self.headers = list(headers)


def _rpc_error(
    request_id: Any, code: int, message: str, data: dict[str, Any] | None = None
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _missing_scopes_detail(what: str, missing: Iterable[str], via: Via) -> str:
    """A sentence, without the final period, naming the scopes a caller lacks."""
    names = sorted(missing)
    word = "permission" if via == "api_key" else "scope"
    credential = "API key" if via == "api_key" else "access token"
    if len(names) == 1:
        return f"{what} needs the {names[0]} {word}, and this {credential} doesn't have it"
    listed = ", ".join(names[:-1]) + " and " + names[-1]
    return f"{what} needs the {listed} {word}s, and this {credential} doesn't have them"


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # Two parsers that disagree about a duplicated key would let a message
    # pass the scope check as one method and run as another.
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _decode_header_value(value: str) -> str | None:
    if value.startswith("=?base64?") and value.endswith("?="):
        try:
            return base64.b64decode(value[9:-2], validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return None
    return value


async def _read_body(receive: Any, limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            raise _ClientGone()
        if message["type"] != "http.request":
            continue
        chunk = message.get("body", b"")
        size += len(chunk)
        if size > limit:
            raise _Reject(
                413,
                {"error": "invalid_request", "error_description": "The request body is too large"},
            )
        chunks.append(chunk)
        if not message.get("more_body", False):
            return b"".join(chunks)


def _replay(body: bytes, receive: Any) -> Callable[[], Any]:
    """A ``receive`` that hands the already read body to the wrapped app."""
    sent = False

    async def replay() -> dict[str, Any]:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        message: dict[str, Any] = await receive()
        return message

    return replay


async def _send_json(
    send: Any, status: int, body: dict[str, Any] | None, headers: Iterable[tuple[str, str]] = ()
) -> None:
    data = json.dumps(body).encode("utf-8") if body is not None else b""
    raw_headers = [
        (name.lower().encode("latin-1"), value.encode("latin-1")) for name, value in headers
    ]
    if body is not None:
        raw_headers.append((b"content-type", b"application/json"))
    raw_headers.append((b"content-length", str(len(data)).encode("ascii")))
    await send({"type": "http.response.start", "status": status, "headers": raw_headers})
    await send({"type": "http.response.body", "body": data})


class McpAuth:
    """Access token checks and per tool scopes for a Streamable HTTP MCP server.

    Args:
        issuer: Your MicroAuth service's issuer, such as
            ``https://auth.example.com``. Defaults to ``MICROAUTH_ISSUER``.
        resource: The MCP server's canonical URL exactly as registered in
            MicroAuth, such as ``https://app.example.com/mcp``. Defaults to
            ``MICROAUTH_RESOURCE``.
        scopes: Scopes every request needs. They are also what the ``401``
            challenge asks clients for first.
        scopes_supported: Scopes listed in the protected resource metadata,
            meant as the minimum for basic use. Defaults to ``scopes``.
        tool_scopes: Scopes per tool name, as an alternative to the
            ``@auth.tool(...)`` decorator.
        api_keys: Also accept API keys your users made for their accounts.
            Needs the server's credentials. Default False.
        resource_client_id: This MCP server's server credential ID, for
            checking keys. Pass it with ``resource_secret`` when one app
            protects more than one resource. Defaults to
            ``MICROAUTH_RESOURCE_CLIENT_ID``.
        resource_secret: This MCP server's server credential secret.
            Defaults to ``MICROAUTH_RESOURCE_SECRET``.
        stale_if_error: Seconds an active key keeps working past its cached
            answer when MicroAuth can't be reached. 0 turns it off.
            Default 600.
        unknown_key_limit: Unknown, revoked or mistyped keys one client
            address may send per minute before it gets ``429``. 0 turns it
            off. Default 20.
        client_address: A function that takes the request and returns the
            caller's address, for servers behind a proxy. Defaults to the
            connection's peer address.
        redis_url: Keep key answers and limits in Redis, shared by every
            worker. Defaults to ``MICROAUTH_REDIS_URL``.
        redis_client: Optional externally owned ``redis.asyncio`` client.
        leeway: Seconds of clock skew allowed on token times. Default 60.
        timeout: HTTP timeout for calls to MicroAuth. Default 10.
        jwks_refresh_interval: Seconds between scheduled refreshes of the
            signing keys. Default 900.
        max_body_size: Largest request body accepted, in bytes. Default 4 MiB.
        http_client: Optional externally owned ``httpx.AsyncClient``.
    """

    def __init__(
        self,
        *,
        issuer: str | None = None,
        resource: str | None = None,
        scopes: str | Iterable[str] | None = None,
        scopes_supported: Iterable[str] | None = None,
        tool_scopes: Mapping[str, str | Iterable[str]] | None = None,
        api_keys: bool = False,
        resource_client_id: str | None = None,
        resource_secret: str | None = None,
        stale_if_error: float = DEFAULT_STALE_IF_ERROR,
        unknown_key_limit: int = DEFAULT_UNKNOWN_KEY_LIMIT,
        client_address: ClientAddress | None = None,
        redis_url: str | None = None,
        redis_client: Any | None = None,
        leeway: float = LEEWAY_SECONDS,
        timeout: float = 10.0,
        jwks_refresh_interval: float = 900.0,
        max_body_size: int = DEFAULT_MAX_BODY_SIZE,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.issuer = validate_issuer(issuer or getenv("MICROAUTH_ISSUER"))
        self.resource = validate_resource(resource or getenv("MICROAUTH_RESOURCE"))
        self.required_scopes = normalize_scopes(scopes, "scopes")
        self._scopes_supported = (
            None
            if scopes_supported is None
            else normalize_scopes(scopes_supported, "scopes_supported")
        )
        if type(max_body_size) is not int or max_body_size < 1024:
            raise MicroAuthConfigurationError("max_body_size must be at least 1024 bytes")
        self.max_body_size = max_body_size
        self._tools: dict[str, frozenset[str]] = {}
        for name, needed in (tool_scopes or {}).items():
            self._add_tool(name, normalize_scopes(needed, f"tool_scopes[{name!r}]"))
        if client_address is not None and not callable(client_address):
            raise MicroAuthConfigurationError("client_address must be a function of the request")
        self._client_address = client_address
        self.metadata_url = metadata_url(self.resource)
        self._metadata_path = metadata_path(self.resource)
        self._bearer = bearer_verifier(
            issuer=self.issuer,
            resource=self.resource,
            leeway=leeway,
            timeout=timeout,
            jwks_refresh_interval=jwks_refresh_interval,
            http_client=http_client,
            api_keys=api_keys,
            resource_client_id=resource_client_id,
            resource_secret=resource_secret,
            stale_if_error=stale_if_error,
            unknown_key_limit=unknown_key_limit,
            redis_url=redis_url,
            redis_client=redis_client,
        )
        self.verifier = self._bearer.access
        self.key_checks = self._bearer.keys
        what = "a MicroAuth access token or API key" if api_keys else "a MicroAuth access token"
        self._missing = f"Send {what} in the Authorization header"
        self._warned: set[str] = set()

    # Config

    def tool(self, *scopes: str, name: str | None = None) -> Callable[[F], F]:
        """Declare the scopes a tool needs. The name defaults to the function's.

        Stack it with your MCP server's tool decorator; it returns the
        function unchanged. Pass ``name=`` when the tool is registered under
        a different name.
        """
        if len(scopes) == 1 and callable(scopes[0]):
            raise TypeError("Use @auth.tool('scope:name'), with parentheses and the scopes")
        needed = normalize_scopes(scopes, "@auth.tool()")

        def decorator(fn: F) -> F:
            tool_name = name or getattr(fn, "__name__", None)
            if not isinstance(tool_name, str) or not tool_name:
                raise MicroAuthConfigurationError("Pass name= for a tool without a __name__")
            self._add_tool(tool_name, needed)
            return fn

        return decorator

    def _add_tool(self, name: str, needed: frozenset[str]) -> None:
        if not isinstance(name, str) or not name:
            raise MicroAuthConfigurationError("Tool names must be non empty strings")
        self._tools[name] = self._tools.get(name, frozenset()) | needed

    @property
    def tool_scopes(self) -> Mapping[str, frozenset[str]]:
        """The scopes declared for each tool, not counting ``scopes``."""
        return MappingProxyType(dict(self._tools))

    def scopes_for(self, tool: str) -> frozenset[str]:
        """Every scope a call to ``tool`` needs."""
        return self.required_scopes | self._tools.get(tool, frozenset())

    @property
    def scopes_supported(self) -> frozenset[str]:
        if self._scopes_supported is not None:
            return self._scopes_supported
        return self.required_scopes

    def metadata(self) -> dict[str, Any]:
        """The MCP server's protected resource metadata document (RFC 9728)."""
        return metadata_document(self.resource, self.issuer, self.scopes_supported)

    def wrap(self, app: Any) -> Callable[..., Any]:
        """The MCP ASGI app, protected, for an MCP server that is the whole site.

        Serve the result at the root of the host. To add the MCP server to an
        app that has other routes, use ``mount()``.
        """
        types = _mcp_auth_types()
        inner = types[2](app) if types is not None else app
        return _ProtectedApp(self, inner)

    def mount(self, app: Any, server: Any, *, path: str | None = None) -> None:
        """Serve a protected MCP server inside your FastAPI or Starlette app.

        Adds the MCP endpoint at ``path`` and the protected resource metadata
        at its well-known URL, starts and stops the MCP server with your app,
        and closes this instance at shutdown. Your app's other routes and its
        own lifespan keep working. Call it before the app starts::

            mcp = MCPServer("Invoices", log_level="WARNING")
            auth = McpAuth(scopes=["invoices:read"])
            app = FastAPI()
            auth.mount(app, mcp)

        Args:
            app: Your FastAPI or Starlette app.
            server: An ``MCPServer``, which is served statelessly with JSON
                responses and accepts only the Host and Origin of
                ``resource``, or the app its ``streamable_http_app()``
                returns when you want other transport settings. Build that
                app with ``streamable_http_path`` set to ``path``.
            path: Where the MCP endpoint lives. Defaults to the path of
                ``resource``, or ``/mcp`` when the resource has none.
        """
        if path is None:
            path = urlsplit(self.resource).path.rstrip("/") or "/mcp"
        if not isinstance(path, str) or not path.startswith("/") or path == "/":
            raise MicroAuthConfigurationError(
                "mount() needs a path below the root, such as '/mcp'. Use wrap() to serve "
                "the MCP server as the whole site."
            )
        router: Any = getattr(app, "router", None)
        if not isinstance(getattr(router, "routes", None), list) or not hasattr(
            router, "lifespan_context"
        ):
            raise MicroAuthConfigurationError("mount() needs a FastAPI or Starlette app")
        if callable(getattr(server, "streamable_http_app", None)):
            from mcp.server.transport_security import TransportSecuritySettings

            # Without settings the MCP SDK accepts only localhost Host headers.
            public = urlsplit(self.resource)
            server = server.streamable_http_app(
                streamable_http_path=path,
                stateless_http=True,
                json_response=True,
                transport_security=TransportSecuritySettings(
                    allowed_hosts=[public.netloc],
                    allowed_origins=[f"{public.scheme}://{public.netloc}"],
                ),
            )
        server_lifespan = getattr(getattr(server, "router", None), "lifespan_context", None)
        if server_lifespan is None:
            raise MicroAuthConfigurationError(
                "mount() takes an MCPServer, or the app its streamable_http_app() returns"
            )
        served = [getattr(route, "path", None) for route in server.router.routes]
        if path not in served:
            raise MicroAuthConfigurationError(
                f"The MCP app doesn't answer at {path}. Build it with "
                f"streamable_http_app(streamable_http_path={path!r}), or pass the MCPServer "
                "itself."
            )
        router.routes.append(Route(path, self.wrap(server), include_in_schema=False))
        router.routes.append(
            Route(self._metadata_path, _MetadataApp(self), include_in_schema=False)
        )
        app_lifespan = router.lifespan_context

        @asynccontextmanager
        async def lifespan(host: Any) -> AsyncIterator[Any]:
            try:
                async with app_lifespan(host) as state, server_lifespan(server):
                    yield state
            finally:
                await self._close_quietly()

        router.lifespan_context = lifespan

    async def _close_quietly(self) -> None:
        try:
            await self.aclose()
        except Exception:
            logger.exception("microauth: closing McpAuth at shutdown failed")

    async def aclose(self) -> None:
        """Close the HTTP and Redis clients this instance created and empty
        its key caches. Idempotent; runs when the wrapped app shuts down."""
        await self._bearer.aclose()

    # Serving

    async def serve(self, app: Any, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
                return
            if scope["type"] == "lifespan":
                send = self._closing_on_shutdown(send)
            await app(scope, receive, send)
            return
        method = scope["method"]
        if scope["path"] == self._metadata_path:
            await self._serve_metadata(method, send)
            return
        if method == "OPTIONS":
            # CORS preflights carry no credentials and run nothing.
            await app(scope, receive, send)
            return
        try:
            token, claims = await self._authenticate(scope)
            if method == "POST":
                body = await _read_body(receive, self.max_body_size)
                self._check_message(body, Headers(scope=scope), claims)
                receive = _replay(body, receive)
            elif not self.required_scopes <= claims.scopes:
                raise self._forbidden(_NO_MESSAGE, self.required_scopes, "This MCP server", claims)
        except _Reject as reject:
            await _send_json(send, reject.status, reject.body, reject.headers)
            return
        except _ClientGone:
            return
        scope["auth"] = AuthCredentials(sorted(claims.scopes))
        types = _mcp_auth_types()
        if types is not None:
            access_token = _mcp_access_token(types[0], token, claims, self.resource)
            scope["user"] = types[1](access_token)
        context = _identity.set(claims)
        try:
            await app(scope, receive, send)
        finally:
            _identity.reset(context)

    def _closing_on_shutdown(self, send: Any) -> Callable[[dict[str, Any]], Any]:
        async def lifespan_send(message: dict[str, Any]) -> None:
            if message["type"] == "lifespan.shutdown.complete":
                await self._close_quietly()
            await send(message)

        return lifespan_send

    async def _serve_metadata(self, method: str, send: Any) -> None:
        cors = [("Access-Control-Allow-Origin", "*")]
        if method in ("GET", "HEAD"):
            body = self.metadata()
            headers = [*cors, ("Cache-Control", "public, max-age=300")]
            if method == "HEAD":
                await _send_json(send, 200, None, [*headers, ("Content-Type", "application/json")])
            else:
                await _send_json(send, 200, body, headers)
        elif method == "OPTIONS":
            await _send_json(
                send,
                204,
                None,
                [
                    *cors,
                    ("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS"),
                    ("Access-Control-Allow-Headers", "*"),
                    ("Access-Control-Max-Age", "86400"),
                ],
            )
        else:
            await _send_json(
                send,
                405,
                {"error": "method_not_allowed"},
                [("Allow", "GET, HEAD, OPTIONS")],
            )

    async def _authenticate(self, scope: dict[str, Any]) -> tuple[str, TokenClaims]:
        headers = Headers(scope=scope)
        try:
            token = bearer_token(headers.getlist("authorization"))
        except TokenRejected as exc:
            raise self._unauthorized(exc.reason) from None
        if token is None:
            raise self._unauthorized(None)
        try:
            return token, await self._bearer.verify(token, self._address(scope))
        except TokenRejected as exc:
            raise self._unauthorized(exc.reason) from None
        except RequestThrottled as exc:
            raise _Reject(
                429,
                {"error": "rate_limited", "error_description": exc.reason},
                [("Retry-After", str(max(1, math.ceil(exc.retry_after))))],
            ) from None
        except KeyCheckUnavailable:
            raise self._unavailable() from None
        except MicroAuthError as exc:
            logger.error("microauth: MCP access tokens can't be checked right now (%s)", exc)
            raise self._unavailable() from None

    def _address(self, scope: dict[str, Any]) -> str | None:
        if self._client_address is not None:
            return self._client_address(Request(scope))
        client = scope.get("client")
        return client[0] if client else None

    @staticmethod
    def _unavailable() -> _Reject:
        return _Reject(
            503,
            {
                "error": "temporarily_unavailable",
                "error_description": "Authorization is temporarily unavailable",
            },
            [("Retry-After", str(OUTAGE_RETRY_AFTER))],
        )

    def _unauthorized(self, reason: str | None) -> _Reject:
        challenge = bearer_challenge(
            error="invalid_token" if reason else None,
            error_description=reason,
            resource_metadata=self.metadata_url,
            scope=" ".join(sorted(self.scopes_supported)) or None,
        )
        return _Reject(
            401,
            {"error": "invalid_token", "error_description": reason or self._missing},
            [("WWW-Authenticate", challenge)],
        )

    def _check_message(self, body: bytes, headers: Headers, claims: TokenClaims) -> None:
        try:
            message = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_keys)
        except (UnicodeDecodeError, ValueError):
            raise _Reject(
                400,
                _rpc_error(None, _PARSE_ERROR, "Parse error: send one JSON-RPC message as JSON"),
            ) from None
        if isinstance(message, list):
            raise _Reject(
                400,
                _rpc_error(
                    None,
                    _INVALID_REQUEST,
                    "Batched JSON-RPC requests aren't supported. Send one request per POST.",
                ),
            )
        if not isinstance(message, dict):
            raise _Reject(400, _rpc_error(None, _INVALID_REQUEST, "Invalid Request"))
        method = message.get("method")
        request_id = message.get("id")
        method_header = headers.get("mcp-method")
        if method_header is not None and method_header != method:
            raise _Reject(
                400,
                _rpc_error(
                    request_id, _HEADER_MISMATCH, "Header mismatch: Mcp-Method doesn't match method"
                ),
            )
        if method != "tools/call":
            if not self.required_scopes <= claims.scopes:
                raise self._forbidden(request_id, self.required_scopes, "This MCP server", claims)
            return
        params = message.get("params")
        name = params.get("name") if isinstance(params, dict) else None
        if not isinstance(name, str) or not name:
            raise _Reject(
                400, _rpc_error(request_id, _INVALID_PARAMS, "tools/call needs params.name")
            )
        name_header = headers.get("mcp-name")
        if name_header is not None and _decode_header_value(name_header) != name:
            raise _Reject(
                400,
                _rpc_error(
                    request_id,
                    _HEADER_MISMATCH,
                    "Header mismatch: Mcp-Name doesn't match params.name",
                ),
            )
        if (
            name not in self._tools
            and name not in self._warned
            and len(self._warned) < _MAX_WARNED_TOOLS
        ):
            self._warned.add(name)
            logger.warning(
                "microauth: tool %r has no scopes declared with McpAuth, so any valid "
                "token can call it",
                name[:100],
            )
        needed = self.scopes_for(name)
        if not needed <= claims.scopes:
            what = f"The {name} tool" if _SAFE_TOOL_NAME.fullmatch(name) else "This tool"
            raise self._forbidden(request_id, needed, what, claims)

    def _forbidden(
        self, request_id: Any, needed: frozenset[str], what: str, claims: TokenClaims
    ) -> _Reject:
        """``403`` naming every scope the request needs, for the client to step up.

        With a ``request_id`` (any POST) the body is a JSON-RPC error, which
        is what MCP clients show the person.
        """
        scope = " ".join(sorted(needed))
        detail = _missing_scopes_detail(what, needed - claims.scopes, claims.via)
        challenge = bearer_challenge(
            error="insufficient_scope",
            scope=scope,
            resource_metadata=self.metadata_url,
            error_description=detail,
        )
        if request_id is _NO_MESSAGE:
            body = {"error": "insufficient_scope", "error_description": detail, "scope": scope}
        else:
            body = _rpc_error(
                request_id,
                _INSUFFICIENT_SCOPE,
                detail + ".",
                {"error": "insufficient_scope", "scope": scope},
            )
        return _Reject(403, body, [("WWW-Authenticate", challenge)])


class _ProtectedApp:
    """The ASGI app ``McpAuth.wrap()`` returns."""

    def __init__(self, auth: McpAuth, app: Any) -> None:
        self.auth = auth
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        await self.auth.serve(self.app, scope, receive, send)


class _MetadataApp:
    """The metadata route ``McpAuth.mount()`` adds."""

    def __init__(self, auth: McpAuth) -> None:
        self.auth = auth

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        await self.auth._serve_metadata(scope["method"], send)


class MicroAuthTokenVerifier:
    """A ``TokenVerifier`` for the official MCP Python SDK.

    For servers that use the SDK's own auth settings instead of ``McpAuth``::

        from mcp.server.auth.settings import AuthSettings
        from mcp.server.mcpserver import MCPServer
        from microauth_fastapi import MicroAuthTokenVerifier

        mcp = MCPServer(
            "Invoices",
            token_verifier=MicroAuthTokenVerifier(),
            auth=AuthSettings(
                issuer_url="https://auth.example.com",
                resource_server_url="https://app.example.com/mcp",
                required_scopes=["invoices:read"],
                validate_token_resource=True,
            ),
        )

    Tokens are checked exactly like ``TokenAuth`` checks them. Required scopes
    are left to the SDK's settings so a missing scope stays a ``403``.

    With ``api_keys=True`` it accepts your users' API keys too. The MCP SDK
    hands a verifier only the token, never the request, and can only answer
    ``401``. So MicroAuth's per person requests per minute limit and the
    unknown key throttle don't apply here, and when MicroAuth can't be
    reached the client gets ``401`` rather than ``503``. ``McpAuth``
    enforces both limits with ``429`` and ``Retry-After``; use it when you
    accept keys.

    Args:
        issuer: Defaults to ``MICROAUTH_ISSUER``.
        resource: The MCP server's URL. Defaults to ``MICROAUTH_RESOURCE``.
        api_keys: Also accept API keys. Default False.
        resource_client_id: Defaults to ``MICROAUTH_RESOURCE_CLIENT_ID``.
        resource_secret: Defaults to ``MICROAUTH_RESOURCE_SECRET``.
        stale_if_error: Seconds an active key keeps working past its cached
            answer when MicroAuth can't be reached. Default 600.
        redis_url: Keep key answers in Redis. Defaults to
            ``MICROAUTH_REDIS_URL``.
        redis_client: Optional externally owned ``redis.asyncio`` client.
        leeway: Seconds of clock skew allowed on token times. Default 60.
        timeout: HTTP timeout for calls to MicroAuth. Default 10.
        jwks_refresh_interval: Seconds between scheduled key refreshes.
        http_client: Optional externally owned ``httpx.AsyncClient``.
    """

    def __init__(
        self,
        *,
        issuer: str | None = None,
        resource: str | None = None,
        api_keys: bool = False,
        resource_client_id: str | None = None,
        resource_secret: str | None = None,
        stale_if_error: float = DEFAULT_STALE_IF_ERROR,
        redis_url: str | None = None,
        redis_client: Any | None = None,
        leeway: float = LEEWAY_SECONDS,
        timeout: float = 10.0,
        jwks_refresh_interval: float = 900.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        types = _mcp_auth_types()
        if types is None:
            raise MicroAuthConfigurationError(
                "MicroAuthTokenVerifier needs the MCP SDK. Install it with "
                "pip install 'microauth-fastapi[mcp]'."
            )
        self._access_token_class = types[0]
        self.issuer = validate_issuer(issuer or getenv("MICROAUTH_ISSUER"))
        self.resource = validate_resource(resource or getenv("MICROAUTH_RESOURCE"))
        self._bearer = bearer_verifier(
            issuer=self.issuer,
            resource=self.resource,
            leeway=leeway,
            timeout=timeout,
            jwks_refresh_interval=jwks_refresh_interval,
            http_client=http_client,
            api_keys=api_keys,
            resource_client_id=resource_client_id,
            resource_secret=resource_secret,
            stale_if_error=stale_if_error,
            unknown_key_limit=0,
            redis_url=redis_url,
            redis_client=redis_client,
            enforce_limits=False,
        )
        self.verifier = self._bearer.access
        self.key_checks = self._bearer.keys

    async def verify_token(self, token: str) -> AccessToken | None:
        """The SDK's ``AccessToken`` for a valid token or key, otherwise None."""
        try:
            claims = await self._bearer.verify(token, None)
        except TokenRejected as exc:
            logger.debug("microauth: refused an MCP bearer credential (%s)", exc.reason)
            return None
        except KeyCheckUnavailable:
            return None
        except MicroAuthError as exc:
            logger.error("microauth: MCP access tokens can't be checked right now (%s)", exc)
            return None
        access_token: AccessToken = _mcp_access_token(
            self._access_token_class, token, claims, self.resource
        )
        return access_token

    async def aclose(self) -> None:
        """Close the HTTP and Redis clients this instance created. Idempotent."""
        await self._bearer.aclose()
