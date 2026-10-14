"""Protect an API with MicroAuth access tokens, your users' API keys and
browser sessions.

Quickstart::

    from fastapi import Depends, FastAPI
    from microauth_fastapi import TokenAuth, TokenClaims

    app = FastAPI()
    api = TokenAuth(app)  # MICROAUTH_ISSUER and MICROAUTH_RESOURCE

    @app.get("/posts")
    async def posts(token: TokenClaims = Depends(api.require("posts:read"))):
        return {"user": token.sub}

Access tokens are RS256 JWTs (RFC 9068) that MicroAuth issues for one
resource, named in their ``aud``. A token minted for another API or MCP server
is refused here even when it comes from the same issuer, which is what keeps a
token leaked from one service from opening another.

With ``api_keys=True`` the same routes also accept API keys that people made
for their own accounts. A bearer value without dots is a key, checked with
token introspection (RFC 7662) and cached. With ``sessions=auth`` they also
accept a browser signed in with ``UserAuth``, so one API serves both your web
UI and scripts.

Failures follow RFC 6750: ``401`` with a ``WWW-Authenticate: Bearer``
challenge naming the protected resource metadata (RFC 9728), and ``403`` with
``error="insufficient_scope"`` listing every scope the route needs.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Request, Security
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer

from ._env import getenv
from ._keys import (
    DEFAULT_STALE_IF_ERROR,
    DEFAULT_UNKNOWN_KEY_LIMIT,
    KeyAnswer,
    KeyChecks,
    KeyCheckUnavailable,
    is_key_candidate,
)
from ._lifespan import CloseOnShutdown
from ._limits import RequestThrottled
from ._oidc import (
    LEEWAY_SECONDS,
    HttpClient,
    Issuer,
    TokenRejected,
    validate_issuer,
    validate_resource,
    verify_jwt,
)
from ._problem import TOKEN_DENIALS, install_handlers
from .exceptions import (
    AuthUnavailable,
    InsufficientScope,
    InvalidToken,
    MicroAuthConfigurationError,
    MicroAuthError,
    TooManyRequests,
)
from .login import UserAuth, user_from_claims

logger = logging.getLogger("microauth")

METADATA_PREFIX = "/.well-known/oauth-protected-resource"
ACCESS_TOKEN_TYPES = frozenset({"at+jwt", "application/at+jwt"})
_ACCESS_TOKEN_CLAIMS = ("iss", "sub", "aud", "exp", "iat", "client_id")

Via = Literal["access_token", "api_key", "session"]
ClientAddress = Callable[[Request], str | None]


@dataclass(frozen=True, slots=True)
class TokenClaims:
    """Who is calling, handed to your route by ``api.require(...)``.

    ``via`` says how the caller proved it: ``"access_token"`` for a MicroAuth
    access token, ``"api_key"`` for an API key one of your users made, and
    ``"session"`` for a browser signed in with ``UserAuth``. ``sub`` is the
    user in every case. ``scopes`` is what the caller may do: the token's
    scopes, the key's permissions or the signed in user's permissions.

    ``client_id`` is the app a token was issued to, and None for keys and
    sessions. ``expires_at`` is None for keys that never expire and for
    sessions, which the SDK refreshes as needed.
    """

    sub: str
    via: Via
    client_id: str | None
    scopes: frozenset[str]
    claims: Mapping[str, Any]
    issuer: str
    audience: tuple[str, ...]
    expires_at: int | None
    issued_at: int
    token_id: str | None = None
    session_id: str | None = None
    auth_time: int | None = None
    key_id: str | None = None

    def has_scope(self, *scopes: str) -> bool:
        """True when the caller holds every scope given."""
        return all(scope in self.scopes for scope in scopes)


def _is_scope_token(value: str) -> bool:
    # RFC 6749 section 3.3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
    return bool(value) and all(
        ch == "\x21" or "\x23" <= ch <= "\x5b" or "\x5d" <= ch <= "\x7e" for ch in value
    )


def normalize_scopes(value: str | Iterable[str] | None, what: str) -> frozenset[str]:
    """Scopes from a space separated string or an iterable of names."""
    if value is None:
        return frozenset()
    items = value.split() if isinstance(value, str) else list(value)
    scopes: set[str] = set()
    for item in items:
        if not isinstance(item, str) or not _is_scope_token(item):
            raise MicroAuthConfigurationError(
                f"{what} has an invalid scope {item!r}. Scopes are single words such as "
                "'posts:read', without spaces or quotes."
            )
        scopes.add(item)
    return frozenset(scopes)


def parse_scope_claim(value: Any) -> frozenset[str]:
    if not isinstance(value, str):
        return frozenset()
    return frozenset(value.split())


def metadata_path(resource: str) -> str:
    """Where RFC 9728 says the metadata of ``resource`` lives on its host."""
    path = urlsplit(resource).path
    return METADATA_PREFIX + (path if path != "/" else "")


def metadata_url(resource: str) -> str:
    parts = urlsplit(resource)
    return f"{parts.scheme}://{parts.netloc}{metadata_path(resource)}"


def metadata_document(
    resource: str, issuer: str, scopes_supported: Iterable[str] | None
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "resource": resource,
        "authorization_servers": [issuer],
        "bearer_methods_supported": ["header"],
    }
    if scopes_supported:
        document["scopes_supported"] = sorted(scopes_supported)
    return document


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def bearer_challenge(**params: str | None) -> str:
    """``Bearer k="v", ...`` with the parameters in the order given."""
    pairs = [f"{name}={_quote(value)}" for name, value in params.items() if value]
    return "Bearer " + ", ".join(pairs) if pairs else "Bearer"


def bearer_token(values: list[str]) -> str | None:
    """The token from ``Authorization: Bearer ...``, or None when there isn't one.

    Raises ``TokenRejected`` when the request sends more than one
    Authorization header, which RFC 6750 treats as a malformed request.
    """
    if not values:
        return None
    if len(values) > 1:
        raise TokenRejected("Send exactly one Authorization header")
    scheme, _, token = values[0].strip().partition(" ")
    if scheme.lower() != "bearer":
        return None
    token = token.strip()
    return token or None


def credential_name(via: Via) -> str:
    return {"access_token": "access token", "api_key": "API key", "session": "session"}[via]


def missing_scope_detail(via: Via, what: str = "request") -> str:
    if via == "session":
        return f"You don't have a permission this {what} needs"
    return f"The {credential_name(via)} is missing a scope this {what} needs"


def claims_from_key(answer: KeyAnswer) -> TokenClaims:
    return TokenClaims(
        sub=answer.sub,
        via="api_key",
        client_id=None,
        scopes=answer.scopes,
        claims=answer.claims,
        issuer=answer.issuer,
        audience=answer.audience,
        expires_at=answer.expires_at,
        issued_at=answer.issued_at,
        key_id=answer.key_id,
    )


def claims_from_session(claims: Mapping[str, Any], issuer: str) -> TokenClaims:
    """A signed in user as a caller, with their permissions as scopes."""
    user = user_from_claims(claims)
    aud = claims.get("aud")
    iat = claims.get("iat")
    if isinstance(aud, str):
        audience: tuple[str, ...] = (aud,)
    elif isinstance(aud, list):
        audience = tuple(item for item in aud if isinstance(item, str))
    else:
        audience = ()
    auth_time = claims.get("auth_time")
    return TokenClaims(
        sub=user.id,
        via="session",
        client_id=None,
        scopes=user.permissions,
        claims=user.claims,
        issuer=issuer,
        audience=audience,
        expires_at=None,
        issued_at=iat if type(iat) is int else 0,
        session_id=user.session_id,
        auth_time=auth_time if type(auth_time) is int else None,
    )


class AccessTokenVerifier:
    """Verifies MicroAuth access tokens for one resource.

    Shared by TokenAuth, McpAuth and MicroAuthTokenVerifier so all three apply
    exactly the same rules.
    """

    def __init__(
        self,
        issuer: str,
        resource: str,
        *,
        leeway: float = LEEWAY_SECONDS,
        timeout: float = 10.0,
        jwks_refresh_interval: float = 900.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if leeway < 0 or leeway > 300:
            raise MicroAuthConfigurationError("leeway must be between 0 and 300 seconds")
        if timeout <= 0:
            raise MicroAuthConfigurationError("timeout must be positive")
        if jwks_refresh_interval < 60:
            raise MicroAuthConfigurationError("jwks_refresh_interval must be at least 60 seconds")
        self.issuer = issuer
        self.resource = resource
        self.leeway = leeway
        self._http = HttpClient(http_client, timeout)
        self.keys = Issuer(
            issuer, self._http, timeout=timeout, jwks_refresh_interval=jwks_refresh_interval
        )

    async def verify(self, token: str) -> TokenClaims:
        """The verified claims, or ``TokenRejected`` saying why not.

        Raises ``MicroAuthError`` when the issuer's signing keys can't be
        loaded at all, which is an outage rather than a bad token.
        """
        claims = await verify_jwt(
            self.keys,
            token,
            audience=self.resource,
            allowed_types=ACCESS_TOKEN_TYPES,
            type_required=True,
            leeway=self.leeway,
            required_claims=_ACCESS_TOKEN_CLAIMS,
        )
        client_id = claims.get("client_id")
        if not isinstance(client_id, str) or not client_id:
            raise TokenRejected("The token has no valid client_id claim")
        audience = claims["aud"]
        jti = claims.get("jti")
        sid = claims.get("sid")
        auth_time = claims.get("auth_time")
        return TokenClaims(
            sub=claims["sub"],
            via="access_token",
            client_id=client_id,
            scopes=parse_scope_claim(claims.get("scope")),
            claims=MappingProxyType(claims),
            issuer=claims["iss"],
            audience=(audience,) if isinstance(audience, str) else tuple(audience),
            expires_at=int(claims["exp"]),
            issued_at=int(claims["iat"]),
            token_id=jti if isinstance(jti, str) else None,
            session_id=sid if isinstance(sid, str) else None,
            auth_time=auth_time if type(auth_time) is int else None,
        )

    async def aclose(self) -> None:
        await self._http.aclose()


class BearerVerifier:
    """Access tokens checked locally, and API keys checked at the issuer when enabled.

    Raises ``TokenRejected`` for a bad credential, ``RequestThrottled`` when a
    limit is hit, and ``MicroAuthError`` when nothing can be checked.
    """

    def __init__(self, access: AccessTokenVerifier, keys: KeyChecks | None) -> None:
        self.access = access
        self.keys = keys

    async def verify(self, token: str, address: str | None) -> TokenClaims:
        if self.keys is not None and is_key_candidate(token):
            return claims_from_key(await self.keys.verify(token, address))
        return await self.access.verify(token)

    async def aclose(self) -> None:
        if self.keys is not None:
            await self.keys.aclose()
        await self.access.aclose()


def bearer_verifier(
    *,
    issuer: str,
    resource: str,
    leeway: float,
    timeout: float,
    jwks_refresh_interval: float,
    http_client: httpx.AsyncClient | None,
    api_keys: bool,
    resource_client_id: str | None,
    resource_secret: str | None,
    stale_if_error: float,
    unknown_key_limit: int,
    redis_url: str | None,
    redis_client: Any | None,
    enforce_limits: bool = True,
) -> BearerVerifier:
    access = AccessTokenVerifier(
        issuer,
        resource,
        leeway=leeway,
        timeout=timeout,
        jwks_refresh_interval=jwks_refresh_interval,
        http_client=http_client,
    )
    keys = None
    if api_keys:
        keys = KeyChecks(
            access.keys,
            access._http,
            resource=resource,
            client_id=resource_client_id or getenv("MICROAUTH_RESOURCE_CLIENT_ID"),
            client_secret=resource_secret or getenv("MICROAUTH_RESOURCE_SECRET"),
            timeout=timeout,
            leeway=leeway,
            stale_if_error=stale_if_error,
            unknown_key_limit=unknown_key_limit,
            redis_url=redis_url or getenv("MICROAUTH_REDIS_URL") or None,
            redis_client=redis_client,
            enforce_limits=enforce_limits,
        )
    return BearerVerifier(access, keys)


class TokenAuth:
    """FastAPI dependencies that protect an API with MicroAuth access tokens,
    and optionally your users' API keys and browser sessions.

    Args:
        app: Your FastAPI app. When given, the protected resource metadata
            route, the problem JSON error handler and the shutdown cleanup
            are added to it. You can instead call ``install(app)``.
        issuer: Your MicroAuth service's issuer, such as
            ``https://auth.example.com``. Defaults to ``MICROAUTH_ISSUER``.
        resource: This API's identifier exactly as registered in MicroAuth,
            such as ``https://api.example.com``. Tokens must name it in
            ``aud``. Defaults to ``MICROAUTH_RESOURCE``.
        scopes: Scopes every protected route needs, on top of the ones each
            ``require()`` call adds.
        scopes_supported: Scopes listed in the protected resource metadata.
            Defaults to every scope used by ``scopes`` and ``require()``.
        api_keys: Also accept API keys your users made for their accounts.
            Needs this API's server credentials. Default False.
        resource_client_id: This API's server credential ID, for checking
            keys. Defaults to ``MICROAUTH_RESOURCE_CLIENT_ID``.
        resource_secret: This API's server credential secret. Defaults to
            ``MICROAUTH_RESOURCE_SECRET``.
        stale_if_error: Seconds an active key keeps working past its cached
            answer when MicroAuth can't be reached. 0 turns it off.
            Default 600.
        unknown_key_limit: Unknown, revoked or mistyped keys one client
            address may send per minute before it gets ``429``. 0 turns it
            off. Default 20.
        client_address: A function that takes the request and returns the
            caller's address, for apps behind a proxy. Defaults to
            ``request.client.host``.
        sessions: A ``UserAuth`` whose signed in users may call the API from
            the browser without a token. Their permissions act as scopes.
        redis_url: Keep key answers and limits in Redis, shared by every
            worker. Defaults to ``MICROAUTH_REDIS_URL``.
        redis_client: Optional externally owned ``redis.asyncio`` client.
        leeway: Seconds of clock skew allowed on ``exp``, ``nbf`` and
            ``iat``. Default 60.
        timeout: HTTP timeout for calls to MicroAuth. Default 10.
        jwks_refresh_interval: Seconds between scheduled refreshes of the
            signing keys. Unknown key ids refetch sooner. Default 900.
        http_client: Optional externally owned ``httpx.AsyncClient``.
    """

    def __init__(
        self,
        app: Any = None,
        *,
        issuer: str | None = None,
        resource: str | None = None,
        scopes: str | Iterable[str] | None = None,
        scopes_supported: Iterable[str] | None = None,
        api_keys: bool = False,
        resource_client_id: str | None = None,
        resource_secret: str | None = None,
        stale_if_error: float = DEFAULT_STALE_IF_ERROR,
        unknown_key_limit: int = DEFAULT_UNKNOWN_KEY_LIMIT,
        client_address: ClientAddress | None = None,
        sessions: UserAuth | None = None,
        redis_url: str | None = None,
        redis_client: Any | None = None,
        leeway: float = LEEWAY_SECONDS,
        timeout: float = 10.0,
        jwks_refresh_interval: float = 900.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.issuer = validate_issuer(issuer or getenv("MICROAUTH_ISSUER"))
        self.resource = validate_resource(resource or getenv("MICROAUTH_RESOURCE"))
        self.required_scopes = normalize_scopes(scopes, "scopes")
        self._declared: set[str] = set(self.required_scopes)
        self._scopes_supported = (
            None
            if scopes_supported is None
            else normalize_scopes(scopes_supported, "scopes_supported")
        )
        if client_address is not None and not callable(client_address):
            raise MicroAuthConfigurationError("client_address must be a function of the request")
        self.sessions = _checked_sessions(sessions, self.issuer)
        self.metadata_url = metadata_url(self.resource)
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
        self._client_address = client_address
        what = "a MicroAuth access token or API key" if api_keys else "a MicroAuth access token"
        self._missing = f"Send {what} in the Authorization header"
        if self.sessions is not None:
            self._missing = f"Sign in, or send {what} in the Authorization header"
        self._scheme = HTTPBearer(
            auto_error=False,
            scheme_name="MicroAuthAccessToken",
            bearerFormat=None if api_keys else "JWT",
            description=(
                "A MicroAuth access token issued for this API, or an API key."
                if api_keys
                else "A MicroAuth access token issued for this API."
            ),
        )
        self.router = APIRouter()
        self.router.add_api_route(
            metadata_path(self.resource),
            self._metadata_endpoint,
            methods=["GET"],
            include_in_schema=False,
        )
        if app is not None:
            self.install(app)

    def install(self, app: Any) -> None:
        """Add the metadata route, the problem JSON error handler and the
        shutdown cleanup to ``app``."""
        app.add_middleware(CloseOnShutdown, close=self.aclose, name="TokenAuth")
        app.include_router(self.router)
        install_handlers(app, TOKEN_DENIALS)

    @property
    def scopes_supported(self) -> frozenset[str]:
        if self._scopes_supported is not None:
            return self._scopes_supported
        return frozenset(self._declared)

    def metadata(self) -> dict[str, Any]:
        """This API's protected resource metadata document (RFC 9728)."""
        return metadata_document(self.resource, self.issuer, self.scopes_supported)

    def require(self, *scopes: str) -> Callable[..., Awaitable[TokenClaims]]:
        """A dependency that admits a valid caller holding every scope given.

        ``Depends(api.require())`` with no scopes only needs a valid caller.
        """
        needed = self.required_scopes | normalize_scopes(scopes, "require()")
        self._declared |= needed

        async def dependency(
            request: Request, _bearer: Any = Security(self._scheme)
        ) -> TokenClaims:
            return await self.authorize(request, needed)

        return dependency

    async def authorize(self, request: Request, scopes: frozenset[str]) -> TokenClaims:
        """Check the request's caller against ``scopes`` or raise the denial.

        A request with an Authorization header is judged by that header
        alone. Only a request without one can use the ``sessions`` option.
        """
        values = request.headers.getlist("authorization")
        claims = None
        if not values and self.sessions is not None:
            session = await self.sessions._current(request)
            if session is not None:
                claims = claims_from_session(session.claims, self.sessions.issuer)
        if claims is None:
            claims = await self._from_header(request, values)
        if not scopes <= claims.scopes:
            detail = missing_scope_detail(claims.via)
            raise InsufficientScope(
                scopes,
                bearer_challenge(
                    error="insufficient_scope",
                    scope=" ".join(sorted(scopes)),
                    resource_metadata=self.metadata_url,
                    error_description=detail,
                ),
                detail,
            )
        return claims

    async def _from_header(self, request: Request, values: list[str]) -> TokenClaims:
        try:
            token = bearer_token(values)
        except TokenRejected as exc:
            raise self._invalid(exc.reason) from None
        if token is None:
            raise InvalidToken(self._missing, bearer_challenge(resource_metadata=self.metadata_url))
        try:
            return await self._bearer.verify(token, self._address(request))
        except TokenRejected as exc:
            raise self._invalid(exc.reason) from None
        except RequestThrottled as exc:
            raise TooManyRequests(exc.retry_after, exc.reason) from None
        except KeyCheckUnavailable:
            raise AuthUnavailable() from None
        except MicroAuthError as exc:
            logger.error("microauth: access tokens can't be checked right now (%s)", exc)
            raise AuthUnavailable() from None

    def _address(self, request: Request) -> str | None:
        if self._client_address is not None:
            return self._client_address(request)
        return request.client.host if request.client is not None else None

    def _invalid(self, reason: str) -> InvalidToken:
        return InvalidToken(
            reason,
            bearer_challenge(
                error="invalid_token",
                error_description=reason,
                resource_metadata=self.metadata_url,
            ),
        )

    async def _metadata_endpoint(self) -> JSONResponse:
        return JSONResponse(
            self.metadata(),
            headers={
                "Cache-Control": "public, max-age=300",
                "Access-Control-Allow-Origin": "*",
            },
        )

    async def aclose(self) -> None:
        """Close the HTTP and Redis clients this instance created and empty
        its key caches. Idempotent; runs at shutdown when installed."""
        await self._bearer.aclose()


def _checked_sessions(sessions: UserAuth | None, issuer: str) -> UserAuth | None:
    if sessions is None:
        return None
    if not isinstance(sessions, UserAuth):
        raise MicroAuthConfigurationError("sessions must be a UserAuth")
    if "roles" not in sessions.scopes:
        raise MicroAuthConfigurationError(
            "TokenAuth(sessions=auth) gives signed in users their permissions as scopes, and "
            "permissions come with the roles scope. Add 'roles' to UserAuth(scopes=...)."
        )
    if sessions.issuer != issuer:
        raise MicroAuthConfigurationError(
            f"TokenAuth(sessions=auth) needs both on the same issuer, but UserAuth uses "
            f"{sessions.issuer} and TokenAuth uses {issuer}"
        )
    return sessions
