"""Protect an API with MicroAuth access tokens.

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

Failures follow RFC 6750: ``401`` with a ``WWW-Authenticate: Bearer``
challenge naming the protected resource metadata (RFC 9728), and ``403`` with
``error="insufficient_scope"`` listing every scope the route needs.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Request, Security
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer

from ._env import getenv
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
)

logger = logging.getLogger("microauth")

METADATA_PREFIX = "/.well-known/oauth-protected-resource"
ACCESS_TOKEN_TYPES = frozenset({"at+jwt", "application/at+jwt"})
_ACCESS_TOKEN_CLAIMS = ("iss", "sub", "aud", "exp", "iat", "client_id")


@dataclass(frozen=True, slots=True)
class TokenClaims:
    """A verified access token, handed to your route by ``api.require(...)``."""

    sub: str
    client_id: str
    scopes: frozenset[str]
    claims: Mapping[str, Any]
    issuer: str
    audience: tuple[str, ...]
    expires_at: int
    issued_at: int
    token_id: str | None = None
    session_id: str | None = None
    auth_time: int | None = None

    def has_scope(self, *scopes: str) -> bool:
        """True when the token holds every scope given."""
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


class TokenAuth:
    """FastAPI dependencies that protect an API with MicroAuth access tokens.

    Args:
        app: Your FastAPI app. When given, the protected resource metadata
            route and the problem JSON error handler are added to it. You can
            instead call ``install(app)``, or include ``api.router`` yourself.
        issuer: Your MicroAuth service's issuer, such as
            ``https://auth.example.com``. Defaults to ``MICROAUTH_ISSUER``.
        resource: This API's identifier exactly as registered in MicroAuth,
            such as ``https://api.example.com``. Tokens must name it in
            ``aud``. Defaults to ``MICROAUTH_RESOURCE``.
        scopes: Scopes every protected route needs, on top of the ones each
            ``require()`` call adds.
        scopes_supported: Scopes listed in the protected resource metadata.
            Defaults to every scope used by ``scopes`` and ``require()``.
        leeway: Seconds of clock skew allowed on ``exp``, ``nbf`` and
            ``iat``. Default 60.
        timeout: HTTP timeout for discovery and key fetches. Default 10.
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
        self.metadata_url = metadata_url(self.resource)
        self.verifier = AccessTokenVerifier(
            self.issuer,
            self.resource,
            leeway=leeway,
            timeout=timeout,
            jwks_refresh_interval=jwks_refresh_interval,
            http_client=http_client,
        )
        self._scheme = HTTPBearer(
            auto_error=False,
            scheme_name="MicroAuthAccessToken",
            bearerFormat="JWT",
            description="A MicroAuth access token issued for this API.",
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
        """Add the metadata route and the problem JSON error handler to ``app``."""
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
        """A dependency that admits a valid token holding every scope given.

        ``Depends(api.require())`` with no scopes only needs a valid token.
        """
        needed = self.required_scopes | normalize_scopes(scopes, "require()")
        self._declared |= needed

        async def dependency(
            request: Request, _bearer: Any = Security(self._scheme)
        ) -> TokenClaims:
            return await self.authorize(request, needed)

        return dependency

    async def authorize(self, request: Request, scopes: frozenset[str]) -> TokenClaims:
        """Check the request's bearer token against ``scopes`` or raise the denial."""
        try:
            token = bearer_token(request.headers.getlist("authorization"))
        except TokenRejected as exc:
            raise self._invalid(exc.reason) from None
        if token is None:
            raise InvalidToken(
                "Send a MicroAuth access token in the Authorization header",
                bearer_challenge(resource_metadata=self.metadata_url),
            )
        try:
            claims = await self.verifier.verify(token)
        except TokenRejected as exc:
            raise self._invalid(exc.reason) from None
        except MicroAuthError as exc:
            logger.error("microauth: access tokens can't be checked right now (%s)", exc)
            raise AuthUnavailable() from None
        if not scopes <= claims.scopes:
            raise InsufficientScope(
                scopes,
                bearer_challenge(
                    error="insufficient_scope",
                    scope=" ".join(sorted(scopes)),
                    resource_metadata=self.metadata_url,
                    error_description="The access token is missing a scope this request needs",
                ),
            )
        return claims

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
        """Close the HTTP client this instance created. Idempotent."""
        await self.verifier.aclose()
