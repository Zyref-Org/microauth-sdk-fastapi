"""OpenID Connect plumbing shared by UserAuth, TokenAuth and McpAuth.

Discovery documents and signing keys only ever come from the issuer named in
the configuration. A discovery document whose ``issuer`` is not exactly that
value is refused (RFC 8414 section 3.3, OpenID Connect Discovery section 4.3),
and tokens are only checked against keys from the ``jwks_uri`` it names.

Keys rotate. A token signed with a key this process hasn't seen triggers one
refetch of the key set, at most once a minute so a flood of made up key ids
can't turn into a flood of requests to the issuer. The key set is also
refreshed in the background on a schedule, which is how retired keys drop out.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import math
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, TypeVar
from urllib.parse import urlencode, urlsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from .client import USER_AGENT
from .exceptions import (
    MicroAuthAPIError,
    MicroAuthConfigurationError,
    MicroAuthError,
    MicroAuthResponseError,
)

logger = logging.getLogger("microauth")

T = TypeVar("T")

LEEWAY_SECONDS = 60
DISCOVERY_PATH = "/.well-known/openid-configuration"
_MAX_DOCUMENT_BYTES = 512 * 1024
_MAX_TOKEN_LENGTH = 16 * 1024
_MIN_RSA_BITS = 2048
# After a failed fetch, cached copies keep being used and the fetch is not
# retried for this long, so an outage at the issuer isn't hammered.
_RETRY_SECONDS = 60.0

_ENDPOINT_FIELDS = (
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "jwks_uri",
    "end_session_endpoint",
    "revocation_endpoint",
    "introspection_endpoint",
    "pushed_authorization_request_endpoint",
)


class TokenRejected(Exception):
    """A token failed validation. ``reason`` is safe to show to the caller."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# URLs


def is_development_host(host: str) -> bool:
    """Hosts where plain http is allowed, for local development only."""
    host = host.lower()
    return host in ("localhost", "127.0.0.1") or host.endswith(".localhost")


def _url_problem(value: str, *, allow_query: bool = False) -> str | None:
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        return "it contains spaces or control characters"
    try:
        parts = urlsplit(value)
        _ = parts.port  # raises ValueError for a port that isn't a number
    except ValueError:
        return "it is not a valid URL"
    if parts.scheme not in ("https", "http") or not parts.hostname:
        return "it must be an absolute https URL"
    if parts.username is not None or parts.password is not None:
        return "it must not contain a user name or password"
    if "#" in value:
        return "it must not have a fragment"
    if not allow_query and "?" in value:
        return "it must not have a query string"
    if parts.scheme == "http" and not is_development_host(parts.hostname):
        return "http is only allowed for localhost, 127.0.0.1 and *.localhost; use https"
    return None


def _origin_problem(value: str) -> str | None:
    problem = _url_problem(value)
    if problem is None and urlsplit(value).path:
        problem = (
            "it must be an origin like https://auth.example.com, with no path or trailing slash"
        )
    return problem


def validate_issuer(value: str | None) -> str:
    """The issuer exactly as configured, after checking it's a bare origin."""
    value = (value or "").strip()
    if not value:
        raise MicroAuthConfigurationError(
            "The MicroAuth issuer is missing. Pass issuer='https://auth.example.com' or set "
            "MICROAUTH_ISSUER. It's on your service's Overview page in the MicroAuth dashboard."
        )
    problem = _origin_problem(value)
    if problem is not None:
        raise MicroAuthConfigurationError(f"The issuer {value!r} is not valid: {problem}.")
    return value


def validate_app_url(value: str | None) -> str:
    value = (value or "").strip()
    if not value:
        raise MicroAuthConfigurationError(
            "Your app's public URL is missing. Pass app_url='https://app.example.com' or set "
            "MICROAUTH_APP_URL. The sign in callback is built from it."
        )
    value = value.removesuffix("/")
    problem = _origin_problem(value)
    if problem is not None:
        raise MicroAuthConfigurationError(f"The app URL {value!r} is not valid: {problem}.")
    return value


def validate_resource(value: str | None) -> str:
    """A resource identifier (RFC 8707): an absolute URL without fragment or query."""
    value = (value or "").strip()
    if not value:
        raise MicroAuthConfigurationError(
            "The resource is missing. Pass resource='https://api.example.com' or set "
            "MICROAUTH_RESOURCE. Use the URL of the API or MCP server exactly as it is "
            "registered under APIs and MCP servers in the MicroAuth dashboard."
        )
    problem = _url_problem(value)
    if problem is None and value.endswith("/"):
        problem = "drop the trailing slash"
    if problem is not None:
        raise MicroAuthConfigurationError(f"The resource {value!r} is not valid: {problem}.")
    return value


def origin_of(url: str) -> str | None:
    """``scheme://host[:port]`` in lowercase with default ports dropped, or None."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    if port is None or (parts.scheme, port) in (("https", 443), ("http", 80)):
        return f"{parts.scheme}://{host}"
    return f"{parts.scheme}://{host}:{port}"


def add_query(url: str, params: Mapping[str, str]) -> str:
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{urlencode(params)}"


# Discovery


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    """The parts of the issuer's discovery document the SDK uses."""

    issuer: str
    jwks_uri: str
    authorization_endpoint: str | None
    token_endpoint: str | None
    userinfo_endpoint: str | None
    end_session_endpoint: str | None
    revocation_endpoint: str | None
    introspection_endpoint: str | None
    pushed_authorization_request_endpoint: str | None
    code_challenge_methods_supported: frozenset[str]
    authorization_response_iss_parameter_supported: bool
    raw: Mapping[str, Any]


def parse_metadata(document: Any, issuer: str) -> ProviderMetadata:
    if not isinstance(document, dict):
        raise MicroAuthResponseError(f"The discovery document of {issuer} is not a JSON object")
    found = document.get("issuer")
    if found != issuer:
        raise MicroAuthResponseError(
            f"The discovery document of {issuer} names the issuer {found!r}. It must be exactly "
            f"{issuer!r}, so the document is not used. Check MICROAUTH_ISSUER."
        )
    endpoints: dict[str, str | None] = {}
    for field in _ENDPOINT_FIELDS:
        value = document.get(field)
        if value is None:
            endpoints[field] = None
            continue
        if not isinstance(value, str) or _url_problem(value, allow_query=True) is not None:
            raise MicroAuthResponseError(
                f"The discovery document of {issuer} has an invalid {field}: {value!r}"
            )
        endpoints[field] = value
    jwks_uri = endpoints["jwks_uri"]
    if jwks_uri is None:
        raise MicroAuthResponseError(f"The discovery document of {issuer} has no jwks_uri")
    methods = document.get("code_challenge_methods_supported")
    return ProviderMetadata(
        issuer=issuer,
        jwks_uri=jwks_uri,
        authorization_endpoint=endpoints["authorization_endpoint"],
        token_endpoint=endpoints["token_endpoint"],
        userinfo_endpoint=endpoints["userinfo_endpoint"],
        end_session_endpoint=endpoints["end_session_endpoint"],
        revocation_endpoint=endpoints["revocation_endpoint"],
        introspection_endpoint=endpoints["introspection_endpoint"],
        pushed_authorization_request_endpoint=endpoints["pushed_authorization_request_endpoint"],
        code_challenge_methods_supported=frozenset(
            method for method in methods if isinstance(method, str)
        )
        if isinstance(methods, list)
        else frozenset(),
        authorization_response_iss_parameter_supported=(
            document.get("authorization_response_iss_parameter_supported") is True
        ),
        raw=MappingProxyType(dict(document)),
    )


def require_sign_in_support(metadata: ProviderMetadata) -> None:
    """Refuse an issuer that can't run the code flow with PKCE S256."""
    if metadata.authorization_endpoint is None or metadata.token_endpoint is None:
        raise MicroAuthResponseError(
            f"The discovery document of {metadata.issuer} has no authorization or token endpoint"
        )
    if "S256" not in metadata.code_challenge_methods_supported:
        raise MicroAuthResponseError(
            f"{metadata.issuer} does not list S256 in code_challenge_methods_supported, so "
            "sign in is refused. PKCE with S256 is required."
        )


async def fetch_json(http: httpx.AsyncClient, url: str, timeout: float, what: str) -> Any:
    try:
        response = await http.get(
            url,
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        raise MicroAuthAPIError(
            0, f"could not fetch the {what} from {url} ({type(exc).__name__})"
        ) from exc
    if response.status_code != 200:
        raise MicroAuthAPIError(
            response.status_code, f"the {what} at {url} answered {response.status_code}"
        )
    if len(response.content) > _MAX_DOCUMENT_BYTES:
        raise MicroAuthResponseError(f"the {what} at {url} is too large")
    try:
        return response.json()
    except ValueError as exc:
        raise MicroAuthResponseError(f"the {what} at {url} is not JSON") from exc


def parse_jwks(document: Any) -> dict[str, RSAPublicKey]:
    """The RS256 signing keys of a JWKS, by key id. Keys of other kinds are skipped."""
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise MicroAuthResponseError("The signing key set has no keys list")
    keys: dict[str, RSAPublicKey] = {}
    for entry in document["keys"]:
        if not isinstance(entry, dict):
            continue
        kid = entry.get("kid")
        if entry.get("kty") != "RSA" or not isinstance(kid, str) or not kid:
            continue
        if entry.get("use") not in (None, "sig") or entry.get("alg") not in (None, "RS256"):
            continue
        try:
            key = jwt.PyJWK(entry, algorithm="RS256").key
        except (jwt.PyJWTError, ValueError, TypeError, KeyError):
            logger.warning("microauth: skipping signing key %r, which could not be parsed", kid)
            continue
        if not isinstance(key, RSAPublicKey) or key.key_size < _MIN_RSA_BITS:
            continue
        keys[kid] = key
    if not keys:
        raise MicroAuthResponseError("The signing key set has no usable RS256 keys")
    return keys


class HttpClient:
    """The httpx client for issuer calls.

    A client passed in is externally owned and never closed here. Otherwise
    one is created on first use, and created again after ``aclose()``, so an
    app whose lifespan runs twice (common in tests) keeps working.
    """

    def __init__(self, client: httpx.AsyncClient | None, timeout: float) -> None:
        self._client = client
        self._owned = client is None
        self._timeout = timeout

    def __call__(self) -> httpx.AsyncClient:
        if self._client is None or (self._owned and self._client.is_closed):
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def aclose(self) -> None:
        if self._owned and self._client is not None and not self._client.is_closed:
            await self._client.aclose()


class Issuer:
    """Discovery and signing keys of one issuer, cached and refreshed in place.

    Every fetch runs as a single flight: concurrent requests that need the
    same document wait for one HTTP call instead of each making their own.
    """

    def __init__(
        self,
        issuer: str,
        http: Callable[[], httpx.AsyncClient],
        *,
        timeout: float,
        metadata_ttl: float = 3600.0,
        jwks_refresh_interval: float = 900.0,
        unknown_kid_interval: float = 60.0,
    ) -> None:
        self.issuer = issuer
        self._http = http
        self._timeout = timeout
        self._metadata_ttl = metadata_ttl
        self._jwks_refresh_interval = jwks_refresh_interval
        self._unknown_kid_interval = unknown_kid_interval
        self.clock: Callable[[], float] = time.monotonic
        self._metadata: ProviderMetadata | None = None
        self._metadata_at = 0.0
        self._metadata_retry_at = 0.0
        self._keys: dict[str, RSAPublicKey] | None = None
        self._keys_at = 0.0
        self._keys_retry_at = 0.0
        self._forced_at = -math.inf
        self._flights: dict[str, asyncio.Future[Any]] = {}

    async def metadata(self) -> ProviderMetadata:
        if self._metadata is None:
            return await self._once("discovery document", self._load_metadata)
        now = self.clock()
        if now - self._metadata_at >= self._metadata_ttl and now >= self._metadata_retry_at:
            self._start("discovery document", self._load_metadata, background=True)
        return self._metadata

    async def signing_key(self, kid: str) -> RSAPublicKey | None:
        """The key for ``kid``, or None when the issuer doesn't publish it.

        Raises ``MicroAuthError`` only when no key set could be loaded at all.
        """
        just_loaded = self._keys is None
        if self._keys is None:
            await self._once("signing keys", self._load_keys)
        else:
            now = self.clock()
            if now - self._keys_at >= self._jwks_refresh_interval and now >= self._keys_retry_at:
                self._start("signing keys", self._load_keys, background=True)
        assert self._keys is not None
        key = self._keys.get(kid)
        if key is None and not just_loaded:
            now = self.clock()
            if now - self._forced_at >= self._unknown_kid_interval:
                self._forced_at = now
                try:
                    await self._once("signing keys", self._load_keys)
                except MicroAuthError as exc:
                    logger.warning("microauth: refetching the signing keys failed (%s)", exc)
                key = self._keys.get(kid)
        return key

    async def _load_metadata(self) -> ProviderMetadata:
        url = f"{self.issuer}{DISCOVERY_PATH}"
        try:
            document = await fetch_json(self._http(), url, self._timeout, "discovery document")
            metadata = parse_metadata(document, self.issuer)
        except MicroAuthError:
            self._metadata_retry_at = self.clock() + _RETRY_SECONDS
            raise
        self._metadata = metadata
        self._metadata_at = self.clock()
        return metadata

    async def _load_keys(self) -> dict[str, RSAPublicKey]:
        try:
            metadata = await self.metadata()
            document = await fetch_json(
                self._http(), metadata.jwks_uri, self._timeout, "signing keys"
            )
            keys = parse_jwks(document)
        except MicroAuthError:
            self._keys_retry_at = self.clock() + _RETRY_SECONDS
            raise
        self._keys = keys
        self._keys_at = self.clock()
        return keys

    def _start(
        self, what: str, load: Callable[[], Awaitable[T]], *, background: bool = False
    ) -> asyncio.Future[T]:
        flight = self._flights.get(what)
        if flight is None:
            flight = asyncio.ensure_future(load())
            self._flights[what] = flight
            flight.add_done_callback(lambda done: self._landed(what, done, background))
        return flight

    def _landed(self, what: str, flight: asyncio.Future[Any], background: bool) -> None:
        if self._flights.get(what) is flight:
            del self._flights[what]
        if flight.cancelled():
            return
        error = flight.exception()
        if error is not None and background:
            logger.warning(
                "microauth: refreshing the %s of %s failed (%s); the cached copy stays in use",
                what,
                self.issuer,
                error,
            )

    async def _once(self, what: str, load: Callable[[], Awaitable[T]]) -> T:
        return await asyncio.shield(self._start(what, load))


# JWTs


def header_of(token: str) -> dict[str, Any]:
    if not isinstance(token, str) or len(token) > _MAX_TOKEN_LENGTH or token.count(".") != 2:
        raise TokenRejected("The token is malformed")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise TokenRejected("The token is malformed") from exc
    return header


async def verify_jwt(
    issuer: Issuer,
    token: str,
    *,
    audience: str,
    allowed_types: frozenset[str],
    type_required: bool,
    leeway: float,
    required_claims: tuple[str, ...],
) -> dict[str, Any]:
    """Check signature, algorithm, type, issuer, audience and time claims.

    Only RS256 is accepted, so ``none`` and every HMAC algorithm are refused
    before a key is even looked up. ``allowed_types`` holds lowercase ``typ``
    values; when ``type_required`` is False a token without ``typ`` passes too.
    """
    header = header_of(token)
    if header.get("alg") != "RS256":
        raise TokenRejected("The token must be signed with RS256")
    typ = header.get("typ")
    if typ is None:
        if type_required:
            raise TokenRejected("The token has no type (typ)")
    elif not isinstance(typ, str) or typ.lower() not in allowed_types:
        raise TokenRejected("The token has the wrong type (typ)")
    if "crit" in header:
        raise TokenRejected("The token uses critical header extensions, which are not supported")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise TokenRejected("The token has no key id (kid)")
    key = await issuer.signing_key(kid)
    if key is None:
        raise TokenRejected("The token was signed with an unknown key")
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            key=key,
            algorithms=["RS256"],
            audience=audience,
            issuer=issuer.issuer,
            leeway=leeway,
            options={"require": list(required_claims)},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenRejected("The token has expired") from exc
    except jwt.ImmatureSignatureError as exc:
        raise TokenRejected("The token is not valid yet") from exc
    except jwt.InvalidAudienceError as exc:
        raise TokenRejected("The token was issued for a different audience") from exc
    except jwt.InvalidIssuerError as exc:
        raise TokenRejected("The token was issued by a different server") from exc
    except jwt.MissingRequiredClaimError as exc:
        raise TokenRejected(f"The token has no {exc.claim} claim") from exc
    except jwt.InvalidSignatureError as exc:
        raise TokenRejected("The token signature is not valid") from exc
    except jwt.PyJWTError as exc:
        raise TokenRejected("The token is not valid") from exc
    sub = claims.get("sub")
    if "sub" in required_claims and (not isinstance(sub, str) or not sub):
        raise TokenRejected("The token has no valid sub claim")
    return claims


def unverified_claims(token: str) -> dict[str, Any] | None:
    """Claims of a token this process already verified, for example one read
    back from an encrypted cookie. Never use this on a token from a request."""
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return None
    return claims if isinstance(claims, dict) else None


def token_hash(value: str) -> str:
    """``at_hash`` for RS256: the left half of SHA-256, base64url encoded."""
    digest = hashlib.sha256(value.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode("ascii")
