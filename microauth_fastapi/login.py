"""Sign users in to your FastAPI app with MicroAuth.

Quickstart::

    from fastapi import Depends, FastAPI
    from microauth_fastapi import User, UserAuth

    app = FastAPI()
    auth = UserAuth(app)  # settings from MICROAUTH_* or .env

    @app.get("/dashboard")
    async def dashboard(user: User = Depends(auth.login_required)):
        return {"hello": user.name}

This is the backend for frontend pattern. Your server runs the OpenID Connect
code flow with PKCE against your MicroAuth service and keeps the resulting
tokens in an encrypted, HttpOnly cookie. Browser JavaScript never sees a token,
so a cross site scripting bug can't steal one.

Access tokens are short lived. When one expires the SDK refreshes it before
your route runs, which is also when role changes and suspensions reach your
app, and writes the new cookie on whatever response your route returns.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import logging
import re
import secrets
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any
from urllib.parse import quote_plus, urlencode, urlsplit

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from starlette.datastructures import Headers
from starlette.requests import cookie_parser

from ._cookies import (
    MAX_CHUNKS,
    MIN_SECRET_BYTES,
    CookieSealer,
    clear_cookie_header,
    present_names,
    read_value,
    set_cookie_header,
    split_value,
)
from ._env import getenv
from ._oidc import (
    LEEWAY_SECONDS,
    HttpClient,
    Issuer,
    ProviderMetadata,
    TokenRejected,
    add_query,
    origin_of,
    require_sign_in_support,
    token_hash,
    unverified_claims,
    validate_app_url,
    validate_issuer,
    validate_resource,
    verify_jwt,
)
from ._problem import USER_DENIALS, install_handlers
from .client import USER_AGENT
from .exceptions import (
    AuthUnavailable,
    CrossSiteRequest,
    MicroAuthAPIError,
    MicroAuthConfigurationError,
    MicroAuthError,
    MicroAuthResponseError,
    PermissionDenied,
    SignInRedirect,
    SignInRequired,
)

logger = logging.getLogger("microauth")

DEFAULT_SCOPES = ("openid", "profile", "email", "roles")
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
LOGIN_STATE_SECONDS = 600
REFRESH_SKEW_SECONDS = 30
# When a refresh fails for a reason other than the session ending (the issuer
# is down, say), the user stays signed in on the claims they have for this
# long past the access token's expiry. After that, requests get 503.
STALE_GRACE_SECONDS = 300
_RECENT_REFRESH_SECONDS = 60.0
_FAILED_REFRESH_SECONDS = 5.0
_MAX_RECENT_REFRESHES = 1024
_SESSION_VERSION = 1
_ID_TOKEN_TYPES = frozenset({"jwt"})
_SILENT_ERRORS = frozenset(
    {"login_required", "interaction_required", "consent_required", "account_selection_required"}
)
_COOKIE_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")


@dataclass(frozen=True, slots=True)
class User:
    """The signed in user, read from the ID token MicroAuth issued.

    ``roles`` and ``permissions`` come from the ``roles`` scope and are
    current as of the last token refresh, at most one access token lifetime
    ago.
    """

    id: str
    email: str | None
    email_verified: bool
    name: str | None
    picture: str | None
    roles: frozenset[str]
    permissions: frozenset[str]
    session_id: str | None
    claims: Mapping[str, Any]

    def has_role(self, *roles: str) -> bool:
        """True when the user holds every role given."""
        return all(role in self.roles for role in roles)

    def has_permission(self, *permissions: str) -> bool:
        """True when the user holds every permission given."""
        return all(permission in self.permissions for permission in permissions)

    def to_dict(self) -> dict[str, Any]:
        """The fields that are safe to send to the browser, as JSON types."""
        return {
            "id": self.id,
            "email": self.email,
            "email_verified": self.email_verified,
            "name": self.name,
            "picture": self.picture,
            "roles": sorted(self.roles),
            "permissions": sorted(self.permissions),
            "session_id": self.session_id,
        }


def _strings(value: Any) -> frozenset[str]:
    if not isinstance(value, list):
        return frozenset()
    return frozenset(item for item in value if isinstance(item, str))


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def user_from_claims(claims: Mapping[str, Any]) -> User:
    return User(
        id=claims["sub"],
        email=_string(claims.get("email")),
        email_verified=claims.get("email_verified") is True,
        name=_string(claims.get("name")),
        picture=_string(claims.get("picture")),
        roles=_strings(claims.get("roles")),
        permissions=_strings(claims.get("permissions")),
        session_id=_string(claims.get("sid")),
        claims=MappingProxyType(dict(claims)),
    )


@dataclass(slots=True)
class _Session:
    id_token: str
    refresh_token: str | None
    access_token: str | None
    # When the access token expires, and when this cookie session ends for
    # good, both in Unix seconds.
    expires_at: int
    ends_at: int
    claims: dict[str, Any]

    def payload(self) -> dict[str, Any]:
        return {
            "v": _SESSION_VERSION,
            "id": self.id_token,
            "rt": self.refresh_token,
            "at": self.access_token,
            "exp": self.expires_at,
            "end": self.ends_at,
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> _Session | None:
        id_token = payload.get("id")
        refresh_token = payload.get("rt")
        access_token = payload.get("at")
        expires_at = payload.get("exp")
        ends_at = payload.get("end")
        if (
            payload.get("v") != _SESSION_VERSION
            or not isinstance(id_token, str)
            or not isinstance(refresh_token, (str, type(None)))
            or not isinstance(access_token, (str, type(None)))
            or type(expires_at) is not int
            or type(ends_at) is not int
        ):
            return None
        claims = unverified_claims(id_token)
        if claims is None or not isinstance(claims.get("sub"), str):
            return None
        return cls(id_token, refresh_token, access_token, expires_at, ends_at, claims)


class _SignedOut:
    """The issuer ended the session, for example with ``invalid_grant``."""


_SIGNED_OUT = _SignedOut()


@dataclass(frozen=True, slots=True)
class _RefreshFailed:
    """The refresh couldn't be completed but the session may still be alive."""

    reason: str


_RefreshOutcome = _Session | _SignedOut | _RefreshFailed


@dataclass(frozen=True, slots=True)
class _TokenResponse:
    access_token: str
    expires_in: int | None
    refresh_token: str | None
    id_token: str | None
    scope: str | None


class _TokenEndpointError(MicroAuthAPIError):
    """The token endpoint answered with an OAuth error such as ``invalid_grant``."""

    def __init__(self, status_code: int, error: str, description: str | None) -> None:
        self.error = error
        self.description = description
        detail = f"{error}: {description}" if description else error
        super().__init__(status_code, detail)


class _RequestState:
    """What one request read from, and will write to, the auth cookies.

    Routes and dependencies change this, and the middleware turns the
    changes into ``Set-Cookie`` headers when the response starts, so a
    refreshed session reaches the browser whatever response the route
    returns.
    """

    __slots__ = (
        "_login_cleared",
        "_login_value",
        "_session_cleared",
        "_session_max_age",
        "_session_value",
        "auth",
        "cookies",
        "loaded",
        "session",
    )

    def __init__(self, auth: UserAuth, cookies: dict[str, str]) -> None:
        self.auth = auth
        self.cookies = cookies
        self.loaded = False
        self.session: _Session | None = None
        self._session_value: str | None = None
        self._session_max_age = 0
        self._session_cleared = False
        self._login_value: str | None = None
        self._login_cleared = False

    @property
    def has_session_cookie(self) -> bool:
        return read_value(self.cookies, self.auth.session_cookie) is not None

    def write_session(self, session: _Session) -> None:
        value = self.auth._session_sealer.seal(session.payload())
        if len(split_value(value)) > MAX_CHUNKS:
            logger.error(
                "microauth: the session is too large to keep in cookies (%d bytes), so the "
                "user is signed out. Turn off keep_access_token or give users fewer roles "
                "and permissions.",
                len(value),
            )
            self.clear_session()
            return
        self.session = session
        self.loaded = True
        self._session_value = value
        self._session_max_age = max(0, session.ends_at - int(time.time()))
        self._session_cleared = False

    def clear_session(self) -> None:
        self.session = None
        self.loaded = True
        self._session_value = None
        self._session_cleared = True

    def write_login(self, value: str) -> None:
        self._login_value = value
        self._login_cleared = False

    def clear_login(self) -> None:
        self._login_value = None
        self._login_cleared = True

    def set_cookie_headers(self) -> list[str]:
        auth = self.auth
        secure = auth.secure_cookies
        headers: list[str] = []
        if self._session_value is not None or self._session_cleared:
            stale = present_names(self.cookies, auth.session_cookie)
            if self._session_value is not None:
                chunks = split_value(self._session_value)
                if len(chunks) == 1:
                    names = [auth.session_cookie]
                else:
                    names = [f"{auth.session_cookie}.{index}" for index in range(len(chunks))]
                for name, chunk in zip(names, chunks):
                    headers.append(
                        set_cookie_header(name, chunk, secure=secure, max_age=self._session_max_age)
                    )
                stale -= set(names)
            for name in sorted(stale):
                headers.append(clear_cookie_header(name, secure=secure))
        if self._login_value is not None:
            headers.append(
                set_cookie_header(
                    auth.login_cookie,
                    self._login_value,
                    secure=secure,
                    max_age=LOGIN_STATE_SECONDS,
                )
            )
        elif self._login_cleared and auth.login_cookie in self.cookies:
            headers.append(clear_cookie_header(auth.login_cookie, secure=secure))
        return headers


def _cookies_from_scope(scope: Mapping[str, Any]) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for name, value in scope.get("headers", ()):
        if name == b"cookie":
            cookies.update(cookie_parser(value.decode("latin-1")))
    return cookies


class _SessionMiddleware:
    """Writes session cookie changes on every response, and closes the HTTP
    client when the app shuts down."""

    def __init__(self, app: Any, auth: UserAuth) -> None:
        self.app = app
        self.auth = auth

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            await self.app(scope, receive, self._lifespan_send(send))
            return
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        state = _RequestState(self.auth, _cookies_from_scope(scope))
        scope[self.auth._scope_key] = state

        async def send_with_cookies(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                cookies = state.set_cookie_headers()
                if cookies:
                    headers = list(message.get("headers", []))
                    headers.extend((b"set-cookie", value.encode("latin-1")) for value in cookies)
                    if not any(name.lower() == b"cache-control" for name, _ in headers):
                        headers.append((b"cache-control", b"no-store"))
                    message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_cookies)

    def _lifespan_send(self, send: Any) -> Callable[[dict[str, Any]], Awaitable[None]]:
        async def lifespan_send(message: dict[str, Any]) -> None:
            if message["type"] == "lifespan.shutdown.complete":
                try:
                    await self.auth.aclose()
                except Exception:
                    logger.exception("microauth: closing the sign in HTTP client failed")
            await send(message)

        return lifespan_send


def safe_path(value: str | None) -> str | None:
    """``value`` when it is a path on this site, else None.

    Absolute URLs, protocol relative ``//host`` paths, backslashes and control
    characters are refused, since browsers would follow those to another
    site.
    """
    if not value or len(value) > 2048:
        return None
    if not value.startswith("/") or value.startswith("//") or "\\" in value:
        return None
    if any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in value):
        return None
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        return None
    return value


def _cookie_secrets(value: str | Sequence[str] | None) -> list[bytes]:
    if value is None or (isinstance(value, str) and not value.strip()):
        raise MicroAuthConfigurationError(
            "The cookie secret is missing. Pass cookie_secret=... or set "
            "MICROAUTH_COOKIE_SECRET to a random value of 32 bytes or more, for example from "
            "python -c 'import secrets; print(secrets.token_urlsafe(32))'."
        )
    items = value.split(",") if isinstance(value, str) else list(value)
    found = [item.strip().encode("utf-8") for item in items if item.strip()]
    if not found:
        raise MicroAuthConfigurationError("The cookie secret is empty")
    for secret in found:
        if len(secret) < MIN_SECRET_BYTES:
            raise MicroAuthConfigurationError(
                f"Every cookie secret must be at least {MIN_SECRET_BYTES} bytes long. Generate "
                "one with python -c 'import secrets; print(secrets.token_urlsafe(32))'."
            )
    return found


def _names(value: str | Iterable[str], what: str) -> frozenset[str]:
    items = [value] if isinstance(value, str) else list(value)
    for item in items:
        if not isinstance(item, str) or not item:
            raise MicroAuthConfigurationError(f"{what} must be names, got {item!r}")
    return frozenset(items)


def _basic_credentials(client_id: str, client_secret: str) -> str:
    # RFC 6749 section 2.3.1: both parts are form encoded before base64.
    pair = f"{quote_plus(client_id, safe='')}:{quote_plus(client_secret, safe='')}"
    return "Basic " + base64.b64encode(pair.encode("utf-8")).decode("ascii")


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _redirect(location: str) -> Response:
    return Response(
        status_code=303,
        headers={
            "Location": location,
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
        },
    )


def _page(status: int, title: str, message: str, retry: str | None = None) -> HTMLResponse:
    """A small, self contained error page for the browser routes."""
    link = f'<p><a href="{html.escape(retry)}">Try again</a></p>' if retry else ""
    body = (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width, initial-scale=1">'
        f"<title>{html.escape(title)}</title></head>"
        '<body style="font-family: system-ui, sans-serif; max-width: 32rem; '
        'margin: 4rem auto; padding: 0 1rem; line-height: 1.5">'
        f"<h1>{html.escape(title)}</h1><p>{html.escape(message)}</p>{link}</body></html>"
    )
    return HTMLResponse(
        body,
        status_code=status,
        headers={
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
        },
    )


def _access_token_expiry(access_token: str) -> int | None:
    claims = unverified_claims(access_token)
    exp = claims.get("exp") if claims is not None else None
    return exp if type(exp) is int else None


class UserAuth:
    """Sign in, sessions and role checks for a FastAPI app.

    Args:
        app: Your FastAPI app. When given, the sign in routes, the session
            middleware and the error handler are installed on it. You can
            instead call ``install(app)`` before the app starts.
        issuer: Your MicroAuth service's issuer, such as
            ``https://auth.example.com``. Defaults to ``MICROAUTH_ISSUER``.
        client_id: The web application's client ID. Defaults to
            ``MICROAUTH_CLIENT_ID``.
        client_secret: The web application's client secret. Defaults to
            ``MICROAUTH_CLIENT_SECRET``.
        cookie_secret: At least 32 random bytes that encrypt the cookies.
            A comma separated string or a list rotates secrets: the first one
            encrypts and all of them decrypt. Defaults to
            ``MICROAUTH_COOKIE_SECRET``.
        app_url: Your app's public origin, such as
            ``https://app.example.com``. The redirect URI is this plus
            ``prefix`` plus ``/callback``. Defaults to ``MICROAUTH_APP_URL``.
        scopes: Scopes to request. Default ``openid profile email roles``.
            ``openid`` is always added. Add ``offline_access`` only if you
            want refresh tokens that outlive the sign in session.
        resource: An API's resource identifier to request an access token
            for (RFC 8707). Use it with ``keep_access_token`` to call that API.
        prefix: Where the sign in routes live. Default ``/auth``.
        after_sign_in: Where people land after signing in when the sign in
            link had no ``next``. Default ``/``.
        after_sign_out: Where MicroAuth sends people after signing out.
            ``app_url`` plus this must be a sign out URL of the application.
            Default ``/``.
        keep_access_token: Keep the access token in the session so your
            server can call APIs with ``await auth.access_token(request)``.
            It makes the cookie about twice as large. Default False.
        cookie_name: Base name of the cookies. On https the session cookie is
            ``__Host-<name>`` and the sign in state cookie is
            ``__Host-<name>-login``. Default ``microauth``.
        session_max_age: Seconds a cookie session lasts at most, however
            often it is refreshed. Default 30 days.
        max_age: Ask MicroAuth to make people sign in again when their last
            sign in is older than this many seconds. Default None.
        leeway: Seconds of clock skew allowed on token times. Default 60.
        timeout: HTTP timeout for calls to MicroAuth. Default 10.
        http_client: Optional externally owned ``httpx.AsyncClient``.
    """

    def __init__(
        self,
        app: Any = None,
        *,
        issuer: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        cookie_secret: str | Sequence[str] | None = None,
        app_url: str | None = None,
        scopes: str | Iterable[str] = DEFAULT_SCOPES,
        resource: str | None = None,
        prefix: str = "/auth",
        after_sign_in: str = "/",
        after_sign_out: str = "/",
        keep_access_token: bool = False,
        cookie_name: str = "microauth",
        session_max_age: int = 30 * 24 * 3600,
        max_age: int | None = None,
        leeway: float = LEEWAY_SECONDS,
        timeout: float = 10.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.issuer = validate_issuer(issuer or getenv("MICROAUTH_ISSUER"))
        self.client_id = (client_id or getenv("MICROAUTH_CLIENT_ID") or "").strip()
        if not self.client_id:
            raise MicroAuthConfigurationError(
                "The client ID is missing. Pass client_id=... or set MICROAUTH_CLIENT_ID. "
                "Create a web application under Applications in the MicroAuth dashboard."
            )
        client_secret = (client_secret or getenv("MICROAUTH_CLIENT_SECRET") or "").strip()
        if not client_secret:
            raise MicroAuthConfigurationError(
                "The client secret is missing. Pass client_secret=... or set "
                "MICROAUTH_CLIENT_SECRET. It's shown once when you create the application."
            )
        secrets_ = _cookie_secrets(
            cookie_secret if cookie_secret is not None else getenv("MICROAUTH_COOKIE_SECRET")
        )
        self.app_url = validate_app_url(app_url or getenv("MICROAUTH_APP_URL"))
        self.resource = validate_resource(resource) if resource else None

        scope_list = scopes.split() if isinstance(scopes, str) else list(scopes)
        if any(not isinstance(item, str) or not item or " " in item for item in scope_list):
            raise MicroAuthConfigurationError("scopes must be single words such as 'profile'")
        if "openid" not in scope_list:
            scope_list.insert(0, "openid")
        self.scopes = tuple(dict.fromkeys(scope_list))

        prefix = prefix.rstrip("/")
        if prefix and (safe_path(prefix) is None or "?" in prefix or "#" in prefix):
            raise MicroAuthConfigurationError("prefix must be a path such as '/auth'")
        self.prefix = prefix
        checked_in = safe_path(after_sign_in)
        checked_out = safe_path(after_sign_out)
        if checked_in is None or checked_out is None:
            raise MicroAuthConfigurationError(
                "after_sign_in and after_sign_out must be paths on this site, such as '/'"
            )
        self.after_sign_in = checked_in
        self.after_sign_out = checked_out
        if not _COOKIE_NAME.fullmatch(cookie_name):
            raise MicroAuthConfigurationError(
                "cookie_name may only use letters, digits, '-' and '_'"
            )
        if type(session_max_age) is not int or session_max_age < 60:
            raise MicroAuthConfigurationError("session_max_age must be at least 60 seconds")
        if max_age is not None and (type(max_age) is not int or max_age < 0):
            raise MicroAuthConfigurationError("max_age must be a number of seconds or None")
        if leeway < 0 or leeway > 300:
            raise MicroAuthConfigurationError("leeway must be between 0 and 300 seconds")
        if timeout <= 0:
            raise MicroAuthConfigurationError("timeout must be positive")

        self.keep_access_token = bool(keep_access_token)
        self.session_max_age = session_max_age
        self.max_age = max_age
        self.leeway = leeway
        self.secure_cookies = self.app_url.startswith("https://")
        cookie_prefix = "__Host-" if self.secure_cookies else ""
        self.session_cookie = f"{cookie_prefix}{cookie_name}"
        self.login_cookie = f"{cookie_prefix}{cookie_name}-login"
        self.redirect_uri = f"{self.app_url}{self.prefix}/callback"
        self.post_logout_redirect_uri = f"{self.app_url}{self.after_sign_out}"
        self._app_origin = origin_of(self.app_url)
        self._basic = _basic_credentials(self.client_id, client_secret)
        self._session_sealer = CookieSealer(secrets_, "session", compress=True)
        self._login_sealer = CookieSealer(secrets_, "login state", compress=False)
        self._http = HttpClient(http_client, timeout)
        self._timeout = timeout
        self._issuer = Issuer(self.issuer, self._http, timeout=timeout)
        self._scope_key = f"microauth.user_session.{id(self)}"
        self._refreshing: dict[str, asyncio.Future[_RefreshOutcome]] = {}
        self._recent: OrderedDict[str, tuple[float, _RefreshOutcome]] = OrderedDict()

        self.router = APIRouter()
        self.router.add_api_route(
            f"{self.prefix}/login", self._login_route, methods=["GET"], include_in_schema=False
        )
        self.router.add_api_route(
            f"{self.prefix}/signup", self._signup_route, methods=["GET"], include_in_schema=False
        )
        self.router.add_api_route(
            f"{self.prefix}/callback",
            self._callback_route,
            methods=["GET"],
            include_in_schema=False,
        )
        self.router.add_api_route(
            f"{self.prefix}/logout", self._logout_route, methods=["POST"], include_in_schema=False
        )
        self.router.add_api_route(
            f"{self.prefix}/me", self._me_route, methods=["GET"], include_in_schema=False
        )
        if app is not None:
            self.install(app)

    # Setup

    def install(self, app: Any) -> None:
        """Add the sign in routes, the session middleware and the error handler."""
        app.add_middleware(_SessionMiddleware, auth=self)
        app.include_router(self.router)
        install_handlers(app, USER_DENIALS)

    async def aclose(self) -> None:
        """Close the HTTP client this instance created. Idempotent."""
        await self._http.aclose()

    def login_url(self, next: str | None = None) -> str:
        """The local sign in link, coming back to ``next`` afterwards."""
        url = f"{self.prefix}/login"
        if next is not None:
            if safe_path(next) is None:
                raise ValueError("next must be a path on this site")
            url = f"{url}?{urlencode({'next': next})}"
        return url

    # Dependencies

    async def user(self, request: Request) -> User:
        """The signed in user, or ``401`` problem JSON when nobody is."""
        session = await self._current(request)
        if session is None:
            raise SignInRequired()
        return user_from_claims(session.claims)

    async def optional(self, request: Request) -> User | None:
        """The signed in user, or None."""
        session = await self._current(request)
        return user_from_claims(session.claims) if session is not None else None

    async def login_required(self, request: Request) -> User:
        """For pages: the signed in user, or a redirect to sign in and back."""
        session = await self._current(request)
        if session is None:
            raise SignInRedirect(self.login_url(next=self._target(request)))
        return user_from_claims(session.claims)

    def require(
        self,
        *,
        permissions: str | Iterable[str] = (),
        roles: str | Iterable[str] = (),
        redirect: bool = False,
    ) -> Callable[[Request], Awaitable[User]]:
        """A dependency that admits users holding every permission and role given.

        Signed out visitors get ``401``, or a redirect to sign in with
        ``redirect=True``. Users missing something get ``403``.
        """
        needed_permissions = _names(permissions, "permissions")
        needed_roles = _names(roles, "roles")

        async def dependency(request: Request) -> User:
            if redirect:
                user = await self.login_required(request)
            else:
                user = await self.user(request)
            missing_roles = needed_roles - user.roles
            missing_permissions = needed_permissions - user.permissions
            if missing_roles or missing_permissions:
                raise PermissionDenied(missing_roles, missing_permissions)
            return user

        return dependency

    async def access_token(self, request: Request) -> str | None:
        """The signed in user's current access token, refreshed when needed.

        Needs ``keep_access_token=True``. Use it to call an API from your
        server; never send it to the browser.
        """
        if not self.keep_access_token:
            raise MicroAuthConfigurationError(
                "auth.access_token() needs UserAuth(keep_access_token=True)"
            )
        session = await self._current(request)
        return session.access_token if session is not None else None

    # Session

    def _state(self, request: Request) -> _RequestState:
        state = request.scope.get(self._scope_key)
        if not isinstance(state, _RequestState):
            raise MicroAuthConfigurationError(
                "UserAuth isn't installed on this app. Pass the app to UserAuth(app) or call "
                "auth.install(app) before the app starts."
            )
        return state

    def _target(self, request: Request) -> str:
        target = request.url.path
        if request.url.query:
            target = f"{target}?{request.url.query}"
        return safe_path(target) or self.after_sign_in

    def same_origin(self, headers: Headers) -> bool:
        """Whether ``Origin``, or ``Referer`` without it, is this app's origin."""
        origin = headers.get("origin")
        if origin is not None:
            return origin != "null" and origin_of(origin) == self._app_origin
        referer = headers.get("referer")
        return referer is not None and origin_of(referer) == self._app_origin

    async def _current(self, request: Request) -> _Session | None:
        state = self._state(request)
        if state.loaded:
            return state.session
        if not state.has_session_cookie:
            return None
        if request.method not in SAFE_METHODS and not self.same_origin(request.headers):
            raise CrossSiteRequest()
        session = self._read_session(state)
        if session is not None:
            session = await self._keep_fresh(state, session)
        state.loaded = True
        state.session = session
        return session

    def _read_session(self, state: _RequestState) -> _Session | None:
        raw = read_value(state.cookies, self.session_cookie)
        if raw is None:
            return None
        payload = self._session_sealer.unseal(raw)
        session = _Session.from_payload(payload) if payload is not None else None
        if session is None or session.ends_at <= time.time():
            # Tampered, written with a retired secret, or simply over. All of
            # these mean signed out, and the stale cookie is removed.
            state.clear_session()
            return None
        return session

    async def _keep_fresh(self, state: _RequestState, session: _Session) -> _Session | None:
        now = time.time()
        if session.refresh_token is None:
            if now >= session.expires_at:
                state.clear_session()
                return None
            return session
        if now < session.expires_at - REFRESH_SKEW_SECONDS:
            return session
        outcome = await self._refresh_once(session)
        if isinstance(outcome, _Session):
            state.write_session(outcome)
            return outcome
        if isinstance(outcome, _SignedOut):
            state.clear_session()
            return None
        if now < session.expires_at + STALE_GRACE_SECONDS:
            return session
        logger.error("microauth: the session can't be refreshed (%s)", outcome.reason)
        raise AuthUnavailable()

    async def _refresh_once(self, session: _Session) -> _RefreshOutcome:
        """Refresh at most once per refresh token in this process.

        Parallel requests carrying the same cookie share one call, and
        requests that still carry the old cookie shortly afterwards get the
        same result instead of presenting a refresh token that was already
        rotated.
        """
        assert session.refresh_token is not None
        key = hashlib.sha256(session.refresh_token.encode("utf-8")).hexdigest()
        now = time.monotonic()
        recent = self._recent.get(key)
        if recent is not None and recent[0] > now:
            return recent[1]
        flight = self._refreshing.get(key)
        if flight is None:
            flight = asyncio.ensure_future(self._refresh(session))
            self._refreshing[key] = flight
            flight.add_done_callback(lambda done: self._refreshed(key, done))
        return await asyncio.shield(flight)

    def _refreshed(self, key: str, flight: asyncio.Future[_RefreshOutcome]) -> None:
        self._refreshing.pop(key, None)
        if flight.cancelled() or flight.exception() is not None:
            return
        outcome = flight.result()
        now = time.monotonic()
        ttl = (
            _FAILED_REFRESH_SECONDS
            if isinstance(outcome, _RefreshFailed)
            else _RECENT_REFRESH_SECONDS
        )
        self._recent[key] = (now + ttl, outcome)
        self._recent.move_to_end(key)
        while self._recent:
            oldest_key, (expires, _) = next(iter(self._recent.items()))
            if expires > now and len(self._recent) <= _MAX_RECENT_REFRESHES:
                break
            del self._recent[oldest_key]

    async def _refresh(self, session: _Session) -> _RefreshOutcome:
        assert session.refresh_token is not None
        data = {"grant_type": "refresh_token", "refresh_token": session.refresh_token}
        if self.resource:
            data["resource"] = self.resource
        try:
            metadata = await self._metadata()
            tokens = await self._token_request(metadata, data)
        except _TokenEndpointError as exc:
            if exc.error == "invalid_grant":
                logger.info("microauth: the session ended at MicroAuth, signing the user out")
                return _SIGNED_OUT
            logger.warning("microauth: refreshing the session failed (%s)", exc.detail)
            return _RefreshFailed(exc.detail)
        except MicroAuthError as exc:
            logger.warning("microauth: refreshing the session failed (%s)", exc)
            return _RefreshFailed(str(exc))
        except Exception as exc:
            logger.exception("microauth: refreshing the session failed unexpectedly")
            return _RefreshFailed(type(exc).__name__)

        id_token = session.id_token
        claims = session.claims
        if tokens.id_token is not None:
            try:
                claims = await self._verify_id_token(
                    tokens.id_token,
                    nonce=None,
                    access_token=tokens.access_token,
                    max_age=None,
                    previous=session.claims,
                )
                id_token = tokens.id_token
            except TokenRejected as exc:
                logger.error("microauth: refused the refreshed ID token (%s)", exc.reason)
                return _SIGNED_OUT
            except MicroAuthError as exc:
                # The new tokens are kept so the rotated refresh token isn't
                # lost; the claims catch up on the next refresh.
                logger.warning("microauth: the refreshed ID token can't be checked yet (%s)", exc)
        return self._session_from(
            tokens, id_token, claims, ends_at=session.ends_at, previous=session
        )

    def _session_from(
        self,
        tokens: _TokenResponse,
        id_token: str,
        claims: dict[str, Any],
        *,
        ends_at: int,
        previous: _Session | None = None,
    ) -> _Session:
        now = int(time.time())
        if tokens.expires_in is not None:
            expires_at = now + tokens.expires_in
        else:
            expires_at = _access_token_expiry(tokens.access_token) or now + 300
        refresh_token = tokens.refresh_token
        if refresh_token is None and previous is not None:
            refresh_token = previous.refresh_token
        return _Session(
            id_token=id_token,
            refresh_token=refresh_token,
            access_token=tokens.access_token if self.keep_access_token else None,
            expires_at=expires_at,
            ends_at=ends_at,
            claims=claims,
        )

    # Protocol

    async def _metadata(self) -> ProviderMetadata:
        metadata = await self._issuer.metadata()
        require_sign_in_support(metadata)
        return metadata

    async def _post_form(self, url: str, data: Mapping[str, str]) -> httpx.Response:
        try:
            return await self._http().post(
                url,
                data=dict(data),
                headers={
                    "Authorization": self._basic,
                    "Accept": "application/json",
                    "User-Agent": USER_AGENT,
                },
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            raise MicroAuthAPIError(0, f"could not reach {url} ({type(exc).__name__})") from exc

    async def _token_request(
        self, metadata: ProviderMetadata, data: Mapping[str, str]
    ) -> _TokenResponse:
        assert metadata.token_endpoint is not None
        response = await self._post_form(metadata.token_endpoint, data)
        try:
            body = response.json()
        except ValueError:
            body = None
        if response.status_code != 200:
            if isinstance(body, dict) and isinstance(body.get("error"), str):
                description = body.get("error_description")
                raise _TokenEndpointError(
                    response.status_code,
                    body["error"][:100],
                    description[:300] if isinstance(description, str) else None,
                )
            raise MicroAuthAPIError(
                response.status_code, f"the token endpoint answered {response.status_code}"
            )
        if not isinstance(body, dict):
            raise MicroAuthResponseError("The token endpoint did not answer with a JSON object")
        token_type = body.get("token_type")
        access_token = body.get("access_token")
        if not isinstance(token_type, str) or token_type.lower() != "bearer":
            raise MicroAuthResponseError("The token endpoint answered with a non Bearer token")
        if not isinstance(access_token, str) or not access_token:
            raise MicroAuthResponseError("The token endpoint answered without an access token")
        expires_in = body.get("expires_in")
        refresh_token = body.get("refresh_token")
        id_token = body.get("id_token")
        scope = body.get("scope")
        return _TokenResponse(
            access_token=access_token,
            expires_in=expires_in if type(expires_in) is int and expires_in >= 0 else None,
            refresh_token=refresh_token
            if isinstance(refresh_token, str) and refresh_token
            else None,
            id_token=id_token if isinstance(id_token, str) and id_token else None,
            scope=scope if isinstance(scope, str) else None,
        )

    async def _verify_id_token(
        self,
        token: str,
        *,
        nonce: str | None,
        access_token: str | None,
        max_age: int | None,
        previous: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        claims = await verify_jwt(
            self._issuer,
            token,
            audience=self.client_id,
            allowed_types=_ID_TOKEN_TYPES,
            type_required=False,
            leeway=self.leeway,
            required_claims=("iss", "sub", "aud", "exp", "iat"),
        )
        audience = claims["aud"]
        azp = claims.get("azp")
        if isinstance(audience, list) and len(audience) > 1 and azp != self.client_id:
            raise TokenRejected("The ID token has several audiences and its azp isn't this app")
        if azp is not None and azp != self.client_id:
            raise TokenRejected("The ID token was issued to a different app (azp)")
        if nonce is not None:
            found = claims.get("nonce")
            if not isinstance(found, str) or not hmac.compare_digest(found, nonce):
                raise TokenRejected("The ID token's nonce doesn't match this sign in")
        at_hash = claims.get("at_hash")
        if (
            at_hash is not None
            and access_token is not None
            and (
                not isinstance(at_hash, str)
                or not hmac.compare_digest(at_hash, token_hash(access_token))
            )
        ):
            raise TokenRejected("The ID token's at_hash doesn't match the access token")
        if max_age is not None:
            auth_time = claims.get("auth_time")
            if type(auth_time) is not int:
                raise TokenRejected("The ID token has no auth_time, which max_age needs")
            if auth_time + max_age + self.leeway < time.time():
                raise TokenRejected("The sign in is older than max_age allows")
        if previous is not None and claims["sub"] != previous.get("sub"):
            raise TokenRejected("The refreshed ID token is for a different user")
        return claims

    async def login_redirect(
        self,
        request: Request,
        *,
        next: str | None = None,
        prompt: str | None = None,
        login_hint: str | None = None,
        max_age: int | None = None,
    ) -> Response:
        """Start a sign in and return the redirect to MicroAuth.

        Useful for your own routes, for example to make someone sign in
        again with ``prompt="login"`` before a sensitive action.
        """
        state = self._state(request)
        target = self.after_sign_in if next is None else safe_path(next)
        if target is None:
            raise ValueError("next must be a path on this site")
        if max_age is None:
            max_age = self.max_age
        metadata = await self._metadata()
        assert metadata.authorization_endpoint is not None
        verifier, challenge = _pkce_pair()
        state_value = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(self.scopes),
            "state": state_value,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        if prompt:
            params["prompt"] = prompt
        if login_hint:
            params["login_hint"] = login_hint
        if max_age is not None:
            params["max_age"] = str(max_age)
        if self.resource:
            params["resource"] = self.resource
        if metadata.pushed_authorization_request_endpoint is not None:
            request_uri = await self._push(metadata.pushed_authorization_request_endpoint, params)
            location = add_query(
                metadata.authorization_endpoint,
                {"client_id": self.client_id, "request_uri": request_uri},
            )
        else:
            location = add_query(metadata.authorization_endpoint, params)
        state.write_login(
            self._login_sealer.seal(
                {
                    "v": 1,
                    "s": state_value,
                    "n": nonce,
                    "cv": verifier,
                    "next": target,
                    "p": prompt,
                    "ma": max_age,
                    "exp": int(time.time()) + LOGIN_STATE_SECONDS,
                }
            )
        )
        return _redirect(location)

    async def _push(self, endpoint: str, params: Mapping[str, str]) -> str:
        """Push the authorization request (RFC 9126) and return its request_uri."""
        response = await self._post_form(endpoint, params)
        if response.status_code not in (200, 201):
            raise MicroAuthAPIError(
                response.status_code,
                f"the pushed authorization request was refused ({response.status_code})",
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise MicroAuthResponseError("The pushed authorization response is not JSON") from exc
        request_uri = body.get("request_uri") if isinstance(body, dict) else None
        if not isinstance(request_uri, str) or not request_uri:
            raise MicroAuthResponseError("The pushed authorization response has no request_uri")
        return request_uri

    async def _revoke(self, refresh_token: str) -> None:
        try:
            metadata = await self._metadata()
            if metadata.revocation_endpoint is None:
                return
            response = await self._post_form(
                metadata.revocation_endpoint,
                {"token": refresh_token, "token_type_hint": "refresh_token"},
            )
        except MicroAuthError as exc:
            logger.warning("microauth: revoking the refresh token failed (%s)", exc)
            return
        if response.status_code != 200:
            logger.warning(
                "microauth: revoking the refresh token answered %d", response.status_code
            )

    # Routes

    async def _login_route(self, request: Request) -> Response:
        return await self._start(request, signup=False)

    async def _signup_route(self, request: Request) -> Response:
        return await self._start(request, signup=True)

    async def _start(self, request: Request, *, signup: bool) -> Response:
        query = request.query_params
        raw_next = query.get("next")
        target = self.after_sign_in if raw_next is None else safe_path(raw_next)
        if target is None:
            return _page(
                400,
                "This sign in link can't be used",
                "It asks to return to a page that isn't on this site.",
                self.login_url(),
            )
        prompt = "create" if signup else query.get("prompt")
        if prompt is not None and prompt not in ("create", "login", "none"):
            return _page(400, "This sign in link can't be used", "It has an unknown prompt.")
        login_hint = query.get("login_hint")
        if login_hint is not None and len(login_hint) > 256:
            login_hint = None
        try:
            return await self.login_redirect(
                request, next=target, prompt=prompt, login_hint=login_hint
            )
        except MicroAuthError as exc:
            logger.error("microauth: can't start sign in (%s)", exc)
            return _page(
                503,
                "Sign in is unavailable",
                "Signing in isn't possible right now. Please try again in a moment.",
                self.login_url(next=target),
            )

    async def _callback_route(self, request: Request) -> Response:
        state = self._state(request)
        query = request.query_params
        retry = self.login_url()
        if any(len(query.getlist(name)) > 1 for name in ("iss", "state", "code", "error")):
            return _page(400, "Sign in failed", "The sign in response is malformed.", retry)

        # RFC 9207: the response must come from our issuer, compared exactly,
        # before anything else in it is looked at, error fields included.
        iss = query.get("iss")
        if iss is None or iss != self.issuer:
            logger.warning(
                "microauth: refused a sign in response %s",
                "without iss" if iss is None else "from another issuer",
            )
            return _page(
                400,
                "Sign in failed",
                "The sign in response didn't come from the expected server.",
                retry,
            )

        login = self._open_login_state(state.cookies.get(self.login_cookie))
        if login is None:
            if self._read_session(state) is not None:
                return _redirect(self.after_sign_in)
            return _page(
                400,
                "Sign in expired",
                "This sign in took too long or was started in another browser. Please start again.",
                retry,
            )
        retry = self.login_url(next=login["next"])
        returned_state = query.get("state")
        if not returned_state or not hmac.compare_digest(returned_state, login["s"]):
            logger.warning("microauth: refused a sign in response with the wrong state")
            return _page(
                400,
                "Sign in failed",
                "The sign in response doesn't match the sign in this browser started.",
                retry,
            )
        state.clear_login()

        error = query.get("error")
        if error is not None:
            if login.get("p") == "none" and error in _SILENT_ERRORS:
                return _redirect(login["next"])
            logger.info("microauth: sign in ended with %s", error[:64])
            message = (
                "Sign in was cancelled."
                if error == "access_denied"
                else "MicroAuth couldn't complete the sign in."
            )
            return _page(400, "Sign in didn't finish", message, retry)
        code = query.get("code")
        if not code:
            return _page(400, "Sign in failed", "The sign in response has no code.", retry)

        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": login["cv"],
        }
        if self.resource:
            data["resource"] = self.resource
        try:
            metadata = await self._metadata()
            tokens = await self._token_request(metadata, data)
            if tokens.id_token is None:
                raise TokenRejected("The token response has no ID token")
            max_age = login.get("ma")
            claims = await self._verify_id_token(
                tokens.id_token,
                nonce=login["n"],
                access_token=tokens.access_token,
                max_age=max_age if type(max_age) is int else None,
                previous=None,
            )
        except _TokenEndpointError as exc:
            logger.warning("microauth: exchanging the sign in code failed (%s)", exc.detail)
            return _page(400, "Sign in failed", "The sign in couldn't be completed.", retry)
        except TokenRejected as exc:
            logger.warning("microauth: refused the ID token (%s)", exc.reason)
            return _page(400, "Sign in failed", "The sign in couldn't be verified.", retry)
        except MicroAuthError as exc:
            logger.error("microauth: completing sign in failed (%s)", exc)
            return _page(
                503,
                "Sign in is unavailable",
                "Signing in isn't possible right now. Please try again in a moment.",
                retry,
            )
        ends_at = int(time.time()) + self.session_max_age
        state.write_session(self._session_from(tokens, tokens.id_token, claims, ends_at=ends_at))
        return _redirect(login["next"])

    def _open_login_state(self, raw: str | None) -> dict[str, Any] | None:
        if raw is None:
            return None
        login = self._login_sealer.unseal(raw)
        if login is None or login.get("v") != 1:
            return None
        expires = login.get("exp")
        if type(expires) is not int or expires < time.time():
            return None
        for key in ("s", "n", "cv", "next"):
            if not isinstance(login.get(key), str):
                return None
        if safe_path(login["next"]) is None:
            return None
        return login

    async def _logout_route(self, request: Request) -> Response:
        state = self._state(request)
        if not self.same_origin(request.headers):
            raise CrossSiteRequest()
        session = self._read_session(state)
        state.clear_session()
        if state.cookies.get(self.login_cookie) is not None:
            state.clear_login()
        if session is None:
            return _redirect(self.after_sign_out)
        if session.refresh_token is not None:
            await self._revoke(session.refresh_token)
        try:
            metadata = await self._metadata()
        except MicroAuthError as exc:
            logger.warning("microauth: signed out locally only (%s)", exc)
            return _redirect(self.after_sign_out)
        if metadata.end_session_endpoint is None:
            return _redirect(self.after_sign_out)
        return _redirect(
            add_query(
                metadata.end_session_endpoint,
                {
                    "id_token_hint": session.id_token,
                    "post_logout_redirect_uri": self.post_logout_redirect_uri,
                    "state": secrets.token_urlsafe(16),
                    "client_id": self.client_id,
                },
            )
        )

    async def _me_route(self, request: Request) -> Response:
        user = await self.user(request)
        return JSONResponse(user.to_dict(), headers={"Cache-Control": "no-store"})
