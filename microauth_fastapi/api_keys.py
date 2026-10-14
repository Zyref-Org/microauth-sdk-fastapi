"""Let signed in people manage their own API keys from your app.

``UserAuth(api_keys=True)`` asks MicroAuth for the reserved
``microauth:api_keys`` scope and keeps the access token in the session.
``auth.api_keys`` then calls MicroAuth's Account API with that token, so
your app manages keys for the signed in person only, and never holds a
credential that could touch anyone else's::

    @app.post("/settings/api-keys")
    async def create_key(request: Request):
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
        return {"secret": new.secret}  # shown once, never again

Creating and rolling a key needs a sign in from the last 10 minutes. When it
is older, MicroAuth answers with RFC 9470 ``insufficient_user_authentication``
and the SDK raises ``ReauthenticationRequired`` with a link that signs the
person in again and brings them back to the page they were on.
"""

from __future__ import annotations

import builtins
import logging
import re
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import httpx
from fastapi import Request

from ._time import parse_iso8601
from .client import USER_AGENT
from .exceptions import (
    AccountAPIError,
    AuthUnavailable,
    ErrorDetail,
    MicroAuthConfigurationError,
    MicroAuthResponseError,
    ReauthenticationRequired,
    SignInRequired,
)

if TYPE_CHECKING:
    from .login import UserAuth

logger = logging.getLogger("microauth")

ACCOUNT_API_PATH = "/api/v1/me/api-keys"
ACCOUNT_API_SCOPE = "microauth:api_keys"
ROLL_OVERLAP_HOURS = (0, 1, 24)
DEFAULT_REAUTH_MAX_AGE = 600
MAX_LOGIN_MAX_AGE = 86_400
_MAX_RESPONSE_BYTES = 1024 * 1024
_MAX_KEY_ID_LENGTH = 128
_CHALLENGE_PARAM = re.compile(r'([A-Za-z0-9_-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,"]*))')


@dataclass(frozen=True, slots=True)
class APIKeyResource:
    """An API or MCP server a key works at."""

    identifier: str
    name: str


@dataclass(frozen=True, slots=True)
class APIKeyApp:
    """The app a key was created in. Keys made on MicroAuth's own pages have none."""

    client_id: str
    name: str


@dataclass(frozen=True, slots=True)
class APIKey:
    """One of the signed in person's API keys. The secret is never included."""

    id: str
    name: str
    prefix: str
    resources: tuple[APIKeyResource, ...]
    permissions: tuple[str, ...]
    created_at: datetime
    created_by_app: APIKeyApp | None
    expires_at: datetime | None
    last_used_at: datetime | None
    old_secret_expires_at: datetime | None


@dataclass(frozen=True, slots=True)
class NewAPIKey:
    """A key that was just created or rolled, with its secret.

    MicroAuth shows the secret this once and keeps only its hash, so show it
    to the person right away and don't store or log it.
    """

    key: APIKey
    secret: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class APIKeyPermission:
    name: str
    description: str
    sensitive: bool


@dataclass(frozen=True, slots=True)
class APIKeyResourceOption:
    """A server the person can put on a key, with the permissions they can give it."""

    identifier: str
    name: str
    permissions: tuple[APIKeyPermission, ...]


@dataclass(frozen=True, slots=True)
class APIKeyOptions:
    """What the signed in person may put on a new key.

    ``max_days`` is the longest lifetime the owner allows, or None for no
    limit. ``allow_no_expiry`` says whether keys may never expire.
    """

    max_days: int | None
    allow_no_expiry: bool
    resources: tuple[APIKeyResourceOption, ...]


# Parsing


def _fail(what: str, problem: str) -> MicroAuthResponseError:
    return MicroAuthResponseError(f"The Account API answered with {what} that {problem}")


def _object(value: Any, what: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise _fail(what, "is not a JSON object")
    return value


def _text(data: Mapping[str, Any], name: str, what: str) -> str:
    value = data.get(name)
    if not isinstance(value, str):
        raise _fail(what, f"has no {name}")
    return value


def _items(data: Mapping[str, Any], name: str, what: str) -> builtins.list[Any]:
    value = data.get(name)
    if not isinstance(value, builtins.list):
        raise _fail(what, f"has no {name} list")
    return value


def _when(data: Mapping[str, Any], name: str, what: str, *, optional: bool) -> datetime | None:
    value = data.get(name)
    if value is None and optional:
        return None
    if not isinstance(value, str):
        raise _fail(what, f"has no {name}")
    try:
        parsed = parse_iso8601(value)
    except ValueError:
        raise _fail(what, f"has an unreadable {name}") from None
    if parsed.tzinfo is None:
        raise _fail(what, f"has a {name} without a time zone")
    return parsed


def parse_key(value: Any) -> APIKey:
    data = _object(value, "a key")
    app = data.get("created_by_app")
    if app is not None:
        app_data = _object(app, "a key's created_by_app")
        created_by_app: APIKeyApp | None = APIKeyApp(
            client_id=_text(app_data, "client_id", "a key's created_by_app"),
            name=_text(app_data, "name", "a key's created_by_app"),
        )
    else:
        created_by_app = None
    resources = []
    for item in _items(data, "resources", "a key"):
        resource = _object(item, "a key resource")
        resources.append(
            APIKeyResource(
                identifier=_text(resource, "identifier", "a key resource"),
                name=_text(resource, "name", "a key resource"),
            )
        )
    permissions = _items(data, "permissions", "a key")
    if not all(isinstance(permission, str) for permission in permissions):
        raise _fail("a key", "has a permission that isn't a string")
    created_at = _when(data, "created_at", "a key", optional=False)
    assert created_at is not None
    return APIKey(
        id=_text(data, "id", "a key"),
        name=_text(data, "name", "a key"),
        prefix=_text(data, "prefix", "a key"),
        resources=tuple(resources),
        permissions=tuple(permissions),
        created_at=created_at,
        created_by_app=created_by_app,
        expires_at=_when(data, "expires_at", "a key", optional=True),
        last_used_at=_when(data, "last_used_at", "a key", optional=True),
        old_secret_expires_at=_when(data, "old_secret_expires_at", "a key", optional=True),
    )


def parse_new_key(value: Any) -> NewAPIKey:
    data = _object(value, "a new key")
    secret = _text(data, "secret", "a new key")
    if not secret:
        raise _fail("a new key", "has an empty secret")
    return NewAPIKey(key=parse_key(data.get("key")), secret=secret)


def parse_keys(value: Any) -> builtins.list[APIKey]:
    data = _object(value, "a key list")
    return [parse_key(item) for item in _items(data, "keys", "a key list")]


def parse_options(value: Any) -> APIKeyOptions:
    data = _object(value, "key options")
    max_days = data.get("max_days")
    if max_days is not None and (type(max_days) is not int or max_days < 1):
        raise _fail("key options", "have an invalid max_days")
    allow_no_expiry = data.get("allow_no_expiry")
    if type(allow_no_expiry) is not bool:
        raise _fail("key options", "have no allow_no_expiry")
    resources = []
    for item in _items(data, "resources", "key options"):
        resource = _object(item, "a resource option")
        permissions = []
        for entry in _items(resource, "permissions", "a resource option"):
            permission = _object(entry, "a permission option")
            sensitive = permission.get("sensitive")
            if type(sensitive) is not bool:
                raise _fail("a permission option", "has no sensitive flag")
            permissions.append(
                APIKeyPermission(
                    name=_text(permission, "name", "a permission option"),
                    description=_text(permission, "description", "a permission option"),
                    sensitive=sensitive,
                )
            )
        resources.append(
            APIKeyResourceOption(
                identifier=_text(resource, "identifier", "a resource option"),
                name=_text(resource, "name", "a resource option"),
                permissions=tuple(permissions),
            )
        )
    return APIKeyOptions(
        max_days=max_days, allow_no_expiry=allow_no_expiry, resources=tuple(resources)
    )


def parse_problem(status: int, body: Any) -> AccountAPIError:
    """The typed error for an RFC 9457 problem response."""
    title = detail = None
    errors: builtins.list[ErrorDetail] = []
    if isinstance(body, dict):
        title = body.get("title") if isinstance(body.get("title"), str) else None
        detail = body.get("detail") if isinstance(body.get("detail"), str) else None
        found = body.get("errors")
        for item in found if isinstance(found, builtins.list) else ():
            if isinstance(item, dict) and isinstance(item.get("message"), str):
                location = item.get("location")
                errors.append(
                    ErrorDetail(
                        message=item["message"],
                        location=location if isinstance(location, str) else None,
                        value=item.get("value"),
                    )
                )
    message = detail or title or f"the Account API answered {status}"
    return AccountAPIError(status, message[:500], title=title, errors=tuple(errors))


def parse_challenge(header: str | None) -> dict[str, str]:
    """The parameters of a ``WWW-Authenticate: Bearer`` challenge."""
    if not header:
        return {}
    scheme, _, rest = header.strip().partition(" ")
    if scheme.lower() != "bearer":
        return {}
    params: dict[str, str] = {}
    for match in _CHALLENGE_PARAM.finditer(rest):
        quoted = match.group(2)
        value = re.sub(r"\\(.)", r"\1", quoted) if quoted is not None else match.group(3)
        params.setdefault(match.group(1).lower(), value)
    return params


def _challenge_max_age(value: str | None) -> int:
    if value is None or not re.fullmatch(r"[0-9]{1,5}", value):
        return DEFAULT_REAUTH_MAX_AGE
    return min(int(value), MAX_LOGIN_MAX_AGE)


def _key_path(key_id: str) -> str:
    if not isinstance(key_id, str) or not key_id or len(key_id) > _MAX_KEY_ID_LENGTH:
        raise ValueError("key_id must be the id of one of the person's keys")
    return "/" + quote(key_id, safe="")


def _names(values: Iterable[str], what: str) -> builtins.list[str]:
    if isinstance(values, str):
        raise TypeError(f"{what} must be a list of strings, not one string")
    found = builtins.list(values)
    if not all(isinstance(value, str) and value for value in found):
        raise TypeError(f"{what} must be a list of non empty strings")
    return found


# The client


class APIKeys:
    """The signed in person's API keys, through MicroAuth's Account API.

    Every method takes the current request and acts for whoever is signed in
    on it. Nobody signed in raises ``SignInRequired``. A session MicroAuth
    no longer accepts is signed out and raises ``SignInRequired`` too.
    Refusals raise ``AccountAPIError`` with MicroAuth's ``detail``.

    Calls that change keys are unsafe requests, so they pass the same
    origin check as everything else that uses the session.
    """

    def __init__(self, auth: UserAuth) -> None:
        self._auth = auth
        self.url = f"{auth.issuer}{ACCOUNT_API_PATH}"

    async def options(self, request: Request) -> APIKeyOptions:
        """The servers, permissions and lifetimes this person can put on a key."""
        return parse_options(await self._call(request, "GET", "/options", expect=200))

    async def list(self, request: Request) -> builtins.list[APIKey]:
        """The person's keys, without secrets."""
        return parse_keys(await self._call(request, "GET", "", expect=200))

    async def create(
        self,
        request: Request,
        *,
        name: str,
        resources: Iterable[str],
        permissions: Iterable[str],
        expires_in_days: int | None,
    ) -> NewAPIKey:
        """Make a key. Needs a recent sign in, else ``ReauthenticationRequired``.

        ``resources`` are server identifiers and ``permissions`` permission
        names, both from ``options()``. ``expires_in_days=None`` asks for a
        key that never expires, which the owner may not allow.
        """
        if not isinstance(name, str):
            raise TypeError("name must be a string")
        if expires_in_days is not None and (
            type(expires_in_days) is not int or expires_in_days < 1
        ):
            raise ValueError("expires_in_days must be a positive number of days or None")
        body = {
            "name": name,
            "resources": _names(resources, "resources"),
            "permissions": _names(permissions, "permissions"),
            "expires_in_days": expires_in_days,
        }
        return parse_new_key(await self._call(request, "POST", "", json=body, expect=201))

    async def rename(self, request: Request, key_id: str, name: str) -> APIKey:
        """Give a key a new name."""
        if not isinstance(name, str):
            raise TypeError("name must be a string")
        path = _key_path(key_id)
        return parse_key(await self._call(request, "PATCH", path, json={"name": name}, expect=200))

    async def roll(
        self, request: Request, key_id: str, *, old_secret_lasts_hours: int = 0
    ) -> NewAPIKey:
        """Give a key a new secret with the same settings.

        The old secret keeps working for ``old_secret_lasts_hours``: 0, 1 or
        24. Needs a recent sign in, else ``ReauthenticationRequired``.
        """
        if type(old_secret_lasts_hours) is not int or (
            old_secret_lasts_hours not in ROLL_OVERLAP_HOURS
        ):
            raise ValueError("old_secret_lasts_hours must be 0, 1 or 24")
        body = {"old_secret_lasts_hours": old_secret_lasts_hours}
        path = f"{_key_path(key_id)}/roll"
        return parse_new_key(await self._call(request, "POST", path, json=body, expect=200))

    async def revoke(self, request: Request, key_id: str) -> None:
        """Revoke one key. It stops working within the cache lifetime of the APIs."""
        await self._call(request, "DELETE", _key_path(key_id), expect=204)

    async def revoke_all(self, request: Request) -> None:
        """Revoke every key the person has."""
        await self._call(request, "DELETE", "", expect=204)

    async def _call(
        self,
        request: Request,
        method: str,
        path: str,
        *,
        expect: int,
        json: Mapping[str, Any] | None = None,
    ) -> Any:
        auth = self._auth
        session = await auth._current(request)
        if session is None:
            raise SignInRequired()
        if session.access_token is None or not session.api_keys:
            raise ReauthenticationRequired(auth.login_url(next=auth._return_path(request)))
        if session.expires_at <= time.time():
            logger.error(
                "microauth: the session's access token expired and couldn't be refreshed, "
                "so API keys can't be managed right now"
            )
            raise AuthUnavailable()
        url = self.url + path
        headers = {
            "Authorization": f"Bearer {session.access_token}",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        try:
            response = await auth._http().request(
                method, url, json=json, headers=headers, timeout=auth._timeout
            )
        except httpx.HTTPError as exc:
            raise AccountAPIError(0, f"could not reach {url} ({type(exc).__name__})") from exc
        if response.status_code == expect:
            return None if expect == 204 else _json(response)
        raise self._refusal(request, response)

    def _refusal(self, request: Request, response: httpx.Response) -> Exception:
        auth = self._auth
        status = response.status_code
        challenge = parse_challenge(response.headers.get("www-authenticate"))
        error = challenge.get("error")
        if status == 401 and error == "insufficient_user_authentication":
            max_age = _challenge_max_age(challenge.get("max_age"))
            return ReauthenticationRequired(
                auth.login_url(next=auth._return_path(request), max_age=max_age), max_age
            )
        if status == 401:
            logger.info(
                "microauth: MicroAuth no longer accepts this session's access token, so the "
                "user is signed out"
            )
            auth._state(request).clear_session()
            return SignInRequired()
        if status == 403 and error == "insufficient_scope":
            return MicroAuthConfigurationError(
                "MicroAuth won't let this app manage API keys: it refused the access token "
                f"with insufficient_scope, although the sign in asked for {ACCOUNT_API_SCOPE}. "
                "Only web applications can get that scope, so MICROAUTH_CLIENT_ID must be a "
                "web application."
            )
        try:
            body = response.json() if len(response.content) <= _MAX_RESPONSE_BYTES else None
        except ValueError:
            body = None
        return parse_problem(status, body)


def _json(response: httpx.Response) -> Any:
    if len(response.content) > _MAX_RESPONSE_BYTES:
        raise MicroAuthResponseError("The Account API answer is too large")
    try:
        return response.json()
    except ValueError:
        raise MicroAuthResponseError("The Account API answer is not JSON") from None
