"""API keys that people create for their own accounts, and how they're checked.

A key looks like ``cms_<40 random characters><6 character checksum>``: a
prefix the service owner picks, an underscore, then 46 base62 characters.
The checksum is CRC-32 of everything before it, written in base62, so a
mistyped or made up key is refused here without a network call.

A well formed key is checked with token introspection (RFC 7662) at the
issuer, using this API's server credentials. MicroAuth answers whether the
key is active at this API, whose it is and what it may do right now.

Answers are cached by the SHA-256 of the key, never the key itself, for as
long as the answer's ``Cache-Control`` allows and at most five minutes.
When MicroAuth can't be reached, an active answer keeps working for
``stale_if_error`` seconds past its expiry, and a key without one gets 503.
Errors are never cached.
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import logging
import math
import re
import time
import zlib
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Protocol

import httpx

from ._limits import Gcra, KeyLimits, MemoryGcra, RedisGcra, RequestThrottled
from ._oidc import HttpClient, Issuer, TokenRejected, basic_credentials
from .client import USER_AGENT
from .exceptions import LimitBackendUnavailable, MicroAuthConfigurationError, MicroAuthError
from .limiter import DEFAULT_REDIS_MAX_CONNECTIONS

logger = logging.getLogger("microauth")

KEY_PATTERN = re.compile(r"[a-z][a-z0-9]{1,9}_[0-9A-Za-z]{46}")
BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
CHECKSUM_LENGTH = 6
DISPLAY_RANDOM_CHARACTERS = 6
DEFAULT_CACHE_SECONDS = 30
MAX_CACHE_SECONDS = 300
DEFAULT_STALE_IF_ERROR = 600
MAX_STALE_IF_ERROR = 86_400
DEFAULT_UNKNOWN_KEY_LIMIT = 20
CREDENTIAL_SETTINGS = "MICROAUTH_RESOURCE_CLIENT_ID and MICROAUTH_RESOURCE_SECRET"
API_CREDENTIALS_MISSING = (
    f"API keys need this API's server credentials. Set {CREDENTIAL_SETTINGS}, or "
    "pass resource_client_id= and resource_secret=. They're on the API's page "
    "under APIs and MCP servers in the MicroAuth dashboard."
)
MCP_CREDENTIALS_MISSING = (
    f"API keys need this MCP server's server credentials. Set {CREDENTIAL_SETTINGS}, "
    "or pass resource_client_id= and resource_secret=. They're on the MCP server's "
    "page in the MicroAuth dashboard: open APIs and MCP servers, then the server, "
    "then Server credentials."
)
INACTIVE_REASON = "The API key is unknown, revoked or expired"
_MAX_ANSWER_BYTES = 64 * 1024
_MAX_MEMORY_ANSWERS = 10_000
_MAX_WARNED_KEYS = 1024
_LOG_EVERY_SECONDS = 60.0
_ANSWER_VERSION = 1


# Format


def key_checksum(body: str) -> str:
    """The 6 character base62 CRC-32 of ``body``, most significant digit first."""
    value = zlib.crc32(body.encode("ascii"))
    digits = ""
    while value:
        value, digit = divmod(value, 62)
        digits = BASE62[digit] + digits
    return digits.rjust(CHECKSUM_LENGTH, "0")


def is_key_candidate(value: str) -> bool:
    """Whether a bearer value is checked as an API key. JWTs always have dots."""
    return "." not in value


def key_problem(value: str) -> str | None:
    """Why ``value`` can't be a key, or None when its format and checksum are right."""
    if not KEY_PATTERN.fullmatch(value):
        return "The API key is malformed"
    if key_checksum(value[:-CHECKSUM_LENGTH]) != value[-CHECKSUM_LENGTH:]:
        return "The API key is mistyped: its checksum doesn't match"
    return None


def display_prefix(key: str) -> str:
    """What lists show for a key, such as ``cms_Ab12Cd``. Not a secret."""
    prefix, _, rest = key.partition("_")
    return f"{prefix}_{rest[:DISPLAY_RANDOM_CHARACTERS]}"


def key_hash(key: str) -> str:
    return hashlib.sha256(key.encode("ascii")).hexdigest()


def cache_lifetime(header: str | None) -> int:
    """Seconds an introspection answer may be cached, from its Cache-Control.

    ``no-store`` and ``no-cache`` mean not at all. ``max-age`` is clamped to
    0 to 300 seconds, and an unreadable or repeated one counts as 0, the
    way RFC 9111 treats invalid freshness. Without ``max-age`` it is 30.
    """
    if header is None:
        return DEFAULT_CACHE_SECONDS
    max_ages: list[str] = []
    for part in header.split(","):
        name, _, value = part.partition("=")
        name = name.strip().lower()
        if name in ("no-store", "no-cache"):
            return 0
        if name == "max-age":
            max_ages.append(value.strip().strip('"'))
    if not max_ages:
        return DEFAULT_CACHE_SECONDS
    if len(max_ages) > 1 or not re.fullmatch(r"[0-9]{1,10}", max_ages[0]):
        return 0
    return min(int(max_ages[0]), MAX_CACHE_SECONDS)


# Answers


@dataclass(frozen=True, slots=True)
class KeyAnswer:
    """An active introspection answer that passed every check."""

    key_id: str
    sub: str
    scopes: frozenset[str]
    audience: tuple[str, ...]
    issuer: str
    issued_at: int
    expires_at: int | None
    requests_per_minute: int | None
    claims: Mapping[str, Any]


class _Refused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def parse_active(document: Mapping[str, Any], *, issuer: str, resource: str) -> KeyAnswer:
    """The checked answer, or ``_Refused`` saying why it can't be used here."""
    if document.get("active") is not True:
        raise _Refused("it isn't active")
    if document.get("token_use") != "api_key":
        raise _Refused("its token_use isn't api_key")
    key_id = document.get("key_id")
    if not isinstance(key_id, str) or not key_id:
        raise _Refused("it has no key_id")
    sub = document.get("sub")
    if not isinstance(sub, str) or not sub:
        raise _Refused("it has no sub")
    scope = document.get("scope")
    if not isinstance(scope, str):
        raise _Refused("it has no scope")
    aud = document.get("aud")
    if isinstance(aud, str):
        audience: tuple[str, ...] = (aud,)
    elif isinstance(aud, list) and all(isinstance(item, str) for item in aud):
        audience = tuple(aud)
    else:
        raise _Refused("it has no valid aud")
    if resource not in audience:
        raise _Refused(f"its aud doesn't name this API ({resource})")
    if document.get("iss") != issuer:
        raise _Refused(f"its iss isn't {issuer}")
    iat = document.get("iat")
    if type(iat) is not int:
        raise _Refused("it has no valid iat")
    exp = document.get("exp")
    if exp is not None and type(exp) is not int:
        raise _Refused("its exp isn't a number of seconds")
    rpm = document.get("requests_per_minute")
    if rpm is not None and (type(rpm) is not int or rpm < 1):
        raise _Refused("its requests_per_minute isn't a positive integer")
    return KeyAnswer(
        key_id=key_id,
        sub=sub,
        scopes=frozenset(scope.split()),
        audience=audience,
        issuer=issuer,
        issued_at=iat,
        expires_at=exp,
        requests_per_minute=rpm,
        claims=MappingProxyType(dict(document)),
    )


class KeyRejected(TokenRejected):
    """A malformed, mistyped or inactive key. These count toward the unknown key throttle."""


class KeyCheckUnavailable(MicroAuthError):
    """Keys can't be checked right now. Already logged; the caller gets 503."""


class KeyCheckMisconfigured(KeyCheckUnavailable):
    """MicroAuth refused this API's server credentials, or offers no introspection."""


class _Outage(Exception):
    pass


# Cache


@dataclass(frozen=True, slots=True)
class _Entry:
    answer: KeyAnswer | None
    fresh_until: float
    stale_until: float


class AnswerCache(Protocol):
    async def get(self, digest: str, now: float) -> _Entry | None: ...

    async def put(self, digest: str, entry: _Entry, now: float) -> None: ...

    async def delete(self, digest: str) -> None: ...

    async def aclose(self) -> None: ...


class MemoryAnswers:
    """Answers in this process, by key hash, at most ``max_entries`` of them."""

    def __init__(self, *, max_entries: int = _MAX_MEMORY_ANSWERS) -> None:
        self._entries: OrderedDict[str, _Entry] = OrderedDict()
        self._max = max_entries

    def peek(self, digest: str, now: float) -> _Entry | None:
        entry = self._entries.get(digest)
        if entry is not None and entry.stale_until <= now:
            del self._entries[digest]
            return None
        return entry

    async def get(self, digest: str, now: float) -> _Entry | None:
        return self.peek(digest, now)

    async def put(self, digest: str, entry: _Entry, now: float) -> None:
        self._entries[digest] = entry
        self._entries.move_to_end(digest)
        while len(self._entries) > self._max:
            self._entries.popitem(last=False)

    async def delete(self, digest: str) -> None:
        self._entries.pop(digest, None)

    async def aclose(self) -> None:
        self._entries.clear()


class RedisAnswers:
    """Answers in Redis, shared by every worker, each with a TTL."""

    def __init__(
        self, redis: Callable[[], Any], namespace: str, *, issuer: str, resource: str
    ) -> None:
        self._redis = redis
        self._namespace = namespace
        self._issuer = issuer
        self._resource = resource

    def name(self, digest: str) -> str:
        return f"{self._namespace}:answer:{digest}"

    async def get(self, digest: str, now: float) -> _Entry | None:
        raw = await self._redis().get(self.name(digest))
        if raw is None:
            return None
        try:
            stored = json.loads(raw)
            fresh_until = float(stored["f"])
            stale_until = float(stored["s"])
            document = stored["a"]
            if stored.get("v") != _ANSWER_VERSION:
                return None
            answer = (
                None
                if document is None
                else parse_active(document, issuer=self._issuer, resource=self._resource)
            )
        except (ValueError, TypeError, KeyError, AttributeError, _Refused):
            return None
        if stale_until <= now:
            return None
        return _Entry(answer, fresh_until, stale_until)

    async def put(self, digest: str, entry: _Entry, now: float) -> None:
        ttl_ms = math.ceil((entry.stale_until - now) * 1000)
        if ttl_ms <= 0:
            return
        value = json.dumps(
            {
                "v": _ANSWER_VERSION,
                "f": entry.fresh_until,
                "s": entry.stale_until,
                "a": None if entry.answer is None else dict(entry.answer.claims),
            },
            separators=(",", ":"),
        )
        await self._redis().set(self.name(digest), value, px=ttl_ms)

    async def delete(self, digest: str) -> None:
        await self._redis().delete(self.name(digest))

    async def aclose(self) -> None:
        return None


class RedisHandle:
    """A Redis client made on first use and made again after ``aclose()``.

    A client passed in is externally owned and never closed here.
    """

    def __init__(self, url: str | None, client: Any | None) -> None:
        self._url = url
        self._client = client
        self._owned = client is None

    def __call__(self) -> Any:
        if self._client is None:
            assert self._url is not None
            try:
                import redis.asyncio as aioredis
            except ImportError as exc:  # pragma: no cover
                raise MicroAuthConfigurationError(
                    "Redis was configured but the redis package is not installed. "
                    "Install it with pip install 'microauth-fastapi[redis]'."
                ) from exc
            pool = aioredis.BlockingConnectionPool.from_url(
                self._url,
                max_connections=DEFAULT_REDIS_MAX_CONNECTIONS,
                timeout=1.0,
                socket_timeout=1.0,
                socket_connect_timeout=1.0,
            )
            self._client = aioredis.Redis.from_pool(pool)
        return self._client

    async def aclose(self) -> None:
        if not self._owned or self._client is None:
            return
        client, self._client = self._client, None
        try:
            await client.aclose()
        except Exception:  # pragma: no cover
            logger.exception("microauth: closing the Redis client for API keys failed")


# Checks


class KeyIntrospector:
    """Checks keys at the issuer's introspection endpoint, with a cache in front."""

    def __init__(
        self,
        issuer: Issuer,
        http: Callable[[], httpx.AsyncClient],
        answers: AnswerCache,
        *,
        resource: str,
        basic: str,
        timeout: float,
        leeway: float,
        stale_if_error: float,
        credential_settings: str = CREDENTIAL_SETTINGS,
    ) -> None:
        self._issuer = issuer
        self._http = http
        self.answers = answers
        self._resource = resource
        self._basic = basic
        self._credential_settings = credential_settings
        self._timeout = timeout
        self.leeway = leeway
        self.stale_if_error = stale_if_error
        self.clock: Callable[[], float] = time.time
        self._flights: dict[str, asyncio.Future[KeyAnswer | None]] = {}
        self._warned: OrderedDict[str, None] = OrderedDict()
        self._logged: dict[str, float] = {}

    async def check(self, key: str) -> KeyAnswer:
        """The active answer for ``key``.

        Raises ``KeyRejected`` for a key that isn't valid here, and
        ``KeyCheckUnavailable`` when there is no usable answer.
        """
        problem = key_problem(key)
        if problem is not None:
            raise KeyRejected(problem)
        answer = await self._answer(key_hash(key), key)
        if answer is None:
            raise KeyRejected(INACTIVE_REASON)
        if answer.expires_at is not None and answer.expires_at + self.leeway < self.clock():
            raise KeyRejected("The API key has expired")
        return answer

    async def _answer(self, digest: str, key: str) -> KeyAnswer | None:
        if isinstance(self.answers, MemoryAnswers):
            now = self.clock()
            entry = self.answers.peek(digest, now)
            if entry is not None and now < entry.fresh_until:
                return entry.answer
        flight = self._flights.get(digest)
        if flight is None:
            flight = asyncio.ensure_future(self._resolve(digest, key))
            self._flights[digest] = flight
            flight.add_done_callback(functools.partial(self._landed, digest))
        return await asyncio.shield(flight)

    def _landed(self, digest: str, flight: asyncio.Future[KeyAnswer | None]) -> None:
        if self._flights.get(digest) is flight:
            del self._flights[digest]
        if not flight.cancelled():
            flight.exception()

    async def _resolve(self, digest: str, key: str) -> KeyAnswer | None:
        entry = await self._cached(digest)
        if entry is not None and self.clock() < entry.fresh_until:
            return entry.answer
        try:
            answer, lifetime = await self._introspect(key, digest)
        except KeyCheckMisconfigured as exc:
            if self._should_log("misconfigured"):
                logger.error(
                    "microauth: API keys can't be checked: %s. Callers with API keys get 503 "
                    "until this is fixed.",
                    exc,
                )
            raise
        except _Outage as exc:
            if entry is not None and entry.answer is not None and self.clock() < entry.stale_until:
                if self._should_log("stale"):
                    logger.warning(
                        "microauth: MicroAuth can't check API keys right now (%s), so cached "
                        "answers keep working for up to %d seconds past their expiry",
                        exc,
                        self.stale_if_error,
                    )
                return entry.answer
            if self._should_log("outage"):
                logger.error("microauth: API keys can't be checked right now (%s)", exc)
            raise KeyCheckUnavailable(str(exc)) from None
        await self._store(digest, answer, lifetime)
        return answer

    async def _cached(self, digest: str) -> _Entry | None:
        try:
            return await self.answers.get(digest, self.clock())
        except Exception as exc:  # noqa: BLE001 - a broken cache only costs a call to MicroAuth
            if self._should_log("cache"):
                logger.warning(
                    "microauth: the API key cache can't be read (%s), so MicroAuth is asked",
                    type(exc).__name__,
                )
            return None

    async def _store(self, digest: str, answer: KeyAnswer | None, lifetime: int) -> None:
        now = self.clock()
        try:
            if lifetime <= 0:
                await self.answers.delete(digest)
                return
            fresh_until = now + lifetime
            stale_until = fresh_until + (self.stale_if_error if answer is not None else 0)
            await self.answers.put(digest, _Entry(answer, fresh_until, stale_until), now)
        except Exception as exc:  # noqa: BLE001 - a broken cache only costs a call to MicroAuth
            if self._should_log("cache"):
                logger.warning(
                    "microauth: the API key cache can't be written (%s)", type(exc).__name__
                )

    async def _introspect(self, key: str, digest: str) -> tuple[KeyAnswer | None, int]:
        try:
            metadata = await self._issuer.metadata()
        except MicroAuthError as exc:
            raise _Outage(f"the discovery document can't be loaded: {exc}") from None
        endpoint = metadata.introspection_endpoint
        if endpoint is None:
            raise KeyCheckMisconfigured(
                f"the discovery document of {self._issuer.issuer} lists no introspection_endpoint"
            )
        try:
            response = await self._http().post(
                endpoint,
                data={"token": key},
                headers={
                    "Authorization": self._basic,
                    "Accept": "application/json",
                    "User-Agent": USER_AGENT,
                },
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            raise _Outage(f"could not reach {endpoint} ({type(exc).__name__})") from None
        status = response.status_code
        if status in (400, 401):
            raise KeyCheckMisconfigured(
                f"MicroAuth refused this API's server credentials ({status}). Check "
                f"{self._credential_settings}: they must be the server credentials of "
                f"{self._resource} from the MicroAuth dashboard"
            )
        if status != 200:
            raise _Outage(f"the introspection endpoint answered {status}")
        if len(response.content) > _MAX_ANSWER_BYTES:
            raise _Outage("the introspection answer is too large")
        try:
            document = response.json()
        except ValueError:
            raise _Outage("the introspection answer is not JSON") from None
        if not isinstance(document, dict) or type(document.get("active")) is not bool:
            raise _Outage("the introspection answer has no active member")
        lifetime = cache_lifetime(response.headers.get("cache-control"))
        if document["active"] is False:
            return None, lifetime
        try:
            answer = parse_active(document, issuer=self._issuer.issuer, resource=self._resource)
            if answer.expires_at is not None and answer.expires_at + self.leeway < self.clock():
                raise _Refused("its exp has passed")
        except _Refused as exc:
            self._warn_once(digest, document, exc.reason)
            return None, lifetime
        return answer, lifetime

    def _warn_once(self, digest: str, document: Mapping[str, Any], reason: str) -> None:
        if digest in self._warned:
            return
        self._warned[digest] = None
        while len(self._warned) > _MAX_WARNED_KEYS:
            self._warned.popitem(last=False)
        key_id = document.get("key_id")
        logger.warning(
            "microauth: refused API key %s because MicroAuth's answer can't be used here: %s",
            key_id[:64] if isinstance(key_id, str) and key_id else "without a key_id",
            reason,
        )

    def _should_log(self, kind: str) -> bool:
        now = time.monotonic()
        last = self._logged.get(kind)
        if last is not None and now - last < _LOG_EVERY_SECONDS:
            return False
        self._logged[kind] = now
        return True

    async def aclose(self) -> None:
        flights = list(self._flights.values())
        self._flights.clear()
        for flight in flights:
            flight.cancel()
        await self.answers.aclose()


def _namespace(issuer: str, resource: str) -> str:
    tag = hashlib.sha256(f"{issuer}\0{resource}".encode()).hexdigest()[:32]
    return f"ma:keys:{tag}"


class KeyChecks:
    """Everything an API needs to accept its users' API keys.

    Shared by TokenAuth, McpAuth and MicroAuthTokenVerifier. With
    ``enforce_limits=False`` (MicroAuthTokenVerifier, which never sees the
    request) neither the per person limit nor the unknown key throttle
    applies.
    """

    def __init__(
        self,
        issuer: Issuer,
        http: HttpClient,
        *,
        resource: str,
        client_id: str | None,
        client_secret: str | None,
        timeout: float,
        leeway: float,
        stale_if_error: float,
        unknown_key_limit: int,
        redis_url: str | None,
        redis_client: Any | None,
        enforce_limits: bool = True,
        credential_settings: str = CREDENTIAL_SETTINGS,
        credentials_missing: str = API_CREDENTIALS_MISSING,
    ) -> None:
        client_id = (client_id or "").strip()
        client_secret = (client_secret or "").strip()
        if not client_id or not client_secret:
            raise MicroAuthConfigurationError(credentials_missing)
        if (
            isinstance(stale_if_error, bool)
            or not isinstance(stale_if_error, (int, float))
            or not 0 <= stale_if_error <= MAX_STALE_IF_ERROR
        ):
            raise MicroAuthConfigurationError(
                f"stale_if_error must be between 0 and {MAX_STALE_IF_ERROR} seconds"
            )
        if (
            isinstance(unknown_key_limit, bool)
            or not isinstance(unknown_key_limit, int)
            or unknown_key_limit < 0
        ):
            raise MicroAuthConfigurationError(
                "unknown_key_limit must be a whole number of keys per minute, or 0 to turn it off"
            )
        self.resource = resource
        self.enforce_limits = enforce_limits
        namespace = _namespace(issuer.issuer, resource)
        self.redis: RedisHandle | None = (
            RedisHandle(redis_url, redis_client) if redis_url or redis_client is not None else None
        )
        answers: AnswerCache
        gcra: Gcra
        if self.redis is not None:
            answers = RedisAnswers(self.redis, namespace, issuer=issuer.issuer, resource=resource)
            gcra = RedisGcra(self.redis)
        else:
            answers = MemoryAnswers()
            gcra = MemoryGcra()
        self.introspector = KeyIntrospector(
            issuer,
            http,
            answers,
            resource=resource,
            basic=basic_credentials(client_id, client_secret),
            timeout=timeout,
            leeway=leeway,
            stale_if_error=stale_if_error,
            credential_settings=credential_settings,
        )
        self.limits = KeyLimits(gcra, namespace, unknown_key_limit=unknown_key_limit)
        self._warned_unenforced = False

    @property
    def clock(self) -> Callable[[], float]:
        return self.introspector.clock

    @clock.setter
    def clock(self, value: Callable[[], float]) -> None:
        self.introspector.clock = value

    async def verify(self, key: str, address: str | None) -> KeyAnswer:
        """The key's answer once every limit allows it.

        Raises ``KeyRejected``, ``RequestThrottled`` or ``KeyCheckUnavailable``.
        """
        if not self.enforce_limits:
            answer = await self.introspector.check(key)
            if answer.requests_per_minute is not None and not self._warned_unenforced:
                self._warned_unenforced = True
                logger.warning(
                    "microauth: MicroAuthTokenVerifier doesn't enforce requests_per_minute for "
                    "API keys, because the MCP SDK gives it no way to answer 429. Use McpAuth "
                    "to enforce it."
                )
            return answer
        where = address or "-"
        try:
            wait = await self.limits.unknown_key_wait(where, self.clock())
            if wait > 0:
                raise RequestThrottled(wait, "Too many unknown API keys came from this address")
            try:
                answer = await self.introspector.check(key)
            except KeyRejected:
                await self.limits.count_unknown_key(where, self.clock())
                raise
            if answer.requests_per_minute is not None:
                wait = await self.limits.take_request(
                    answer.sub, answer.requests_per_minute, self.clock()
                )
                if wait > 0:
                    raise RequestThrottled(
                        wait,
                        f"This API allows {answer.requests_per_minute} requests a minute with "
                        "each person's API keys",
                    )
        except LimitBackendUnavailable as exc:
            if self.introspector._should_log("limits"):
                logger.error("microauth: %s. Callers with API keys get 503.", exc)
            raise KeyCheckUnavailable(str(exc)) from None
        return answer

    async def aclose(self) -> None:
        """Cancel checks in flight, empty the caches and close an owned Redis client."""
        await self.introspector.aclose()
        await self.limits.aclose()
        if self.redis is not None:
            await self.redis.aclose()
