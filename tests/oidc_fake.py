"""An in-process MicroAuth authorization server for the sign in and token tests.

It speaks just enough OAuth 2.1 and OpenID Connect over an httpx
MockTransport: discovery, JWKS, pushed authorization requests, the token
endpoint with PKCE and refresh token rotation, revocation, API key
introspection and the Account API for API keys. The browser's trip to the
authorize page is simulated by ``FakeIssuer.authorize``.

Tokens, discovery and refresh follow the real server
(internal/server/oauth_tokens.go and internal/oidc): access tokens have no
``nbf``, ``aud`` depends on the resource and on ``openid``, ``sid`` is left
out of ``offline_access`` access tokens, ID tokens carry only the claims
their scopes allow, and refresh tokens rotate with a 30 second grace window
while any other reuse revokes the whole chain.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json
import re
import secrets
import string
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import cache
from typing import Any
from urllib.parse import parse_qs, unquote_plus, urlencode, urlsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from microauth_fastapi._oidc import token_hash

ISSUER = "https://auth.example.com"
CLIENT_ID = "app_web_1"
# Characters that client_secret_basic must form encode before base64.
CLIENT_SECRET = "s3cret:with/odd+chars and spaces"
APP_URL = "https://app.example.com"
COOKIE_SECRET = "cookie-secret-" + "k" * 40
API = "https://api.example.com"
MCP = "https://mcp.example.com/mcp"
RESOURCE_CLIENT_ID = "rs_blog_api"
MCP_CLIENT_ID = "rs_invoices_mcp"
RESOURCE_SECRET = "rs:secret/with+odd chars%"
MCP_SECRET = "mcp:another/secret+for the MCP server%"
REFRESH_GRACE_SECONDS = 30
CLAIMS_SUPPORTED = [
    "sub",
    "iss",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "sid",
    "amr",
    "at_hash",
    "name",
    "picture",
    "updated_at",
    "email",
    "email_verified",
    "roles",
    "permissions",
]
ACCOUNT_API = "/api/v1/me/api-keys"
ACCOUNT_SCOPE = "microauth:api_keys"
APP_NAME = "Blog CMS"
KEY_ALPHABET = string.digits + string.ascii_uppercase + string.ascii_lowercase


def key_checksum(body: str) -> str:
    """CRC-32 in base62, written apart from the SDK so the two check each other."""
    number = binascii.crc32(body.encode("ascii")) & 0xFFFFFFFF
    digits = []
    for _ in range(6):
        number, digit = divmod(number, 62)
        digits.append(KEY_ALPHABET[digit])
    assert number == 0
    return "".join(reversed(digits))


def make_key(prefix: str = "cms", random_part: str | None = None) -> str:
    if random_part is None:
        random_part = "".join(secrets.choice(KEY_ALPHABET) for _ in range(40))
    body = f"{prefix}_{random_part}"
    return body + key_checksum(body)


def rfc3339(seconds: int | None) -> str | None:
    if seconds is None:
        return None
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Clock:
    """A clock tests move by hand, shared by the fake and the SDK."""

    def __init__(self, now: float | None = None) -> None:
        # Whole seconds keep limit arithmetic exact, so Retry-After is predictable.
        self.now = float(int(time.time())) if now is None else now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class FakeKey:
    id: str
    name: str
    secret: str
    sub: str
    resources: list[str]
    permissions: list[str]
    created_at: int
    expires_at: int | None = None
    created_by_app: dict[str, str] | None = None
    last_used_at: int | None = None
    old_secret: str | None = None
    old_secret_expires_at: int | None = None
    requests_per_minute: int | None = None


@cache
def rsa_key(index: int) -> rsa.RSAPrivateKey:
    del index
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def public_jwk(key: rsa.RSAPrivateKey, kid: str) -> dict[str, Any]:
    jwk: dict[str, Any] = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid=kid, use="sig", alg="RS256")
    return jwk


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unsigned_token(claims: dict[str, Any], header: dict[str, Any] | None = None) -> str:
    head = {"alg": "none", "typ": "JWT", "kid": "key-1", **(header or {})}
    return f"{b64url(json.dumps(head).encode())}.{b64url(json.dumps(claims).encode())}."


def hmac_token(claims: dict[str, Any], header: dict[str, Any] | None = None) -> str:
    return jwt.encode(
        claims,
        "an-hmac-key-that-is-long-enough-for-hs256",
        algorithm="HS256",
        headers={"kid": "key-1", **(header or {})},
    )


def form_of(request: httpx.Request) -> dict[str, str]:
    parsed = parse_qs(request.content.decode("ascii"), keep_blank_values=True)
    return {name: values[0] for name, values in parsed.items()}


@dataclass
class FakeUser:
    sub: str = "user_1"
    email: str = "ada@example.com"
    name: str = "Ada Lovelace"
    roles: list[str] = field(default_factory=lambda: ["editor"])
    permissions: list[str] = field(default_factory=lambda: ["posts:write"])
    amr: list[str] = field(default_factory=lambda: ["pwd"])


@dataclass
class RefreshFamily:
    """One sign in's chain of refresh tokens, as the real server stores it."""

    scope: str
    resource: str | None
    auth_time: int
    amr: list[str]
    sid: str
    # Session bound chains end with the hosted session, and their access
    # tokens carry sid. offline_access chains outlive it and leave sid out.
    bound: bool
    generation: int = 0
    rotated_at: float | None = None


def token_audience(issuer: str, scope: str, resource: str | None) -> str | list[str]:
    """The resource, plus the issuer when openid was granted; the issuer alone without one."""
    if resource is None:
        return issuer
    if "openid" in scope.split():
        return [resource, issuer]
    return resource


class FakeIssuer:
    def __init__(self, issuer: str = ISSUER, *, par: bool = True) -> None:
        self.issuer = issuer
        self.par = par
        self.keys: dict[str, rsa.RSAPrivateKey] = {"key-1": rsa_key(0)}
        self.published: list[str] = ["key-1"]
        self.signing_kid = "key-1"
        self.discovery_overrides: dict[str, Any] = {}
        self.user = FakeUser()
        self.access_ttl = 600
        self.issue_refresh_tokens = True
        self.token_delay = 0.0
        # When set, every grant answers with this OAuth error instead.
        self.token_error: str | None = None
        # Called with (claims, header) to rewrite the ID token before signing.
        self.id_token_edit: Any = None
        self.discovery_fetches = 0
        self.jwks_fetches = 0
        self.basic_headers: list[str] = []
        self.par_requests: list[dict[str, str]] = []
        self.token_requests: list[dict[str, str]] = []
        self.revoked: list[dict[str, str]] = []
        self.last_authorization: dict[str, str] = {}
        self._pushed: dict[str, dict[str, str]] = {}
        self._codes: dict[str, dict[str, Any]] = {}
        # A used code remembers the chain it started, which its reuse revokes.
        self._used_codes: dict[str, str | None] = {}
        self.refresh_families: dict[str, RefreshFamily] = {}
        self.issued_refresh_tokens: list[str] = []
        # When set, tokens carry this auth_time and sign ins that ask for a
        # max_age it doesn't meet make the person sign in again.
        self.last_sign_in: int | None = None
        self.reauthentications = 0
        self.issued_access_tokens: list[str] = []

        # API keys
        self.now: Callable[[], float] = time.time
        self.resource_clients = {RESOURCE_CLIENT_ID: API, MCP_CLIENT_ID: MCP}
        # Each resource has its own secret; ones not listed use RESOURCE_SECRET.
        self.resource_secrets = {MCP_CLIENT_ID: MCP_SECRET}
        self.resource_names = {API: "Blog API", MCP: "Invoices MCP server"}
        self.api_keys: dict[str, FakeKey] = {}
        self.introspections: list[dict[str, str]] = []
        self.introspect_cache_control: str | None = "max-age=30"
        self.introspect_delay = 0.0
        # An HTTP status, or an httpx exception class to raise, for every check.
        self.introspect_failure: int | type[httpx.HTTPError] | None = None
        # Called with the active answer to change it before it's sent.
        self.introspect_edit: Callable[[dict[str, Any]], dict[str, Any]] | None = None
        self.key_options: dict[str, Any] = {
            "max_days": 365,
            "allow_no_expiry": True,
            "resources": [
                {
                    "identifier": API,
                    "name": "Blog API",
                    "permissions": [
                        {"name": "posts:read", "description": "Read posts", "sensitive": False},
                        {"name": "posts:write", "description": "Write posts", "sensitive": False},
                        {"name": "posts:delete", "description": "Delete posts", "sensitive": True},
                    ],
                }
            ],
        }
        self.account_requests: list[tuple[str, str, str]] = []
        self.account_forbidden = False
        # Answers by (method, path) once the access token has been accepted.
        self.account_canned: dict[tuple[str, str], httpx.Response] = {}

    # Plumbing

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handle))

    def url(self, path: str) -> str:
        return f"{self.issuer}{path}"

    async def handle(self, request: httpx.Request) -> httpx.Response:
        origin = f"{request.url.scheme}://{request.url.netloc.decode('ascii')}"
        if origin != self.issuer:
            return httpx.Response(404)
        path = request.url.path
        if path == "/.well-known/openid-configuration":
            self.discovery_fetches += 1
            return httpx.Response(200, json=self.discovery())
        if path == "/oauth/jwks":
            self.jwks_fetches += 1
            return httpx.Response(200, json=self.jwks())
        if path == "/oauth/par" and request.method == "POST":
            return self._par(request)
        if path == "/oauth/token" and request.method == "POST":
            if self.token_delay:
                await asyncio.sleep(self.token_delay)
            return self._token(request)
        if path == "/oauth/revoke" and request.method == "POST":
            if not self._client_ok(request):
                return _oauth_error("invalid_client", 401)
            form = form_of(request)
            self.revoked.append(form)
            found = self._read_refresh_token(form.get("token", ""))
            if found is not None:
                self.refresh_families.pop(found[0], None)
            return httpx.Response(200)
        if path == "/oauth/introspect" and request.method == "POST":
            return await self._introspect(request)
        if path == ACCOUNT_API or path.startswith(ACCOUNT_API + "/"):
            return self._account(request, path)
        return httpx.Response(404)

    def discovery(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "issuer": self.issuer,
            "authorization_endpoint": self.url("/oauth/authorize"),
            "token_endpoint": self.url("/oauth/token"),
            "userinfo_endpoint": self.url("/oauth/userinfo"),
            "jwks_uri": self.url("/oauth/jwks"),
            "end_session_endpoint": self.url("/oauth/logout"),
            "revocation_endpoint": self.url("/oauth/revoke"),
            "introspection_endpoint": self.url("/oauth/introspect"),
            "scopes_supported": ["openid", "profile", "email", "offline_access", "roles"],
            "response_types_supported": ["code"],
            "response_modes_supported": ["query", "form_post"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            "revocation_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            "introspection_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "claims_supported": list(CLAIMS_SUPPORTED),
            "prompt_values_supported": ["none", "login", "consent", "create"],
            "authorization_response_iss_parameter_supported": True,
            "require_pushed_authorization_requests": False,
            "request_parameter_supported": False,
            "request_uri_parameter_supported": False,
            "claims_parameter_supported": False,
        }
        if self.par:
            document["pushed_authorization_request_endpoint"] = self.url("/oauth/par")
        document.update(self.discovery_overrides)
        return {name: value for name, value in document.items() if value is not None}

    def jwks(self) -> dict[str, Any]:
        return {"keys": [public_jwk(self.keys[kid], kid) for kid in self.published]}

    def rotate(self, kid: str, index: int) -> None:
        """Start signing with a new key that the JWKS publishes alongside the old one."""
        self.keys[kid] = rsa_key(index)
        self.published.append(kid)
        self.signing_kid = kid

    def _client_ok(self, request: httpx.Request) -> bool:
        header = request.headers.get("authorization", "")
        self.basic_headers.append(header)
        if not header.startswith("Basic "):
            form = form_of(request)
            return form.get("client_id") == CLIENT_ID and form.get("client_secret") == CLIENT_SECRET
        raw_id, _, raw_secret = base64.b64decode(header[6:]).decode("utf-8").partition(":")
        return unquote_plus(raw_id) == CLIENT_ID and unquote_plus(raw_secret) == CLIENT_SECRET

    # Tokens

    def sign(
        self,
        claims: dict[str, Any],
        *,
        typ: str | None = "JWT",
        kid: str | None = None,
        key_index: int | None = None,
    ) -> str:
        kid = kid or self.signing_kid
        key = rsa_key(key_index) if key_index is not None else self.keys[kid]
        # PyJWT adds typ "JWT" unless the header sets typ to None.
        return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid, "typ": typ})

    def access_token_claims(self, **overrides: Any) -> dict[str, Any]:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": self.user.sub,
            "aud": API,
            "exp": now + self.access_ttl,
            "iat": now,
            "jti": secrets.token_hex(8),
            "client_id": CLIENT_ID,
            "scope": "posts:read",
            "sid": "sid_1",
            "auth_time": now - 30,
        }
        claims.update(overrides)
        return {name: value for name, value in claims.items() if value is not None}

    def access_token(
        self, *, typ: str | None = "at+jwt", kid: str | None = None, **overrides: Any
    ) -> str:
        return self.sign(self.access_token_claims(**overrides), typ=typ, kid=kid)

    def id_token_claims(
        self, scope: str = "openid profile email roles", **overrides: Any
    ) -> dict[str, Any]:
        """ID token claims, with only the user claims ``scope`` allows."""
        now = int(time.time())
        user = self.user
        granted = scope.split()
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": user.sub,
            "aud": CLIENT_ID,
            "exp": now + self.access_ttl,
            "iat": now,
            "auth_time": now,
            "sid": "sid_1",
            "amr": list(user.amr),
        }
        if "profile" in granted:
            claims["name"] = user.name
            claims["picture"] = "https://cdn.example.com/ada.png"
            claims["updated_at"] = now - 86400
        if "email" in granted:
            claims["email"] = user.email
            claims["email_verified"] = True
        if "roles" in granted:
            claims["roles"] = list(user.roles)
            claims["permissions"] = list(user.permissions)
        claims.update(overrides)
        return claims

    # Endpoints

    def _par(self, request: httpx.Request) -> httpx.Response:
        if not self._client_ok(request):
            return _oauth_error("invalid_client", 401)
        form = form_of(request)
        self.par_requests.append(form)
        request_uri = "urn:ietf:params:oauth:request_uri:" + secrets.token_urlsafe(16)
        self._pushed[request_uri] = form
        return httpx.Response(201, json={"request_uri": request_uri, "expires_in": 60})

    def authorize(
        self,
        location: str,
        *,
        iss: str | None = "",
        error: str | None = None,
        state: str | None = None,
    ) -> str:
        """Play the authorize page: approve (or fail) and return the redirect back."""
        parts = urlsplit(location)
        assert f"{parts.scheme}://{parts.netloc}{parts.path}" == self.url("/oauth/authorize")
        params = {name: values[0] for name, values in parse_qs(parts.query).items()}
        if "request_uri" in params:
            assert set(params) == {"client_id", "request_uri"}
            pushed = self._pushed.pop(params["request_uri"])
            assert pushed["client_id"] == params["client_id"]
            params = pushed
        assert params["response_type"] == "code"
        assert params["client_id"] == CLIENT_ID
        assert params["code_challenge_method"] == "S256"
        self.last_authorization = params
        max_age = params.get("max_age")
        if (
            max_age is not None
            and self.last_sign_in is not None
            and time.time() - self.last_sign_in > int(max_age)
        ):
            self.last_sign_in = int(time.time())
            self.reauthentications += 1
        query: dict[str, str] = {}
        if error is not None:
            query["error"] = error
        else:
            code = secrets.token_urlsafe(16)
            self._codes[code] = params
            query["code"] = code
        query["state"] = params["state"] if state is None else state
        if iss == "":
            query["iss"] = self.issuer
        elif iss is not None:
            query["iss"] = iss
        return f"{params['redirect_uri']}?{urlencode(query)}"

    def _token(self, request: httpx.Request) -> httpx.Response:
        if not self._client_ok(request):
            return _oauth_error("invalid_client", 401)
        form = form_of(request)
        self.token_requests.append(form)
        if self.token_error is not None:
            return _oauth_error(self.token_error)
        grant = form.get("grant_type")
        if grant == "authorization_code":
            return self._exchange_code(form)
        if grant == "refresh_token":
            return self._refresh(form)
        return _oauth_error("unsupported_grant_type")

    def refreshes(self) -> int:
        return sum(1 for form in self.token_requests if form.get("grant_type") == "refresh_token")

    def end_sessions(self) -> None:
        """End every sign in at MicroAuth, so refresh tokens get invalid_grant."""
        self.refresh_families.clear()

    def _exchange_code(self, form: dict[str, str]) -> httpx.Response:
        code = form.get("code", "")
        if code in self._used_codes:
            family_id = self._used_codes[code]
            if family_id is not None:
                self.refresh_families.pop(family_id, None)
            return _oauth_error("invalid_grant")
        params = self._codes.get(code)
        if params is None or form.get("redirect_uri") != params["redirect_uri"]:
            return _oauth_error("invalid_grant")
        digest = hashlib.sha256(form.get("code_verifier", "").encode("ascii")).digest()
        if b64url(digest) != params["code_challenge"]:
            return _oauth_error("invalid_grant")
        del self._codes[code]
        scope = params["scope"]
        sign_in = RefreshFamily(
            scope=scope,
            resource=params.get("resource"),
            auth_time=self.last_sign_in if self.last_sign_in is not None else int(time.time()),
            amr=list(self.user.amr),
            sid="sid_1",
            bound="offline_access" not in scope.split(),
        )
        refresh = None
        family_id = None
        if self.issue_refresh_tokens:
            family_id = secrets.token_hex(12)
            self.refresh_families[family_id] = sign_in
            refresh = self._refresh_token(family_id, 0)
        self._used_codes[code] = family_id
        return self._issue(sign_in, params.get("nonce"), refresh)

    def _refresh(self, form: dict[str, str]) -> httpx.Response:
        found = self._read_refresh_token(form.get("refresh_token", ""))
        family = self.refresh_families.get(found[0]) if found is not None else None
        if found is None or family is None:
            return _oauth_error("invalid_grant")
        family_id, generation = found
        now = self.now()
        if generation == family.generation:
            family.generation += 1
            family.rotated_at = now
        elif not (
            generation == family.generation - 1
            and family.rotated_at is not None
            and now - family.rotated_at <= REFRESH_GRACE_SECONDS
        ):
            del self.refresh_families[family_id]
            return _oauth_error("invalid_grant")
        return self._issue(family, None, self._refresh_token(family_id, family.generation))

    def _refresh_token(self, family_id: str, generation: int) -> str:
        token = f"rt.{family_id}.{generation}"
        self.issued_refresh_tokens.append(token)
        return token

    @staticmethod
    def _read_refresh_token(token: str) -> tuple[str, int] | None:
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != "rt" or not parts[2].isdigit():
            return None
        return parts[1], int(parts[2])

    def _issue(
        self, sign_in: RefreshFamily, nonce: str | None, refresh: str | None
    ) -> httpx.Response:
        scope = sign_in.scope
        access = self.access_token(
            aud=token_audience(self.issuer, scope, sign_in.resource),
            scope=scope,
            auth_time=sign_in.auth_time,
            sid=sign_in.sid if sign_in.bound else None,
        )
        self.issued_access_tokens.append(access)
        body: dict[str, Any] = {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": self.access_ttl,
            "scope": scope,
        }
        if refresh is not None:
            body["refresh_token"] = refresh
        if "openid" in scope.split():
            claims = self.id_token_claims(
                scope,
                at_hash=token_hash(access),
                auth_time=sign_in.auth_time,
                amr=list(sign_in.amr),
                sid=sign_in.sid,
            )
            if nonce is not None:
                claims["nonce"] = nonce
            header: dict[str, Any] = {"typ": "JWT"}
            if self.id_token_edit is not None:
                body["id_token"] = self.id_token_edit(self, claims, header)
            else:
                body["id_token"] = self.sign(claims, typ=header["typ"])
        return httpx.Response(200, json=body, headers={"Cache-Control": "no-store"})

    # API keys

    def add_key(
        self,
        *,
        resources: list[str] | None = None,
        permissions: list[str] | None = None,
        sub: str | None = None,
        prefix: str = "cms",
        **fields: Any,
    ) -> FakeKey:
        """A key someone made on MicroAuth's own pages, ready to introspect."""
        key = FakeKey(
            id=str(uuid.uuid4()),
            name=fields.pop("name", "Deploy script"),
            secret=make_key(prefix),
            sub=sub or self.user.sub,
            resources=[API] if resources is None else resources,
            permissions=["posts:read"] if permissions is None else permissions,
            created_at=int(self.now()) - 3600,
            **fields,
        )
        self.api_keys[key.id] = key
        return key

    def _resource_of(self, request: httpx.Request) -> str | None:
        header = request.headers.get("authorization", "")
        if not header.startswith("Basic "):
            return None
        raw_id, _, raw_secret = base64.b64decode(header[6:]).decode("utf-8").partition(":")
        client_id = unquote_plus(raw_id)
        if unquote_plus(raw_secret) != self.resource_secrets.get(client_id, RESOURCE_SECRET):
            return None
        return self.resource_clients.get(client_id)

    def _find_key(self, secret: str, now: int) -> FakeKey | None:
        for key in self.api_keys.values():
            if key.expires_at is not None and key.expires_at <= now:
                continue
            if secrets.compare_digest(key.secret, secret):
                return key
            if (
                key.old_secret is not None
                and key.old_secret_expires_at is not None
                and key.old_secret_expires_at > now
                and secrets.compare_digest(key.old_secret, secret)
            ):
                return key
        return None

    def introspection_answer(self, key: FakeKey, resource: str) -> dict[str, Any]:
        document: dict[str, Any] = {
            "active": True,
            "token_use": "api_key",
            "key_id": key.id,
            "sub": key.sub,
            "scope": " ".join(key.permissions),
            "aud": key.resources if len(key.resources) > 1 else resource,
            "iss": self.issuer,
            "iat": key.created_at,
        }
        if key.expires_at is not None:
            document["exp"] = key.expires_at
        if key.requests_per_minute is not None:
            document["requests_per_minute"] = key.requests_per_minute
        return document

    async def _introspect(self, request: httpx.Request) -> httpx.Response:
        self.introspections.append(form_of(request))
        if self.introspect_delay:
            await asyncio.sleep(self.introspect_delay)
        failure = self.introspect_failure
        if isinstance(failure, int):
            return httpx.Response(failure, json={"error": "temporarily_unavailable"})
        if failure is not None:
            raise failure("the fake can't be reached", request=request)
        resource = self._resource_of(request)
        if resource is None:
            return _oauth_error("invalid_client", 401)
        if request.headers.get("accept") != "application/json":
            return httpx.Response(406)
        now = int(self.now())
        key = self._find_key(form_of(request).get("token", ""), now)
        headers = {}
        if self.introspect_cache_control is not None:
            headers["Cache-Control"] = self.introspect_cache_control
        if key is None or resource not in key.resources:
            return httpx.Response(200, json={"active": False}, headers=headers)
        key.last_used_at = now
        document = self.introspection_answer(key, resource)
        if self.introspect_edit is not None:
            document = self.introspect_edit(document)
        return httpx.Response(200, json=document, headers=headers)

    def key_json(self, key: FakeKey) -> dict[str, Any]:
        prefix, _, rest = key.secret.partition("_")
        return {
            "id": key.id,
            "name": key.name,
            "prefix": f"{prefix}_{rest[:6]}",
            "resources": [
                {"identifier": identifier, "name": self.resource_names[identifier]}
                for identifier in key.resources
            ],
            "permissions": list(key.permissions),
            "created_at": rfc3339(key.created_at),
            "created_by_app": key.created_by_app,
            "expires_at": rfc3339(key.expires_at),
            "last_used_at": rfc3339(key.last_used_at),
            "old_secret_expires_at": rfc3339(key.old_secret_expires_at),
        }

    def _account_claims(self, header: str) -> dict[str, Any] | None:
        if not header.startswith("Bearer "):
            return None
        token = header[7:]
        try:
            kid = jwt.get_unverified_header(token).get("kid", "")
            claims: dict[str, Any] = jwt.decode(
                token,
                self.keys[kid].public_key(),
                algorithms=["RS256"],
                audience=self.issuer,
                issuer=self.issuer,
            )
        except (jwt.PyJWTError, KeyError):
            return None
        return claims

    def _account(self, request: httpx.Request, path: str) -> httpx.Response:
        header = request.headers.get("authorization", "")
        self.account_requests.append((request.method, path, header))
        claims = self._account_claims(header)
        if claims is None:
            return _bearer_error(401, "invalid_token", "The access token is invalid or expired")
        if self.account_forbidden or ACCOUNT_SCOPE not in str(claims.get("scope", "")).split():
            return _bearer_error(
                403, "insufficient_scope", "This app can't manage API keys", scope=ACCOUNT_SCOPE
            )
        canned = self.account_canned.get((request.method, path))
        if canned is not None:
            return canned
        sub = claims["sub"]
        rest = path[len(ACCOUNT_API) :]
        now = int(self.now())
        body = json.loads(request.content) if request.content else None
        if rest == "/options" and request.method == "GET":
            return httpx.Response(200, json=self.key_options)
        if rest == "" and request.method == "GET":
            mine = [self.key_json(key) for key in self.api_keys.values() if key.sub == sub]
            return httpx.Response(200, json={"keys": mine})
        if rest == "" and request.method == "POST":
            return self._create_key(claims, body, now)
        if rest == "" and request.method == "DELETE":
            for key_id in [key.id for key in self.api_keys.values() if key.sub == sub]:
                del self.api_keys[key_id]
            return httpx.Response(204)
        found = re.fullmatch(r"/([0-9a-f-]{36})(/roll)?", rest)
        key = self.api_keys.get(found.group(1)) if found else None
        if key is None or key.sub != sub:
            return _problem(404, "Not Found", "There is no such API key")
        assert found is not None
        if found.group(2) and request.method == "POST":
            return self._roll_key(claims, key, body, now)
        if not found.group(2) and request.method == "PATCH":
            name = body.get("name") if isinstance(body, dict) else None
            if not isinstance(name, str) or not 1 <= len(name.strip()) <= 64:
                return _invalid("Give the key a name of 1 to 64 characters", "body.name", name)
            key.name = name.strip()
            return httpx.Response(200, json=self.key_json(key))
        if not found.group(2) and request.method == "DELETE":
            del self.api_keys[key.id]
            return httpx.Response(204)
        return _problem(405, "Method Not Allowed", "This method isn't allowed here")

    def _recent_sign_in(self, claims: dict[str, Any], now: int) -> httpx.Response | None:
        auth_time = claims.get("auth_time")
        if type(auth_time) is int and now - auth_time <= 600:
            return None
        description = "Sign in again to create or roll an API key"
        response = _problem(401, "Unauthorized", description)
        response.headers["WWW-Authenticate"] = (
            f'Bearer error="insufficient_user_authentication", '
            f'error_description="{description}", max_age="600"'
        )
        return response

    def _create_key(self, claims: dict[str, Any], body: Any, now: int) -> httpx.Response:
        stale = self._recent_sign_in(claims, now)
        if stale is not None:
            return stale
        body = body if isinstance(body, dict) else {}
        offered = {item["identifier"]: item for item in self.key_options["resources"]}
        errors = []
        name = body.get("name")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 64:
            errors.append(_error("Give the key a name of 1 to 64 characters", "body.name", name))
        resources = body.get("resources")
        if not isinstance(resources, list) or not resources:
            errors.append(_error("Pick at least one API", "body.resources", resources))
            resources = []
        for index, identifier in enumerate(resources):
            if identifier not in offered:
                errors.append(
                    _error(
                        "You can't make keys for this API", f"body.resources[{index}]", identifier
                    )
                )
        allowed = {
            permission["name"]
            for identifier in resources
            if identifier in offered
            for permission in offered[identifier]["permissions"]
        }
        permissions = body.get("permissions")
        if not isinstance(permissions, list):
            errors.append(_error("Pick the key's permissions", "body.permissions", permissions))
            permissions = []
        for index, permission in enumerate(permissions):
            if permission not in allowed:
                errors.append(
                    _error(
                        "You can't give a key this permission",
                        f"body.permissions[{index}]",
                        permission,
                    )
                )
        days = body.get("expires_in_days")
        max_days = self.key_options["max_days"]
        if days is None:
            if not self.key_options["allow_no_expiry"]:
                errors.append(_error("Keys must expire", "body.expires_in_days", None))
        elif type(days) is not int or days < 1 or (max_days is not None and days > max_days):
            errors.append(_error(f"Pick 1 to {max_days} days", "body.expires_in_days", days))
        if errors:
            return _problem(422, "Unprocessable Entity", "validation failed", errors)
        key = FakeKey(
            id=str(uuid.uuid4()),
            name=name.strip(),
            secret=make_key(),
            sub=claims["sub"],
            resources=list(dict.fromkeys(resources)),
            permissions=list(dict.fromkeys(permissions)),
            created_at=now,
            expires_at=None if days is None else now + days * 86400,
            created_by_app={"client_id": claims["client_id"], "name": APP_NAME},
        )
        self.api_keys[key.id] = key
        return httpx.Response(201, json={"key": self.key_json(key), "secret": key.secret})

    def _roll_key(
        self, claims: dict[str, Any], key: FakeKey, body: Any, now: int
    ) -> httpx.Response:
        stale = self._recent_sign_in(claims, now)
        if stale is not None:
            return stale
        hours = body.get("old_secret_lasts_hours") if isinstance(body, dict) else None
        if type(hours) is not int or hours not in (0, 1, 24):
            return _invalid("Pick 0, 1 or 24 hours", "body.old_secret_lasts_hours", hours)
        old = key.secret
        key.secret = make_key(old.partition("_")[0])
        key.old_secret = old if hours else None
        key.old_secret_expires_at = now + hours * 3600 if hours else None
        return httpx.Response(200, json={"key": self.key_json(key), "secret": key.secret})


def _oauth_error(error: str, status: int = 400) -> httpx.Response:
    return httpx.Response(status, json={"error": error, "error_description": f"fake {error}"})


def _problem(
    status: int, title: str, detail: str, errors: list[dict[str, Any]] | None = None
) -> httpx.Response:
    body: dict[str, Any] = {"title": title, "status": status, "detail": detail}
    if errors:
        body["errors"] = errors
    return httpx.Response(status, json=body, headers={"Content-Type": "application/problem+json"})


def _error(message: str, location: str, value: Any) -> dict[str, Any]:
    return {"message": message, "location": location, "value": value}


def _invalid(message: str, location: str, value: Any) -> httpx.Response:
    return _problem(
        422, "Unprocessable Entity", "validation failed", [_error(message, location, value)]
    )


def _bearer_error(status: int, error: str, description: str, **extra: str) -> httpx.Response:
    params = [f'error="{error}"', f'error_description="{description}"']
    params.extend(f'{name}="{value}"' for name, value in extra.items())
    response = _problem(status, "Unauthorized" if status == 401 else "Forbidden", description)
    response.headers["WWW-Authenticate"] = "Bearer " + ", ".join(params)
    return response


async def sign_in(
    client: httpx.AsyncClient, fake: FakeIssuer, next: str = "/dashboard"
) -> httpx.Response:
    """Run the whole browser sign in against an app using UserAuth."""
    start = await client.get("/auth/login", params={"next": next})
    assert start.status_code == 303, start.text
    done = await client.get(fake.authorize(start.headers["location"]))
    assert done.status_code == 303, done.text
    return done
