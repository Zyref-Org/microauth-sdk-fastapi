"""An in-process MicroAuth authorization server for the sign in and token tests.

It speaks just enough OAuth 2.1 and OpenID Connect over an httpx
MockTransport: discovery, JWKS, pushed authorization requests, the token
endpoint with PKCE and refresh token rotation, and revocation. The browser's
trip to the authorize page is simulated by ``FakeIssuer.authorize``.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
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
        self.refresh_tokens: dict[str, dict[str, Any]] = {}

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
            record = self.refresh_tokens.get(form.get("token", ""))
            if record is not None:
                record["used"] = True
            return httpx.Response(200)
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
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "authorization_response_iss_parameter_supported": True,
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
            return False
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
            "nbf": now,
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

    def id_token_claims(self, **overrides: Any) -> dict[str, Any]:
        now = int(time.time())
        user = self.user
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": user.sub,
            "aud": CLIENT_ID,
            "exp": now + 600,
            "iat": now,
            "auth_time": now,
            "sid": "sid_1",
            "email": user.email,
            "email_verified": True,
            "name": user.name,
            "picture": "https://cdn.example.com/ada.png",
            "roles": list(user.roles),
            "permissions": list(user.permissions),
        }
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
            params = self._codes.pop(form.get("code", ""), None)
            if params is None or form.get("redirect_uri") != params["redirect_uri"]:
                return _oauth_error("invalid_grant")
            digest = hashlib.sha256(form.get("code_verifier", "").encode("ascii")).digest()
            if b64url(digest) != params["code_challenge"]:
                return _oauth_error("invalid_grant")
            return self._issue(params["scope"], params.get("nonce"), params.get("resource"))
        if grant == "refresh_token":
            record = self.refresh_tokens.get(form.get("refresh_token", ""))
            if record is None or record["used"]:
                return _oauth_error("invalid_grant")
            record["used"] = True
            return self._issue(record["scope"], None, record["resource"])
        return _oauth_error("unsupported_grant_type")

    def refreshes(self) -> int:
        return sum(1 for form in self.token_requests if form.get("grant_type") == "refresh_token")

    def _issue(self, scope: str, nonce: str | None, resource: str | None) -> httpx.Response:
        access = self.access_token(aud=resource or self.issuer, scope=scope)
        claims = self.id_token_claims(at_hash=token_hash(access))
        if nonce is not None:
            claims["nonce"] = nonce
        header: dict[str, Any] = {"typ": "JWT"}
        if self.id_token_edit is not None:
            id_token = self.id_token_edit(self, claims, header)
        else:
            id_token = self.sign(claims, typ=header["typ"])
        body: dict[str, Any] = {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": self.access_ttl,
            "id_token": id_token,
            "scope": scope,
        }
        if self.issue_refresh_tokens:
            refresh = secrets.token_urlsafe(24)
            self.refresh_tokens[refresh] = {"used": False, "scope": scope, "resource": resource}
            body["refresh_token"] = refresh
        return httpx.Response(200, json=body, headers={"Cache-Control": "no-store"})


def _oauth_error(error: str, status: int = 400) -> httpx.Response:
    return httpx.Response(status, json={"error": error, "error_description": f"fake {error}"})


async def sign_in(
    client: httpx.AsyncClient, fake: FakeIssuer, next: str = "/dashboard"
) -> httpx.Response:
    """Run the whole browser sign in against an app using UserAuth."""
    start = await client.get("/auth/login", params={"next": next})
    assert start.status_code == 303, start.text
    done = await client.get(fake.authorize(start.headers["location"]))
    assert done.status_code == 303, done.text
    return done
