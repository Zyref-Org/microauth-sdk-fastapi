"""Encrypted cookies for UserAuth.

A sealed value looks like ``v1.<base64url(nonce || ciphertext || tag)>``. It
is AES-256-GCM with a key derived from the cookie secret by HKDF-SHA256. The
key derivation and the associated data both name the cookie's purpose, so a
sign in state cookie can never be replayed as a session cookie or the other
way around.

Several secrets can be configured for rotation. The first one seals and every
one of them opens, so a new secret can be rolled out in front of the old one
and the old one removed once every session has been rewritten.

Browsers keep about 4 KB per cookie, so a long value is split into numbered
chunks (``name.0``, ``name.1`` and so on) and joined again when read.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import zlib
from collections.abc import Mapping, Sequence
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION_PREFIX = "v1."
CHUNK_SIZE = 3800
MAX_CHUNKS = 8
MIN_SECRET_BYTES = 32
_NONCE_BYTES = 12
_TAG_BYTES = 16
_MAX_PLAINTEXT = 64 * 1024
_SALT = b"microauth-fastapi cookies"


def derive_key(secret: bytes, purpose: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_SALT,
        info=f"microauth-fastapi {purpose} cookie v1".encode(),
    ).derive(secret)


class CookieSealer:
    """Seals and opens JSON payloads for one cookie purpose."""

    def __init__(self, secrets: Sequence[bytes], purpose: str, *, compress: bool) -> None:
        if not secrets:
            raise ValueError("at least one cookie secret is required")
        self._ciphers = [AESGCM(derive_key(secret, purpose)) for secret in secrets]
        self._aad = f"microauth-fastapi {purpose} v1".encode()
        self._compress = compress

    def seal(self, payload: Mapping[str, Any]) -> str:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if self._compress:
            data = zlib.compress(data, 9)
        nonce = os.urandom(_NONCE_BYTES)
        sealed = self._ciphers[0].encrypt(nonce, data, self._aad)
        encoded = base64.urlsafe_b64encode(nonce + sealed).rstrip(b"=").decode("ascii")
        return VERSION_PREFIX + encoded

    def unseal(self, value: str) -> dict[str, Any] | None:
        """The payload, or None for anything tampered, truncated or foreign."""
        if not value.startswith(VERSION_PREFIX) or len(value) > CHUNK_SIZE * MAX_CHUNKS:
            return None
        body = value[len(VERSION_PREFIX) :]
        try:
            raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        except (binascii.Error, ValueError):
            return None
        if len(raw) < _NONCE_BYTES + _TAG_BYTES:
            return None
        nonce, sealed = raw[:_NONCE_BYTES], raw[_NONCE_BYTES:]
        data: bytes | None = None
        for cipher in self._ciphers:
            try:
                data = cipher.decrypt(nonce, sealed, self._aad)
            except InvalidTag:
                continue
            break
        if data is None:
            return None
        if self._compress:
            inflater = zlib.decompressobj()
            try:
                data = inflater.decompress(data, _MAX_PLAINTEXT)
            except zlib.error:
                return None
            if inflater.unconsumed_tail:
                return None
        try:
            payload = json.loads(data)
        except ValueError:
            return None
        return payload if isinstance(payload, dict) else None


def split_value(value: str) -> list[str]:
    return [value[i : i + CHUNK_SIZE] for i in range(0, len(value), CHUNK_SIZE)]


def read_value(cookies: Mapping[str, str], name: str) -> str | None:
    """A cookie's value, joining numbered chunks when it was split."""
    if name in cookies:
        return cookies[name]
    parts: list[str] = []
    for index in range(MAX_CHUNKS):
        part = cookies.get(f"{name}.{index}")
        if part is None:
            break
        parts.append(part)
    return "".join(parts) if parts else None


def present_names(cookies: Mapping[str, str], name: str) -> set[str]:
    """Every cookie the request carries for ``name``, chunks included."""
    prefix = f"{name}."
    return {
        key
        for key in cookies
        if key == name or (key.startswith(prefix) and key[len(prefix) :].isdigit())
    }


def set_cookie_header(
    name: str, value: str, *, secure: bool, max_age: int | None, http_only: bool = True
) -> str:
    parts = [f"{name}={value}", "Path=/", "SameSite=Lax"]
    if http_only:
        parts.append("HttpOnly")
    if secure:
        parts.append("Secure")
    if max_age is not None:
        parts.append(f"Max-Age={max_age}")
    return "; ".join(parts)


def clear_cookie_header(name: str, *, secure: bool) -> str:
    parts = [
        f"{name}=",
        "Path=/",
        "SameSite=Lax",
        "HttpOnly",
        "Max-Age=0",
        "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
    ]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)
