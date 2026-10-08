"""API key generation, hashing and lookup.

An API key looks like ``cs_live_<40 hex chars>``. It is shown to the operator
exactly once, at creation. What the database stores is a SHA-256 digest, so a
database dump does not yield usable credentials.

Why SHA-256 and not Argon2 for this hash
-----------------------------------------
API keys are 160 bits of CSPRNG output. There is nothing to brute-force, so the
work factor that Argon2 adds buys nothing while making every authenticated
request pay ~50 ms of memory-hard hashing. Slowing a check that has no
attackable entropy is a self-inflicted denial of service. The passwords module
uses Argon2 precisely because passwords *do* have guessable entropy.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Final

from app.core.exceptions import AuthenticationError
from app.security.passwords import constant_time_equals

KEY_PREFIX: Final[str] = "cs"
KEY_ENTROPY_BYTES: Final[int] = 20  # 160 bits
#: Characters after the underscore; used for the non-secret display handle.
DISPLAY_HANDLE_LENGTH: Final[int] = 6
DEFAULT_TTL_DAYS: Final[int] = 90

#: Scopes an API key may carry. A key is granted the minimum needed.
SCOPES: Final[frozenset[str]] = frozenset(
    {"scan:read", "scan:write", "quarantine:read", "quarantine:write", "admin:read"}
)


class InvalidApiKeyError(AuthenticationError):
    code = "auth_invalid"
    message = "The API key is invalid, expired or revoked."


@dataclass(frozen=True, slots=True)
class GeneratedApiKey:
    """A freshly minted key: the plaintext plus its storage representation."""

    plaintext: str
    prefix: str
    key_hash: str


def generate_api_key(environment: str = "development") -> GeneratedApiKey:
    """Create a new API key.

    The ``live``/``test`` marker lets an operator tell a production key from a
    test key at a glance in a log or config file. It carries no authority.
    """
    env_tag = "live" if environment == "production" else "test"
    secret = secrets.token_hex(KEY_ENTROPY_BYTES)
    plaintext = f"{KEY_PREFIX}_{env_tag}_{secret}"
    return GeneratedApiKey(
        plaintext=plaintext,
        prefix=display_handle(plaintext),
        key_hash=hash_api_key(plaintext),
    )


def hash_api_key(plaintext: str) -> str:
    """Return the storage digest for an API key."""
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def display_handle(plaintext: str) -> str:
    """Non-secret prefix for human identification.

    >>> display_handle("cs_live_0123456789abcdef")
    'cs_live_012345'
    """
    parts = plaintext.split("_")
    if len(parts) < 3:
        return plaintext[:12]
    return f"{parts[0]}_{parts[1]}_{parts[2][:DISPLAY_HANDLE_LENGTH]}"


def verify_api_key(plaintext: str, stored_hash: str | None) -> bool:
    """Constant-time comparison of a presented key against its stored digest.

    Returns ``False`` for any mismatch, including a missing hash, so callers
    cannot accidentally treat an unset column as a match.
    """
    if not plaintext or not stored_hash:
        return False
    return hmac.compare_digest(hash_api_key(plaintext), stored_hash)


def normalise_scopes(requested: list[str] | None, *, default: str = "scan:read") -> str:
    """Validate and store requested scopes as a comma-separated string.

    Unknown scopes are dropped rather than rejected: a client requesting a scope
    this version does not implement should get the subset that works, with the
    unknown parts visible in the response, instead of a hard failure.
    """
    if not requested:
        return default
    allowed = {scope for scope in requested if scope in SCOPES}
    if not allowed:
        return default
    return ",".join(sorted(allowed))


def parse_scopes(raw: str | None) -> list[str]:
    """Split a stored scope string."""
    if not raw:
        return []
    return [scope.strip() for scope in raw.split(",") if scope.strip()]


def default_expiry(days: int = DEFAULT_TTL_DAYS) -> datetime:
    """Absolute expiry for a newly created key."""
    return datetime.now(timezone.utc) + timedelta(days=days)


def redact_api_key(value: str | None) -> str:
    """Loggable rendering of a key that reveals only its handle.

    Used by request logging so an operator can correlate a call with a key
    without the log becoming a credential store.
    """
    if not value:
        return "<none>"
    if len(value) <= 16:
        return "*" * len(value)
    return f"{display_handle(value)}{'*' * 8}"


__all__ = [
    "DEFAULT_TTL_DAYS",
    "GeneratedApiKey",
    "InvalidApiKeyError",
    "KEY_PREFIX",
    "SCOPES",
    "default_expiry",
    "display_handle",
    "generate_api_key",
    "hash_api_key",
    "normalise_scopes",
    "parse_scopes",
    "redact_api_key",
    "verify_api_key",
]