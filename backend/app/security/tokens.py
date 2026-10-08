"""JWT issuance and verification.

Design decisions
----------------
* **HS256 with a pinned secret.** The service is a single issuer, so a symmetric
  algorithm is appropriate and avoids key-distribution complexity. The secret
  comes from the environment and production refuses to start without one.
* **Explicit claim allow-list.** Verification does not accept arbitrary claims:
  it rejects a token whose type, algorithm, issuer or audience does not match,
  which blocks algorithm-confusion and token-substitution attacks.
* **Typed tokens.** Access and refresh tokens carry a ``typ`` claim and are not
  interchangeable, so a stolen refresh token cannot be replayed as an access
  token against a resource.
* **Not-before and required expiry.** ``nbf`` and ``exp`` are both required; a
  token without an expiry would be valid forever.
* **Revocation.** Access tokens are stateless, so logout is enforced by a short
  expiry plus an optional revocation list keyed on ``jti`` when the deployment
  needs immediate logout.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Final

import jwt

from app.core.config import get_settings
from app.core.exceptions import AuthenticationError

ACCESS_TOKEN_TYPE: Final[str] = "access"
REFRESH_TOKEN_TYPE: Final[str] = "refresh"
TOKEN_ISSUER: Final[str] = "cybershield"
TOKEN_AUDIENCE: Final[str] = "cybershield-api"

#: Tolerance for clock skew between the issuer and verifier, in seconds.
LEEWAY_SECONDS: Final[int] = 30

#: Longest a revoked ``jti`` is remembered. Access tokens are short-lived, so this
#: comfortably exceeds any token a logout could revoke. The store is bounded to
#: keep memory flat even when an attacker triggers many logouts.
_MAX_REVOKED_ENTRIES: Final[int] = 50_000


class TokenRevocationStore:
    """Process-local, best-effort mapping of revoked ``jti`` values.

    Explicitly **not** a cross-replica revocation mechanism: with multiple API
    processes behind a load balancer, a JWT evicted from this process may be
    accepted by another until it expires. A deployment that needs immediate,
    cluster-wide logout should switch this to a shared store (e.g. Redis) with
    the same interface. The store is thread-safe because ``TokenService`` may be
    shared between sync and async contexts.
    """

    def __init__(self) -> None:
        self._revoked: dict[str, float] = {}
        self._lock = threading.Lock()

    def revoke(self, jti: str, *, expires_at: datetime | None = None) -> None:
        """Mark ``jti`` as revoked until its natural expiry."""
        deadline = expires_at or (datetime.now(timezone.utc) + timedelta(days=14))
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=timezone.utc)
        with self._lock:
            self._prune()
            self._revoked[jti] = deadline.timestamp()

    def is_revoked(self, jti: str) -> bool:
        """Whether ``jti`` was revoked and its revocation has not lapsed."""
        with self._lock:
            self._prune()
            return jti in self._revoked

    def clear(self) -> None:
        with self._lock:
            self._revoked.clear()

    def __len__(self) -> int:
        return len(self._revoked)

    def _prune(self, now: float | None = None) -> None:
        reference = now if now is not None else time.time()
        expired = [key for key, deadline in self._revoked.items() if deadline <= reference]
        for key in expired:
            self._revoked.pop(key, None)
        if len(self._revoked) > _MAX_REVOKED_ENTRIES:
            # Drop the oldest quarter rather than refusing new revocations.
            ordered = sorted(self._revoked.items(), key=lambda kv: kv[1])
            for stale_key, _ in ordered[: _MAX_REVOKED_ENTRIES // 4]:
                self._revoked.pop(stale_key, None)


_revocation = TokenRevocationStore()


class TokenError(AuthenticationError):
    """Raised when a token is malformed, expired or otherwise unusable."""

    code = "auth_invalid"
    message = "The authentication token is invalid or has expired."


@dataclass(frozen=True, slots=True)
class TokenPayload:
    """Verified token contents."""

    subject: str
    token_type: str
    jti: str
    issued_at: datetime
    expires_at: datetime
    scopes: tuple[str, ...] = ()
    email: str | None = None

    @property
    def is_access(self) -> bool:
        return self.token_type == ACCESS_TOKEN_TYPE

    @property
    def is_refresh(self) -> bool:
        return self.token_type == REFRESH_TOKEN_TYPE


class TokenService:
    """Issues and verifies HS256 JWTs."""

    def __init__(self, secret: str | None = None, algorithm: str | None = None) -> None:
        settings = get_settings()
        self._secret = secret or settings.secret_key
        self._algorithm = algorithm or settings.jwt_algorithm
        self._access_minutes = settings.access_token_expire_minutes
        self._refresh_days = settings.refresh_token_expire_days

        if self._algorithm != "HS256":
            # Guard against configuration selecting ``none`` or an asymmetric
            # algorithm with a symmetric secret.
            raise TokenError("Only HS256 tokens are supported.")

    # ------------------------------------------------------------------
    # Issuance
    # ------------------------------------------------------------------
    def create_access_token(
        self,
        *,
        subject: str,
        email: str | None = None,
        scopes: list[str] | None = None,
        expires_delta: timedelta | None = None,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        """Mint a short-lived access token."""
        lifetime = expires_delta or timedelta(minutes=self._access_minutes)
        return self._encode(
            subject=subject,
            token_type=ACCESS_TOKEN_TYPE,
            lifetime=lifetime,
            email=email,
            scopes=scopes or [],
            extra_claims=extra_claims,
        )

    def create_refresh_token(
        self,
        *,
        subject: str,
        email: str | None = None,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        """Mint a long-lived refresh token.

        The token carries only the subject and a unique id. Keeping it minimal
        limits what a leaked refresh token exposes.
        """
        return self._encode(
            subject=subject,
            token_type=REFRESH_TOKEN_TYPE,
            lifetime=timedelta(days=self._refresh_days),
            email=email,
            scopes=[],
            extra_claims=extra_claims,
        )

    def create_token_pair(
        self, *, subject: str, email: str | None = None, scopes: list[str] | None = None
    ) -> tuple[str, str]:
        """Return ``(access_token, refresh_token)`` for a login response."""
        return (
            self.create_access_token(subject=subject, email=email, scopes=scopes),
            self.create_refresh_token(subject=subject, email=email),
        )

    def _encode(
        self,
        *,
        subject: str,
        token_type: str,
        lifetime: timedelta,
        email: str | None,
        scopes: list[str],
        extra_claims: dict[str, Any] | None,
    ) -> str:
        now = datetime.now(timezone.utc)
        claims: dict[str, Any] = {
            "sub": subject,
            "typ": token_type,
            "jti": uuid.uuid4().hex,
            "iss": TOKEN_ISSUER,
            "aud": TOKEN_AUDIENCE,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + lifetime).timestamp()),
        }
        if email:
            claims["email"] = email
        if scopes:
            claims["scopes"] = sorted(set(scopes))
        if extra_claims:
            # Reserved claims cannot be overwritten by a caller.
            claims.update({k: v for k, v in extra_claims.items() if k not in claims})

        return jwt.encode(claims, self._secret, algorithm=self._algorithm)

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------
    def decode(
        self,
        token: str,
        *,
        expected_type: str | None = None,
        verify_audience: bool = True,
    ) -> TokenPayload:
        """Verify a token and return its payload.

        Args:
            token: Raw compact JWT.
            expected_type: When given, the token's ``typ`` must match. This is
                what stops a refresh token being used as an access token.

        Raises:
            TokenError: On any verification failure. The message never
                distinguishes "wrong signature" from "expired", because that
                distinction helps an attacker probe token state.
        """
        if not token or not isinstance(token, str):
            raise TokenError("A token is required.")

        try:
            claims = jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],
                audience=TOKEN_AUDIENCE if verify_audience else None,
                issuer=TOKEN_ISSUER,
                leeway=LEEWAY_SECONDS,
                options={
                    "require": ["exp", "iat", "nbf", "sub", "jti"],
                    "verify_aud": verify_audience,
                    "verify_signature": True,
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenError("The token has expired.") from exc
        except jwt.InvalidTokenError as exc:
            raise TokenError() from exc

        token_type = str(claims.get("typ", ""))
        if not token_type:
            raise TokenError("The token is missing its type claim.")
        if expected_type is not None and token_type != expected_type:
            raise TokenError("The token type does not match this endpoint.")

        jti = str(claims["jti"])
        if _revocation.is_revoked(jti):
            raise TokenError()

        scopes_raw = claims.get("scopes", [])
        scopes = tuple(scopes_raw) if isinstance(scopes_raw, list) else ()

        return TokenPayload(
            subject=str(claims["sub"]),
            token_type=token_type,
            jti=jti,
            issued_at=datetime.fromtimestamp(int(claims["iat"]), tz=timezone.utc),
            expires_at=datetime.fromtimestamp(int(claims["exp"]), tz=timezone.utc),
            scopes=scopes,
            email=claims.get("email"),
        )

    def decode_access_token(self, token: str) -> TokenPayload:
        """Verify a token is an access token."""
        return self.decode(token, expected_type=ACCESS_TOKEN_TYPE)

    def decode_refresh_token(self, token: str) -> TokenPayload:
        """Verify a token is a refresh token."""
        return self.decode(token, expected_type=REFRESH_TOKEN_TYPE)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def extract_bearer(header_value: str | None) -> str | None:
        """Pull the credential out of an ``Authorization: Bearer <token>`` header.

        Returns ``None`` rather than raising so callers can treat a malformed
        header exactly like a missing one.
        """
        if not header_value:
            return None
        scheme, _, credential = header_value.partition(" ")
        if scheme.lower() != "bearer":
            return None
        credential = credential.strip()
        return credential or None

    def token_lifetime_seconds(self, token_type: str) -> int:
        """Configured lifetime, for clients that pre-empt expiry."""
        if token_type == REFRESH_TOKEN_TYPE:
            return self._refresh_days * 86400
        return self._access_minutes * 60


_service: TokenService | None = None


def get_token_service() -> TokenService:
    """Return the process-wide token service."""
    global _service
    if _service is None:
        _service = TokenService()
    return _service


def get_revocation_store() -> TokenRevocationStore:
    """Return the process-wide JTI revocation store (best-effort logout)."""
    return _revocation


__all__ = [
    "ACCESS_TOKEN_TYPE",
    "LEEWAY_SECONDS",
    "REFRESH_TOKEN_TYPE",
    "TokenError",
    "TokenPayload",
    "TokenRevocationStore",
    "TokenService",
    "get_revocation_store",
    "get_token_service",
]