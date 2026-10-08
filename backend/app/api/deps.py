"""Shared FastAPI dependencies: authentication, scoping, and rate limiting.

Authentication accepts either a Bearer access token or an ``X-API-Key`` header.
Both paths resolve to an :class:`AuthPrincipal` so routes never care which
credential was used. The dependency graph is deliberately shallow:

* ``require_user`` / ``optional_user`` run first and put the principal on
  ``request.state``;
* ``require_scope`` / ``require_admin`` build on them;
* ``rate_limit(bucket)`` is a *factory* returning a dependency that keys on the
  principal when present (``user:<id>``) and otherwise on the client IP, so an
  attacker rotating API keys or tokens cannot multiply their budget anonymously.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Annotated, Any, Awaitable, Callable

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    RateLimitError,
)
from app.db.session import get_db
from app.models.base import utcnow
from app.models.user import ApiKey, User
from app.security.api_keys import hash_api_key, parse_scopes
from app.security.rate_limit import get_rate_limiter
from app.security.tokens import ACCESS_TOKEN_TYPE, TokenError, get_token_service
from app.services.audit import record_rate_limit_event

#: Scopes an ordinary account carries by default.
USER_SCOPES = frozenset({"scan:read", "scan:write", "quarantine:read", "quarantine:write"})
#: Scope only administrator accounts carry.
ADMIN_SCOPE = "admin:read"
ADMIN_SCOPES = USER_SCOPES | frozenset({ADMIN_SCOPE})


@dataclass(frozen=True, slots=True)
class AuthPrincipal:
    """The authenticated caller, however they authenticated."""

    user_id: uuid.UUID
    auth_type: str  # "jwt" | "api_key"
    scopes: frozenset[str]
    user_email: str | None = None
    is_admin: bool = False
    api_key_id: uuid.UUID | None = None
    source_ip: str | None = None
    user_agent: str | None = None

    @property
    def rate_limit_identity(self) -> str:
        """Stable per-account key that survives credential rotation."""
        return f"user:{self.user_id}"

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


def client_ip(request: Request) -> str | None:
    """Client address, honouring trusted proxy headers only when configured.

    ``X-Forwarded-For`` is spoofable; it is only trusted when
    ``TRUST_PROXY_HEADERS`` is set because the deployment sits behind a proxy
    that overwrites the header. Never trust it unconditionally.
    """
    settings: Settings = get_settings()
    if settings.trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()[:64]
    return request.client.host if request.client else None


def client_identity(request: Request) -> tuple[str, str | None]:
    """Return ``(rate-limit identity, source ip)`` for the current request.

    Anonymous requests are keyed by IP; authenticated requests by user id, so
    the two are never conflated.
    """
    principal: AuthPrincipal | None = getattr(request.state, "principal", None)
    if principal is not None:
        return principal.rate_limit_identity, principal.source_ip
    ip = client_ip(request) or "unknown"
    return f"ip:{ip}", ip


async def _authenticate(request: Request, db: AsyncSession) -> AuthPrincipal | None:
    """Resolve whichever credential was presented, or ``None`` when absent.

    A presented-but-invalid credential is always an error (an attacker probing
    with bad keys should not be silently treated as anonymous).
    """
    authorization = request.headers.get("authorization", "")
    api_key = request.headers.get("x-api-key", "")
    source_ip = client_ip(request)
    user_agent = request.headers.get("user-agent")

    if not authorization and not api_key:
        return None

    if api_key:
        return await _authenticate_api_key(
            db, api_key, source_ip=source_ip, user_agent=user_agent
        )
    if authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
        return await _authenticate_jwt(
            db, token, source_ip=source_ip, user_agent=user_agent
        )
    raise AuthenticationError("Unsupported authentication scheme.")


async def _authenticate_jwt(  # noqa: D103
    db: AsyncSession,
    token: str,
    *,
    source_ip: str | None,
    user_agent: str | None,
) -> AuthPrincipal:
    if not token:
        raise AuthenticationError()
    try:
        payload = get_token_service().decode(token, expected_type=ACCESS_TOKEN_TYPE)
    except TokenError as exc:
        raise AuthenticationError(
            exc.message or "The authentication token is invalid or has expired."
        ) from exc
    try:
        user_id = uuid.UUID(payload.subject)
    except ValueError as exc:
        raise AuthenticationError(
            "The authentication token is invalid or has expired."
        ) from exc

    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        raise AuthenticationError(
            "The account is disabled or no longer exists."
        )
    scopes = USER_SCOPES | frozenset(payload.scopes)
    if user.is_admin:
        scopes |= ADMIN_SCOPES
    return AuthPrincipal(
        user_id=user.id,
        auth_type="jwt",
        scopes=frozenset(scopes),
        user_email=user.email,
        is_admin=user.is_admin,
        source_ip=source_ip,
        user_agent=user_agent,
    )


async def _authenticate_api_key(  # noqa: D103
    db: AsyncSession,
    presented: str,
    *,
    source_ip: str | None,
    user_agent: str | None,
) -> AuthPrincipal:
    digest = hash_api_key(presented)
    row = (
        await db.execute(select(ApiKey).where(ApiKey.key_hash == digest))
    ).scalar_one_or_none()
    if row is None or not row.is_usable():
        raise AuthenticationError("The API key is invalid, expired or revoked.")
    user = await db.get(User, row.user_id)
    if user is None or not user.is_active:
        raise AuthenticationError(
            "The account associated with this API key is disabled."
        )
    row.last_used_at = utcnow()
    return AuthPrincipal(
        user_id=user.id,
        auth_type="api_key",
        scopes=frozenset(parse_scopes(row.scopes)),
        user_email=user.email,
        is_admin=user.is_admin,
        api_key_id=row.id,
        source_ip=source_ip,
        user_agent=user_agent,
    )


async def require_user(
    request: Request, db: Annotated[AsyncSession, Depends(get_db)]
) -> AuthPrincipal:
    """Require a valid authenticated caller."""
    principal = await _authenticate(request, db)
    if principal is None:
        raise AuthenticationError()
    request.state.principal = principal
    return principal


async def optional_user(
    request: Request, db: Annotated[AsyncSession, Depends(get_db)]
) -> AuthPrincipal | None:
    """Resolve the caller when a credential is present, else ``None``.

    A credential that *is* present but invalid still raises: an anonymous
    consumer must simply omit the headers.
    """
    if not (request.headers.get("authorization") or request.headers.get("x-api-key")):
        return None
    principal = await _authenticate(request, db)
    request.state.principal = principal
    return principal


def require_scope(scope: str) -> Callable[..., Awaitable[AuthPrincipal]]:
    """Factory for a dependency requiring a specific scope."""

    async def dependency(
        request: Request,
        principal: Annotated[AuthPrincipal, Depends(require_user)],
    ) -> AuthPrincipal:
        if not principal.has_scope(scope):
            raise AuthorizationError(
                f"The credential does not grant the required scope '{scope}'."
            )
        return principal

    return dependency


async def require_admin(
    request: Request,
    principal: Annotated[AuthPrincipal, Depends(require_user)],
) -> AuthPrincipal:
    """Require an administrator account."""
    if not principal.is_admin:
        raise AuthorizationError("Administrator privileges are required.")
    return principal


def rate_limit(bucket: str) -> Callable[..., Awaitable[None]]:
    """Factory for a rate-limiting dependency on a named bucket.

    Declare ``require_user``/``optional_user`` **before** this parameter in the
    route signature so ``request.state.principal`` is already resolved. The
    limiter keys on ``user:<id>`` for authenticated callers and ``ip:<address>``
    otherwise; every rejection is recorded for abuse analysis.
    """

    async def dependency(
        request: Request,
        db: Annotated[AsyncSession, Depends(get_db)],
    ) -> None:
        identity, _ = client_identity(request)
        limiter = get_rate_limiter()
        rule = limiter.rule_for(bucket)
        try:
            result = await limiter.enforce(bucket, identity)
        except RateLimitError as exc:
            # Every rejection is recorded so abuse patterns are visible even
            # before the caller rotates to another identity. The event is
            # committed here explicitly: the 429 propagation below would
            # otherwise roll back the dependency's session.
            await record_rate_limit_event(
                db,
                identifier=identity,
                rule=bucket,
                limit=rule.requests,
                window_seconds=rule.window_seconds,
                path=request.url.path,
            )
            await db.commit()
            raise
        # Attach the limit headers via request state; the request-ID middleware
        # in ``main`` copies them onto the response so clients can back off.
        request.state.rate_headers = {
            "X-RateLimit-Limit": str(rule.requests),
            "X-RateLimit-Remaining": str(result.remaining),
        }
        return None

    return dependency


DbSession = Annotated[AsyncSession, Depends(get_db)]
UserPrincipal = Annotated[AuthPrincipal, Depends(require_user)]
OptionalPrincipal = Annotated[AuthPrincipal | None, Depends(optional_user)]

__all__ = [
    "ADMIN_SCOPE",
    "ADMIN_SCOPES",
    "AuthPrincipal",
    "USER_SCOPES",
    "client_identity",
    "client_ip",
    "optional_user",
    "rate_limit",
    "require_admin",
    "require_scope",
    "require_user",
]