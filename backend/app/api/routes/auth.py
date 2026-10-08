"""Authentication endpoints: login, refresh, logout, password lifecycle.

Session management is stateless: the server issues signed JWTs and keeps only
an in-process **best-effort** revocation list (documented in the project report)
so that logging out is still meaningful in a single-process deployment without
turning the database into a session store. Multi-replica deployments that need
immediate cross-node revocation should back the revocation store with shared
state; see ``docs/project-report``.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select

from app.api.deps import (
    DbSession,
    UserPrincipal,
    client_ip,
    rate_limit,
)
from app.core.config import get_settings
from app.core.exceptions import AuthenticationError
from app.core.logging import request_id_ctx
from app.models.base import utcnow
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    PasswordChangeRequest,
    PasswordStrengthRequest,
    PasswordStrengthResponse,
    RefreshRequest,
    TokenResponse,
)
from app.security.passwords import get_password_hasher, password_strength_score
from app.security.tokens import get_revocation_store, get_token_service
from app.services.audit import log_audit

router = APIRouter(prefix="/auth", tags=["authentication"])

#: Access-token TTLs reported to clients so they can pre-empt refr
REFRESH_OR_ROTATE_THRESHOLD = 0.8


def _ttls() -> tuple[int, int]:
    settings = get_settings()
    return (
        settings.access_token_expire_minutes * 60,
        settings.refresh_token_expire_days * 86_400,
    )


async def _load_user_by_email(db: DbSession, email: str) -> User | None:
    return (
        await db.execute(select(User).where(User.email == email.lower().strip()))
    ).scalar_one_or_none()


@router.post("/login", response_model=TokenResponse, name="auth:login")
async def login(
    body: LoginRequest,
    request: Request,
    _: None = Depends(rate_limit("auth")),
    db: DbSession = None,
) -> TokenResponse:
    """Exchange credentials for an access/refresh token pair."""
    hasher = get_password_hasher()
    user = await _load_user_by_email(db, body.email)

    if user is None:
        # Spend the same ~50 ms as a real Argon2 check so login timing does not
        # reveal whether an email is registered.
        await _dummy_argon2(body.password)
        await log_audit(
            db,
            action="auth.login",
            outcome="failure",
            source_ip=client_ip(request),
            user_agent=request.headers.get("user-agent"),
            request_id=request_id_ctx.get(),
            details={"reason": "unknown_account"},
        )
        raise AuthenticationError("Invalid email or password.")

    if user.is_locked():
        raise AuthenticationError(
            "Account is temporarily locked due to too many failed attempts. "
            "Try again later."
        )

    if not hasher.verify(body.password, user.password_hash):
        user.failed_login_count = (user.failed_login_count or 0) + 1
        if user.failed_login_count >= get_settings().max_failed_logins:
            user.locked_until = utcnow() + timedelta(minutes=get_settings().lockout_minutes)
        await log_audit(
            db,
            action="auth.login",
            outcome="failure",
            actor_id=user.id,
            actor_label=user.email,
            source_ip=client_ip(request),
            user_agent=request.headers.get("user-agent"),
            request_id=request_id_ctx.get(),
            details={
                "reason": "bad_password",
                "failed_count": user.failed_login_count,
            },
        )
        # The counter and lockout are the *point* of this branch; commit them
        # before raising so ``get_db``'s rollback-on-error cannot discard them.
        await db.commit()
        raise AuthenticationError("Invalid email or password.")

    if not user.is_active:
        raise AuthenticationError("This account is disabled.")

    if hasher.needs_rehash(user.password_hash):
        user.password_hash = hasher.hash(body.password)

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = utcnow()

    scopes = list(user_scope_names(user))
    access, refresh = get_token_service().create_token_pair(
        subject=str(user.id), email=user.email, scopes=scopes
    )
    await log_audit(
        db,
        action="auth.login",
        outcome="success",
        actor_id=user.id,
        actor_label=user.email,
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        request_id=request_id_ctx.get(),
        details={"scopes": scopes},
    )
    return _token_response(access, refresh)


@router.post("/refresh", response_model=TokenResponse, name="auth:refresh")
async def refresh(
    body: RefreshRequest,
    request: Request,
    _: None = Depends(rate_limit("auth")),
    db: DbSession = None,
) -> TokenResponse:
    """Rotate a refresh token into a fresh pair.

    The presented refresh token is revoked after use (best-effort, in-process),
    so a replayed token stops working once the event loop has seen it twice.
    """
    try:
        payload = get_token_service().decode_refresh_token(body.refresh_token)
        subject = uuid.UUID(payload.subject)
    except ValueError:
        raise AuthenticationError("The refresh token is invalid.") from None
    user = await db.get(User, subject)
    if user is None or not user.is_active:
        raise AuthenticationError("The account associated with this token is unavailable.")

    get_revocation_store().revoke(payload.jti)
    access, refresh = get_token_service().create_token_pair(
        subject=str(user.id), email=user.email, scopes=list(user_scope_names(user))
    )
    await log_audit(
        db,
        action="auth.refresh",
        outcome="success",
        actor_id=user.id,
        actor_label=user.email,
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        request_id=request_id_ctx.get(),
    )
    return _token_response(access, refresh)


@router.post("/logout", status_code=204, name="auth:logout")
async def logout(
    request: Request,
    principal: UserPrincipal,
    db: DbSession,
) -> Response:
    """Revoke the presented access token (best-effort revocation store)."""
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        try:
            payload = get_token_service().decode_access_token(authorization[7:].strip())
            get_revocation_store().revoke(payload.jti, expires_at=payload.expires_at)
        except AuthenticationError:
            pass  # already invalid at decode time; nothing further to revoke
    await log_audit(
        db,
        action="auth.logout",
        outcome="success",
        actor_id=principal.user_id,
        actor_label=principal.user_email,
        source_ip=principal.source_ip,
        user_agent=request.headers.get("user-agent"),
        request_id=request_id_ctx.get(),
    )
    return Response(status_code=204)


@router.post("/change-password", status_code=204, name="auth:change-password")
async def change_password(
    body: PasswordChangeRequest,
    principal: UserPrincipal,
    db: DbSession,
    request: Request,
    _limit: Annotated[None, Depends(rate_limit("auth"))] = None,
) -> Response:
    """Rotate the caller's own password. Job-based lockouts are not affected."""
    user = await db.get(User, principal.user_id)
    hasher = get_password_hasher()
    if not hasher.verify(body.current_password, user.password_hash):
        raise AuthenticationError("Current password is incorrect.")
    if hasher.verify(body.new_password, user.password_hash):
        raise AuthenticationError("New password must be different from the current one.")

    # ``hash()`` enforces the password policy and raises PasswordPolicyError
    # (a 400-level CyberShieldError) when the new value fails it.
    user.password_hash = hasher.hash(body.new_password)
    user.password_changed_at = utcnow()

    # A password change invalidates every outstanding session token except the
    # one carrying jti ... which we do not store. Best effort: revoke what we
    # can identify (the present access token's jti) and note the gap.
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        try:
            payload = get_token_service().decode_access_token(authorization[7:].strip())
            get_revocation_store().revoke(payload.jti, expires_at=payload.expires_at)
        except AuthenticationError:
            pass

    await log_audit(
        db,
        action="auth.password_change",
        outcome="success",
        actor_id=user.id,
        actor_label=user.email,
        source_ip=principal.source_ip,
        user_agent=request.headers.get("user-agent"),
        request_id=request_id_ctx.get(),
    )
    return Response(status_code=204)


@router.post(
    "/password-strength",
    response_model=PasswordStrengthResponse,
    name="auth:password-strength",
)
async def password_strength(
    body: PasswordStrengthRequest,
    _: None = Depends(rate_limit("auth")),
) -> PasswordStrengthResponse:
    """Advisory strength readout for the client's password meter.

    Advisory only: it never grants access and is not a policy check.
    """
    return PasswordStrengthResponse(**password_strength_score(body.password))


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

_dummy_hash: str | None = None


async def _dummy_argon2(password: str) -> None:
    """Burn the same cost as a real ``verify`` for an unknown account."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = get_password_hasher().hash("cybershield-dummy-timing-equaliser")
    get_password_hasher().verify(password, _dummy_hash)


def user_scope_names(user: User) -> set[str]:
    """Effective scope set for issued tokens (role-based)."""
    from app.api.deps import ADMIN_SCOPES, USER_SCOPES

    scopes = set(USER_SCOPES)
    if user.is_admin:
        scopes |= ADMIN_SCOPES
    return scopes


def _token_response(access: str, refresh: str) -> TokenResponse:
    access_ttl, refresh_ttl = _ttls()
    return TokenResponse.build(access, refresh, access_ttl, refresh_ttl)