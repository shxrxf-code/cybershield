"""User self-service and administration endpoints.

Administration (creating accounts, flipping ``is_active``/``is_admin``) is the
kind of irreversible, privilege-changing action that must be audited, so every
such call writes an :class:`~app.models.audit.AuditEvent`.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from app.api.deps import DbSession, UserPrincipal, require_admin
from app.core.exceptions import NotFoundError, ValidationError
from app.models.base import utcnow
from app.models.user import User
from app.schemas.auth import UserCreateRequest, UserResponse, UserUpdateRequest
from app.security.passwords import get_password_hasher
from app.services.audit import log_audit

router = APIRouter(prefix="/users", tags=["users"])


class AdminUserUpdate(BaseModel):
    """Admin-only modifications to an account."""

    model_config = ConfigDict(extra="forbid")

    is_active: bool | None = None
    is_admin: bool | None = None


def _user_response(user: User) -> UserResponse:
    # ``UserResponse.id`` is a ``str``; pydantic will not coerce a uuid4, so
    # stringify explicitly (mirrors ``str(scan.id)`` in the scan service).
    return UserResponse(
        id=str(user.id),
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        is_admin=user.is_admin,
        is_verified=user.is_verified,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


@router.get("/me", response_model=UserResponse, name="users:me")
async def me(principal: UserPrincipal, db: DbSession) -> UserResponse:
    """The caller's own profile."""
    user = await db.get(User, principal.user_id)
    if user is None:  # defensive: api-key auth always resolves to an account
        raise NotFoundError("Account not found.")
    return _user_response(user)


@router.patch("/me", response_model=UserResponse, name="users:update-me")
async def update_me(
    body: UserUpdateRequest,
    request: Request,
    principal: UserPrincipal,
    db: DbSession,
) -> UserResponse:
    """Update the caller's profile (currently just the display name)."""
    user = await db.get(User, principal.user_id)
    if user is None:
        raise NotFoundError("Account not found.")
    if body.full_name is not None:
        user.full_name = body.full_name
    await log_audit(
        db,
        action="profile.update",
        outcome="success",
        actor_id=user.id,
        actor_label=user.email,
        source_ip=principal.source_ip,
        user_agent=request.headers.get("user-agent"),
    )
    return _user_response(user)


@router.get("", response_model=list[UserResponse], name="users:list")
async def list_users(
    _admin: None = Depends(require_admin),
    db: DbSession = None,
) -> list[UserResponse]:
    """List accounts (admin only)."""
    users = (await db.execute(select(User).order_by(User.created_at))).scalars().all()
    return [_user_response(u) for u in users]


@router.post("", response_model=UserResponse, status_code=201, name="users:create")
async def create_user(
    body: UserCreateRequest,
    request: Request,
    db: DbSession,
    _admin: None = Depends(require_admin),
) -> UserResponse:
    """Create an account (admin only). Passwords follow the enforced policy."""
    existing = (
        await db.execute(select(User).where(User.email == body.email))
    ).scalar_one_or_none()
    if existing is not None:
        raise ValidationError("An account with this email already exists.")

    user = User(
        email=body.email,
        password_hash=get_password_hasher().hash(body.password),
        full_name=body.full_name,
        is_active=True,
        is_admin=False,
        is_verified=False,
        password_changed_at=utcnow(),
    )
    db.add(user)
    await db.flush()
    await log_audit(
        db,
        action="user.create",
        outcome="success",
        actor_id=request.state.principal.user_id,
        actor_label=request.state.principal.user_email,
        target_type="user",
        target_id=str(user.id),
        source_ip=request.state.principal.source_ip,
        user_agent=request.headers.get("user-agent"),
        details={"email": user.email},
    )
    return _user_response(user)


@router.patch("/{user_id}", response_model=UserResponse, name="users:update")
async def update_user(
    user_id: uuid.UUID,
    body: AdminUserUpdate,
    request: Request,
    db: DbSession,
    _admin: None = Depends(require_admin),
) -> UserResponse:
    """Modify an account's flags (admin only)."""
    user = await db.get(User, user_id)
    if user is None:
        raise NotFoundError("Account not found.")
    if body.is_active is not None:
        if not body.is_active and user.id == request.state.principal.user_id:
            raise ValidationError("You cannot deactivate your own account.")
        user.is_active = body.is_active
    if body.is_admin is not None:
        if user.id == request.state.principal.user_id:
            raise ValidationError("You cannot change your own admin flag.")
        user.is_admin = body.is_admin
    await log_audit(
        db,
        action="user.update",
        outcome="success",
        actor_id=request.state.principal.user_id,
        actor_label=request.state.principal.user_email,
        target_type="user",
        target_id=str(user.id),
        source_ip=request.state.principal.source_ip,
        user_agent=request.headers.get("user-agent"),
        details=body.model_dump(exclude_none=True),
    )
    return _user_response(user)


@router.delete("/{user_id}", status_code=204, name="users:deactivate")
async def deactivate_user(
    user_id: uuid.UUID,
    request: Request,
    db: DbSession,
    _admin: None = Depends(require_admin),
) -> None:
    """Deactivate (soft-delete) an account (admin only)."""
    user = await db.get(User, user_id)
    if user is None:
        raise NotFoundError("Account not found.")
    if user.id == request.state.principal.user_id:
        raise ValidationError("You cannot deactivate your own account.")
    user.is_active = False
    user.locked_until = None
    await log_audit(
        db,
        action="user.deactivate",
        outcome="success",
        actor_id=request.state.principal.user_id,
        actor_label=request.state.principal.user_email,
        target_type="user",
        target_id=str(user.id),
        source_ip=request.state.principal.source_ip,
        user_agent=request.headers.get("user-agent"),
    )
    return None