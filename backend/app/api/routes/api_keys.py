"""API-key management endpoints.

A key's plaintext is shown exactly once, at creation, then never again - not
even to an administrator. Database rows hold only the SHA-256 digest plus a
non-secret display prefix, so a dump of ``api_keys`` is not a credential dump.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select

from app.api.deps import DbSession, UserPrincipal, rate_limit
from app.core.config import get_settings
from app.core.exceptions import NotFoundError
from app.models.base import utcnow
from app.models.user import ApiKey
from app.schemas.auth import ApiKeyCreateRequest, ApiKeyResponse, RevokeRequest
from app.security.api_keys import (
    DEFAULT_TTL_DAYS,
    default_expiry,
    generate_api_key,
    normalise_scopes,
)
from app.services.audit import log_audit

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


def _key_response(key: ApiKey) -> ApiKeyResponse:
    return ApiKeyResponse(
        id=str(key.id),
        name=key.name,
        prefix=key.prefix,
        scopes=key.scope_list,
        is_active=key.is_active,
        created_at=key.created_at,
        expires_at=key.expires_at,
        last_used_at=key.last_used_at,
    )


@router.get("", response_model=list[ApiKeyResponse], name="api_keys:list")
async def list_api_keys(
    principal: UserPrincipal,
    db: DbSession,
) -> list[ApiKeyResponse]:
    """List the caller's API keys with their metadata and scopes."""
    rows = (
        await db.execute(
            select(ApiKey)
            .where(ApiKey.user_id == principal.user_id)
            .order_by(ApiKey.created_at)
        )
    ).scalars().all()
    return [_key_response(key) for key in rows]


@router.post(
    "", response_model=ApiKeyResponse, status_code=201, name="api_keys:create"
)
async def create_api_key(
    body: ApiKeyCreateRequest,
    principal: UserPrincipal,
    db: DbSession,
    request: Request,
    _limit: Annotated[None, Depends(rate_limit("default"))] = None,
) -> ApiKeyResponse:
    """Create a machine credential.

    ``plaintext`` appears once in this response and cannot be recovered later,
    so the caller must store it immediately.
    """
    settings = get_settings()
    generated = generate_api_key(environment=settings.environment)
    expires_at = default_expiry(body.expires_in_days or DEFAULT_TTL_DAYS)
    key = ApiKey(
        user_id=principal.user_id,
        name=body.name,
        prefix=generated.prefix,
        key_hash=generated.key_hash,
        scopes=normalise_scopes(body.scopes),
        is_active=True,
        expires_at=expires_at,
    )
    db.add(key)
    await db.flush()
    await log_audit(
        db,
        action="api_key.create",
        outcome="success",
        actor_id=principal.user_id,
        actor_label=principal.user_email,
        target_type="api_key",
        target_id=str(key.id),
        source_ip=principal.source_ip,
        user_agent=request.headers.get("user-agent"),
        details={"prefix": key.prefix, "scopes": key.scope_list},
    )
    response = _key_response(key)
    response.plaintext = generated.plaintext
    return response


@router.post("/{key_id}/revoke", status_code=204, name="api_keys:revoke")
async def revoke_api_key(
    key_id: uuid.UUID,
    body: RevokeRequest,
    request: Request,
    principal: UserPrincipal,
    db: DbSession,
) -> None:
    """Revoke a key immediately. Authentication via it stops on the next use."""
    key = await db.get(ApiKey, key_id)
    if key is None or key.user_id != principal.user_id:
        raise NotFoundError("API key not found.")
    key.is_active = False
    key.revoked_at = utcnow()
    await log_audit(
        db,
        action="api_key.revoke",
        outcome="success",
        actor_id=principal.user_id,
        actor_label=principal.user_email,
        target_type="api_key",
        target_id=str(key.id),
        source_ip=principal.source_ip,
        user_agent=request.headers.get("user-agent"),
        details={"prefix": key.prefix, "reason": body.reason},
    )
    return None