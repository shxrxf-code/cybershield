"""Quarantine endpoints: browse, download, release, delete.

The stored bytes are decrypted and integrity-checked on every read, never
executed or mounted. Downloads and releases are audited. The filename attached
to a download is always the **sanitised display name** - the original name is
never used as a path or an OS route, so a malicious original filename cannot
influence routing or storage.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response

from app.api.deps import DbSession, UserPrincipal, require_scope
from app.core.config import get_settings
from app.core.exceptions import NotFoundError, QuarantineError
from app.models.quarantine import QuarantineItem
from app.schemas.quarantine import QuarantineItemSummary
from app.security.sanitize import sanitize_filename
from app.services.quarantine import get_quarantine_service
from sqlalchemy import select

router = APIRouter(prefix="/quarantine", tags=["quarantine"])

ReadScope = Depends(require_scope("quarantine:read"))
WriteScope = Depends(require_scope("quarantine:write"))


def _summary(item: QuarantineItem) -> QuarantineItemSummary:
    return QuarantineItemSummary.model_validate(
        {
            "id": str(item.id),
            "scan_id": str(item.scan_id) if item.scan_id else None,
            "original_filename": item.original_filename,
            "size_bytes": item.size_bytes,
            "sha256": item.sha256,
            "detected_type": item.detected_type,
            "verdict": item.verdict,
            "score": item.score,
            "is_encrypted": item.is_encrypted,
            "is_released": item.is_released,
            "created_at": item.created_at,
            "expires_at": item.expires_at,
            "metadata_json": item.metadata_json or {},
        }
    )


async def _get_owned_item(
    db: DbSession, item_id: uuid.UUID, principal: UserPrincipal
) -> QuarantineItem:
    item = await db.get(QuarantineItem, item_id)
    if item is None:
        raise NotFoundError("Quarantine item not found.")
    if not principal.is_admin and item.user_id != principal.user_id:
        raise NotFoundError("Quarantine item not found.")
    return item


@router.get("", response_model=list[QuarantineItemSummary], name="quarantine:list")
async def list_items(
    principal: UserPrincipal,
    db: DbSession,
    _scope: Annotated[None, ReadScope] = None,
) -> list[QuarantineItemSummary]:
    """List quarantined samples the caller may access (admins see all)."""
    stmt = select(QuarantineItem).order_by(QuarantineItem.created_at.desc())
    if not principal.is_admin:
        stmt = stmt.where(QuarantineItem.user_id == principal.user_id)
    rows = (await db.execute(stmt)).scalars().all()
    return [_summary(item) for item in rows]


@router.get("/{item_id}", response_model=QuarantineItemSummary, name="quarantine:get")
async def get_item(
    item_id: uuid.UUID,
    principal: UserPrincipal,
    db: DbSession,
    _scope: Annotated[None, ReadScope] = None,
) -> QuarantineItemSummary:
    """Metadata for one quarantined sample (never its bytes)."""
    item = await _get_owned_item(db, item_id, principal)
    return _summary(item)


@router.get("/{item_id}/download", name="quarantine:download")
async def download_item(
    item_id: uuid.UUID,
    request: Request,
    principal: UserPrincipal,
    db: DbSession,
    _scope: Annotated[None, ReadScope] = None,
) -> Response:
    """Download the verified, decrypted bytes. Audited."""
    service = get_quarantine_service(get_settings())
    item = await _get_owned_item(db, item_id, principal)
    stored = await service.read_blob(
        db,
        item,
        actor_id=principal.user_id,
    )
    name = sanitize_filename(item.original_filename) or "quarantined-file.bin"
    return Response(
        content=stored.data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "X-Quarantine-Id": str(item.id),
            "X-Quarantine-Sha256": item.sha256,
            "Content-Length": str(len(stored.data)),
        },
    )


@router.post("/{item_id}/release", name="quarantine:release")
async def release_item(
    item_id: uuid.UUID,
    request: Request,
    principal: UserPrincipal,
    db: DbSession,
    _scope: Annotated[None, WriteScope] = None,
) -> Response:
    """Mark the item released and return its verified bytes. Audited."""
    service = get_quarantine_service(get_settings())
    item = await _get_owned_item(db, item_id, principal)
    stored = await service.release(
        db,
        item,
        actor_id=principal.user_id,
    )
    name = sanitize_filename(item.original_filename) or "quarantined-file.bin"
    return Response(
        content=stored.data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "X-Quarantine-Id": str(item.id),
            "X-Quarantine-Sha256": item.sha256,
        },
    )


@router.delete("/{item_id}", status_code=204, name="quarantine:delete")
async def delete_item(
    item_id: uuid.UUID,
    request: Request,
    principal: UserPrincipal,
    db: DbSession,
    _scope: Annotated[None, WriteScope] = None,
) -> None:
    """Delete the blob and its row. Audited; permanent."""
    service = get_quarantine_service(get_settings())
    item = await _get_owned_item(db, item_id, principal)
    await service.delete(
        db,
        item,
        actor_id=principal.user_id,
        source_ip=principal.source_ip,
        user_agent=request.headers.get("user-agent"),
    )
    return None