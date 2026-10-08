"""Quarantine API schemas.

A quarantine item is metadata about a stored, never-executed sample. The bytes
themselves are downloaded through the ``GET``/``release`` endpoints as
``application/octet-stream`` with the original filename re-attached as a
*sanitised display* value; splits are avoided so a malicious original name can
never influence storage or response routing.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import Verdict


class QuarantineItemSummary(BaseModel):
    """One row in the quarantine list view."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str | None
    original_filename: str
    size_bytes: int
    sha256: str
    detected_type: str | None
    verdict: Verdict | None
    score: float | None
    is_encrypted: bool = False
    is_released: bool = False
    created_at: datetime
    expires_at: datetime | None
    metadata_json: dict | None = Field(default=None)


__all__ = ["QuarantineItemSummary"]