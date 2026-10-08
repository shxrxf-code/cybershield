"""Threat-intelligence lookup endpoints.

These read the local reputation cache (filled during scans) and never make an
outbound query by themselves. The cache is a bounded, expiring store, so "no
entry" means *unknown from our cache*, never *clean*, and the response says so.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select

from app.api.deps import DbSession, require_scope
from app.core.exceptions import NotFoundError
from app.models.intel import ThreatIntelCache

router = APIRouter(prefix="/intel", tags=["threat-intel"])

ReadScope = Depends(require_scope("scan:read"))


@router.get("/search", response_model=dict, name="intel:search")
async def search_indicator(
    indicator: str,
    provider: str | None = None,
    _scope: Annotated[None, ReadScope] = None,
    db: DbSession = None,
) -> dict:
    """Return every cached answer about one indicator.

    An empty cache for an indicator is a ``404``: *unknown from our cache* is an
    actionable, honest outcome, and it is clearer to consume than an empty
    result set. This endpoint never triggers an outbound query and never
    submits anything to a third party.
    """
    stmt = (
        select(ThreatIntelCache)
        .where(ThreatIntelCache.indicator == indicator.strip()[:512])
        .order_by(ThreatIntelCache.expires_at.desc())
    )
    if provider:
        stmt = stmt.where(ThreatIntelCache.provider == provider.strip())
    rows = (await db.execute(stmt)).scalars().all()
    if not rows:
        raise NotFoundError(
            "No cached reputation for this indicator. A missing entry means "
            "'unknown from our cache', never 'clean'."
        )

    answers: list[dict] = []
    for row in rows:
        answers.append(
            {
                "provider": row.provider,
                "indicator_type": row.indicator_type,
                "is_malicious": row.is_malicious,
                "confidence": row.confidence,
                "detection_ratio": row.detection_ratio,
                "categories": [
                    c.strip() for c in (row.categories or "").split(",") if c.strip()
                ],
                "threat_type": row.threat_type,
                "source_name": row.source_name,
                "reference": row.reference,
                "hit_count": row.hit_count,
                "cached_until": row.expires_at,
                "metadata": row.metadata_json or {},
            }
        )
    positives = [a for a in answers if a["is_malicious"]]
    consensus = (
        "malicious"
        if positives and len(positives) == len(answers)
        else ("mixed" if positives else "clean")
    )
    return {
        "indicator": indicator.strip()[:512],
        "answers": answers,
        "consensus": consensus,
        "note": "Cached data only; nothing was sent to a third party by this request.",
    }