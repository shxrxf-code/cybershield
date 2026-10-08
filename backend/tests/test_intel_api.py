"""Threat-intel cache API.

The cache is filled *during scans* (only when the user consented to third-party
lookup). These tests seed rows directly and verify the key honesty property: a
missing cache entry is a 404 meaning "unknown from our cache", never "clean".
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from app.models.base import utcnow
from app.models.intel import ThreatIntelCache


async def test_unknown_indicator_is_404_not_clean(client, user_headers):
    response = await client.get(
        "/api/v1/intel/search?indicator=never-seen.example.com", headers=user_headers
    )
    assert response.status_code == 404
    assert "unknown from our cache" in response.json()["error"]["message"].lower()


async def test_cached_answer_returns_with_consensus(client, user_headers, db):
    db.add(
        ThreatIntelCache(
            provider="test-provider",
            indicator_type="hostname",
            indicator="mal.example.com",
            is_malicious=True,
            confidence=0.9,
            detection_ratio="11/20",
            categories="malware,phishing",
            source_name="test-feed",
            expires_at=utcnow() + timedelta(hours=2),
            hit_count=3,
            metadata_json={"raw": {"verdict": "malicious"}},
        )
    )
    await db.commit()

    response = await client.get(
        "/api/v1/intel/search?indicator=mal.example.com", headers=user_headers
    )
    assert response.status_code == 200
    body = response.json()
    assert body["indicator"] == "mal.example.com"
    assert body["consensus"] == "malicious"
    assert len(body["answers"]) == 1
    answer = body["answers"][0]
    assert answer["provider"] == "test-provider"
    assert answer["is_malicious"] is True
    assert answer["detection_ratio"] == "11/20"
    assert answer["categories"] == ["malware", "phishing"]
    assert response.json()["note"]


async def test_intel_search_requires_auth(client):
    response = await client.get("/api/v1/intel/search?indicator=any.example.com")
    assert response.status_code == 401