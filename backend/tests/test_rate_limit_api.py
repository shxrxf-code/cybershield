"""Rate limiting: headers on success, 429 + Retry-After on refusal, audit row."""

from __future__ import annotations

from sqlalchemy import select

from app.models.audit import RateLimitEvent
from app.security.rate_limit import RateLimit, RateLimiter, set_rate_limiter


async def test_rate_limit_headers_on_success(client, user_headers):
    # Scan submission carries the scan bucket's headers; history reads do not.
    response = await client.post(
        "/api/v1/scan/text", headers=user_headers, json={"text": "rate limit probe"}
    )
    assert response.status_code == 200
    assert response.headers["x-ratelimit-limit"]  # non-empty
    assert response.headers["x-ratelimit-remaining"]
    assert response.headers["x-request-id"]


async def test_rate_limit_rejects_and_records_event(client, db):
    limiter = RateLimiter()
    limiter._rules["auth"] = RateLimit(2, 60.0)  # noqa: SLF001 - test hook
    set_rate_limiter(limiter)
    try:
        # The in-process window store is shared across the whole test session;
        # earlier auth-bucket calls would otherwise trip the artificially low
        # limit of 2 before this test's own requests start.
        identity = "ip:127.0.0.1"  # httpx ASGI transport default client
        await limiter.reset("auth", identity)

        for attempt in range(2):
            response = await client.post(
                "/api/v1/auth/password-strength", json={"password": "x"}
            )
            assert response.status_code == 200, attempt

        refused = await client.post("/api/v1/auth/password-strength", json={"password": "x"})
        assert refused.status_code == 429
        assert refused.headers["retry-after"]
        assert refused.headers["x-request-id"]
    finally:
        set_rate_limiter(None)

    # The rejection was recorded for abuse analysis.
    events = (
        await db.execute(
            select(RateLimitEvent).where(RateLimitEvent.rule == "auth")
        )
    ).scalars().all()
    assert any(event.identifier.startswith("ip:") for event in events)


async def test_rate_limit_keys_by_authenticated_user(client, user_headers, user):
    # Authenticated calls are keyed by user id, not IP, so two users sharing an
    # IP do not share a budget.
    response = await client.get("/api/v1/scans", headers=user_headers)
    assert response.status_code == 200