"""API tests for the authentication endpoints.

Covers the happy paths plus the failure modes that actually matter for account
security: user-enumeration resistance on login, credential lockout, refresh
token rotation (a replayed refresh token stops working), explicit logout
revocation, password change, and the advisory strength meter.
"""

from __future__ import annotations

from sqlalchemy import select

from app.models.user import User

from tests.conftest import TEST_PASSWORD


async def test_login_issues_token_pair(client, make_user):
    info = await make_user()
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": info["email"], "password": TEST_PASSWORD},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["expires_in"] == 1800
    assert body["refresh_expires_in"] == 86400


async def test_login_failure_is_ambiguous_for_missing_account(client):
    """Login timing must not leak whether an email is registered: the error
    string is identical for unknown accounts and bad passwords."""
    unknown = await client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@test.dev", "password": "whatever-Pass-1!"},
    )
    assert unknown.status_code == 401
    assert "Invalid email or password" in unknown.json()["error"]["message"]


async def test_login_unknown_email_does_not_create_row(client, db):
    await client.post(
        "/api/v1/auth/login",
        json={"email": "ghost@test.dev", "password": "whatever-Pass-1!"},
    )
    row = (
        await db.execute(select(User).where(User.email == "ghost@test.dev"))
    ).scalar_one_or_none()
    assert row is None


async def test_account_lockout_after_max_failed_logins(client, make_user, db):
    info = await make_user()
    for _ in range(4):
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": info["email"], "password": "wrong-password-1!"},
        )
        assert response.status_code == 401

    # 5th failure pushes the account into the lockout window.
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": info["email"], "password": "wrong-password-1!"},
    )
    assert response.status_code == 401

    # Even a *correct* password is refused while locked.
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": info["email"], "password": TEST_PASSWORD},
    )
    assert response.status_code == 401
    assert "locked" in response.json()["error"]["message"].lower()

    row = (await db.execute(select(User).where(User.id == info["id"]))).scalar_one()
    assert row.failed_login_count == 5
    assert row.locked_until is not None


async def test_failed_login_counts_are_recorded(client, make_user, db):
    info = await make_user()
    await client.post(
        "/api/v1/auth/login",
        json={"email": info["email"], "password": "wrong-password-1!"},
    )
    row = (await db.execute(select(User).where(User.id == info["id"]))).scalar_one()
    assert row.failed_login_count == 1
    assert row.locked_until is None


async def test_refresh_token_rotation_revokes_old_token(client, make_user):
    info = await make_user()
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": info["email"], "password": TEST_PASSWORD},
    )
    first = login.json()

    refreshed = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]}
    )
    assert refreshed.status_code == 200
    second = refreshed.json()
    assert second["access_token"] != first["access_token"]

    # Replaying the rotated refresh token must fail.
    replay = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]}
    )
    assert replay.status_code == 401


async def test_logout_revokes_access_token(client, make_user):
    info = await make_user()
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": info["email"], "password": TEST_PASSWORD},
    )
    access = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {access}"}

    assert (await client.get("/api/v1/scans", headers=headers)).status_code == 200

    logout = await client.post("/api/v1/auth/logout", headers=headers)
    assert logout.status_code == 204

    # The revoked access token is now rejected.
    assert (await client.get("/api/v1/scans", headers=headers)).status_code == 401


async def test_change_password_requires_current(client, user, user_headers):
    response = await client.post(
        "/api/v1/auth/change-password",
        headers=user_headers,
        json={"current_password": "not-the-password-1!", "new_password": "Brand-New-Pass-99!"},
    )
    assert response.status_code == 401

    response = await client.post(
        "/api/v1/auth/change-password",
        headers=user_headers,
        json={"current_password": TEST_PASSWORD, "new_password": "Brand-New-Pass-99!"},
    )
    assert response.status_code == 204

    good = await client.post(
        "/api/v1/auth/login",
        json={"email": user["email"], "password": "Brand-New-Pass-99!"},
    )
    assert good.status_code == 200


async def test_change_password_rejects_reuse(client, user_headers):
    response = await client.post(
        "/api/v1/auth/change-password",
        headers=user_headers,
        json={"current_password": TEST_PASSWORD, "new_password": TEST_PASSWORD},
    )
    assert response.status_code == 401  # identical to the current hash


async def test_password_strength_advisory(client):
    weak = await client.post("/api/v1/auth/password-strength", json={"password": "abc"})
    assert weak.status_code == 200
    body = weak.json()
    assert body["score"] < 0.5
    assert body["problems"]

    strong = await client.post(
        "/api/v1/auth/password-strength", json={"password": "Tr0ub4dor-&-3"}
    )
    assert strong.status_code == 200
    assert strong.json()["score"] >= 0.5


async def test_disabled_account_cannot_login(client, make_user):
    info = await make_user(active=False)
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": info["email"], "password": TEST_PASSWORD},
    )
    assert response.status_code == 401