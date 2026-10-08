"""API tests for user self-service and administration endpoints."""

from __future__ import annotations

from sqlalchemy import select

from app.models.user import User

from tests.conftest import TEST_PASSWORD


async def test_me_returns_profile(client, user, user_headers):
    response = await client.get("/api/v1/users/me", headers=user_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["email"] == user["email"]
    assert body["id"] == str(user["id"])
    assert body["is_admin"] is False


async def test_me_requires_auth(client):
    assert (await client.get("/api/v1/users/me")).status_code == 401


async def test_update_me_sets_display_name(client, user_headers):
    response = await client.patch(
        "/api/v1/users/me", headers=user_headers, json={"full_name": "Renamed"}
    )
    assert response.status_code == 200
    assert response.json()["full_name"] == "Renamed"


async def test_list_users_requires_admin(client, user_headers):
    assert (await client.get("/api/v1/users", headers=user_headers)).status_code == 403


async def test_list_users_as_admin(client, admin_headers):
    response = await client.get("/api/v1/users", headers=admin_headers)
    assert response.status_code == 200
    assert response.json()  # the admin account itself is listed


async def test_create_user_admin_only(client, admin_headers, user_headers):
    created = await client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={"email": "invited@test.dev", "password": TEST_PASSWORD},
    )
    assert created.status_code == 201
    assert created.json()["email"] == "invited@test.dev"
    assert created.json()["is_admin"] is False

    # A regular account may not create users.
    denied = await client.post(
        "/api/v1/users",
        headers=user_headers,
        json={"email": "sneaky@test.dev", "password": TEST_PASSWORD},
    )
    assert denied.status_code == 403


async def test_create_duplicate_email_rejected(client, admin_headers, make_user):
    info = await make_user()
    response = await client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={"email": info["email"], "password": TEST_PASSWORD},
    )
    assert response.status_code == 422  # ValidationError envelope


async def test_admin_toggles_account_flags(client, admin_headers, make_user):
    target = await make_user()
    response = await client.patch(
        f"/api/v1/users/{target['id']}",
        headers=admin_headers,
        json={"is_active": False},
    )
    assert response.status_code == 200
    assert response.json()["is_active"] is False


async def test_admin_cannot_deactivate_self(client, make_user, token_headers):
    admin = await make_user(admin=True)
    admin_auth = await token_headers(admin["id"], admin["email"], admin=True)
    response = await client.patch(
        f"/api/v1/users/{admin['id']}",
        headers=admin_auth,
        json={"is_active": False},
    )
    assert response.status_code == 422  # ValidationError, not a silent no-op


async def test_deactivated_user_cannot_authenticate(client, make_user, admin_headers, token_headers):
    target = await make_user()
    # Deactivate via admin.
    await client.patch(
        f"/api/v1/users/{target['id']}",
        headers=admin_headers,
        json={"is_active": False},
    )
    headers = await token_headers(target["id"], target["email"])
    assert (await client.get("/api/v1/users/me", headers=headers)).status_code == 401


async def test_deactivate_unknown_user_404(client, admin_headers):
    from app.models.base import Base

    import uuid as _uuid

    response = await client.delete(f"/api/v1/users/{_uuid.uuid4()}", headers=admin_headers)
    assert response.status_code == 404