"""API-key lifecycle tests.

The central property: the plaintext is shown exactly once, and after revocation
authentication through the key fails immediately.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select

from app.models.user import ApiKey


async def test_create_key_returns_plaintext_once(client, user_headers, db):
    response = await client.post(
        "/api/v1/api-keys",
        headers=user_headers,
        json={"name": "ci", "scopes": ["scan:read", "scan:write"]},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["plaintext"]
    assert body["prefix"]
    assert body["plaintext"].startswith(body["prefix"])
    assert body["scopes"] == ["scan:read", "scan:write"]

    # The database stores only the digest.
    row = (await db.execute(select(ApiKey).where(ApiKey.id == uuid.UUID(body["id"])))).scalar_one()
    assert row.key_hash != body["plaintext"]
    assert row.prefix == body["prefix"]


async def test_key_authenticates_scans(client, user_headers, api_key_login):
    _plaintext, key_headers = await api_key_login(user_headers)
    response = await client.post(
        "/api/v1/scan/text",
        headers=key_headers,
        json={"text": "hello world"},
    )
    assert response.status_code == 200


async def test_key_scopes_enforced(client, user_headers):
    # A key scoped only to scan:read can list scans but cannot submit new ones.
    created = await client.post(
        "/api/v1/api-keys",
        headers=user_headers,
        json={"name": "readonly", "scopes": ["scan:read"]},
    )
    assert created.status_code == 201, created.text
    key_headers = {"X-API-Key": created.json()["plaintext"]}

    read_ok = await client.get("/api/v1/scans", headers=key_headers)
    assert read_ok.status_code == 200

    write_denied = await client.post(
        "/api/v1/scan/text", headers=key_headers, json={"text": "hello"}
    )
    assert write_denied.status_code == 403


async def test_key_list_never_shows_plaintext(client, user_headers, api_key_login, db):
    plaintext, _ = await api_key_login(user_headers)
    response = await client.get("/api/v1/api-keys", headers=user_headers)
    assert response.status_code == 200
    body = response.json()
    assert body
    for key in body:
        assert not key.get("plaintext") or key["plaintext"] != plaintext


async def test_revoke_key_blocks_auth(client, user_headers, api_key_login):
    plaintext, key_headers = await api_key_login(user_headers)
    assert (await client.get("/api/v1/users/me", headers=key_headers)).status_code == 200

    listing = await client.get("/api/v1/api-keys", headers=user_headers)
    key_id = listing.json()[0]["id"]
    revoked = await client.post(
        f"/api/v1/api-keys/{key_id}/revoke", headers=user_headers, json={"reason": "test"}
    )
    assert revoked.status_code == 204

    assert (await client.get("/api/v1/users/me", headers=key_headers)).status_code == 401


async def test_revoking_another_users_key_is_404(client, user_headers, admin_headers):
    # Create a key for the admin, attempt to revoke it as the regular user.
    created = await client.post(
        "/api/v1/api-keys",
        headers=admin_headers,
        json={"name": "admin-key"},
    )
    key_id = created.json()["id"]
    response = await client.post(
        f"/api/v1/api-keys/{key_id}/revoke", headers=user_headers, json={"reason": "x"}
    )
    assert response.status_code == 404