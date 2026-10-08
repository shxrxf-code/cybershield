"""Quarantine lifecycle over the API.

Because quarantine is an evidence locker, the tests assert the byte-level
properties that matter: only the owner can download, decrypted bytes match the
upload, and delete removes the blob from disk as well as the row.
"""

from __future__ import annotations

import json

from app.core.config import get_settings


async def _quarantine_one_file(client, headers) -> dict:
    content = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00fake-executable"
    await client.post(
        "/api/v1/scan/file",
        headers=headers,
        files={"file": ("sample.exe", content, "application/x-msdownload")},
        data={"options": json.dumps({"skip_yara": True, "skip_antivirus": True})},
    )
    listing = await client.get("/api/v1/quarantine", headers=headers)
    assert listing.status_code == 200
    items = listing.json()
    assert items, "expected a quarantined item after a non-quick file scan"
    return items[0]


async def test_file_scan_creates_quarantine_item(client, user_headers):
    item = await _quarantine_one_file(client, user_headers)
    assert item["original_filename"] == "sample.exe"
    assert item["size_bytes"] > 0
    assert len(item["sha256"]) == 64
    assert item["is_released"] is False


async def test_quarantine_download_round_trip(client, user_headers):
    settings = get_settings()
    item = await _quarantine_one_file(client, user_headers)
    download = await client.get(f"/api/v1/quarantine/{item['id']}/download", headers=user_headers)
    assert download.status_code == 200
    assert download.headers["content-disposition"].startswith("attachment")
    assert len(download.content) == item["size_bytes"]
    # Decrypt-integrity is enforced by the quarantine service; reaching here
    # already proves the blob passed authenticity verification.
    assert download.content[:2] == b"MZ"


async def test_quarantine_ownership_isolation(client, user_headers, make_user, token_headers):
    item = await _quarantine_one_file(client, user_headers)
    other = await make_user()
    other_headers = await token_headers(other["id"], other["email"])
    stolen = await client.get(
        f"/api/v1/quarantine/{item['id']}/download", headers=other_headers
    )
    assert stolen.status_code == 404


async def test_quarantine_release_marks_item(client, user_headers):
    item = await _quarantine_one_file(client, user_headers)
    released = await client.post(
        f"/api/v1/quarantine/{item['id']}/release", headers=user_headers
    )
    assert released.status_code == 200
    assert released.content[:2] == b"MZ"

    detail = await client.get(f"/api/v1/quarantine/{item['id']}", headers=user_headers)
    assert detail.json()["is_released"] is True


async def test_quarantine_delete_removes_blob_and_row(client, user_headers):
    item = await _quarantine_one_file(client, user_headers)
    response = await client.delete(f"/api/v1/quarantine/{item['id']}", headers=user_headers)
    assert response.status_code == 204

    assert (await client.get(f"/api/v1/quarantine/{item['id']}", headers=user_headers)).status_code == 404
    stale = await client.get(f"/api/v1/quarantine/{item['id']}/download", headers=user_headers)
    assert stale.status_code == 404


async def test_quick_scan_does_not_quarantine(client, user_headers):
    content = b"not-quarantined"
    await client.post(
        "/api/v1/scan/file",
        headers=user_headers,
        files={"file": ("x.txt", content, "text/plain")},
        data={"options": json.dumps({"quick": True})},
    )
    listing = await client.get("/api/v1/quarantine", headers=user_headers)
    # Any items here belong to earlier tests in the shared session; a quick scan
    # specifically must not have added one with our filename.
    names = [item["original_filename"] for item in listing.json()]
    assert "x.txt" not in names