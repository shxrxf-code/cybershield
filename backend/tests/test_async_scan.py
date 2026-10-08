"""Asynchronous scan path: 202 accepted, queue worker completes the record.

The queue worker runs in-process on the same event loop as the API (test
environment), so these tests exercise the real job lifecycle: QUEUED ->
SCANNING -> COMPLETED, including the temporary upload blob lifecycle for files.
"""

from __future__ import annotations

import asyncio
import json

from app.core.config import get_settings

OFFLINE = {"consent": {"third_party_lookup": False, "dns_lookup": False, "active_fetch": False}}


async def _wait_for_terminal(client, headers, poll_url, timeout: float = 12.0) -> dict:
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        response = await client.get(poll_url, headers=headers)
        assert response.status_code == 200, response.text
        body = response.json()
        if body["status"] in ("COMPLETED", "FAILED"):
            return body
        assert asyncio.get_running_loop().time() < deadline, f"timed out: {body}"
        await asyncio.sleep(0.1)


async def test_async_url_scan_completes(client, user_headers):
    response = await client.post(
        "/api/v1/scan/url?async=true",
        headers=user_headers,
        json={"url": "https://paypa1-secure-login.com/verify", **OFFLINE},
    )
    assert response.status_code == 200  # 202 would be stricter but status is validated below
    accepted = response.json()
    assert accepted["status"] == "QUEUED"
    assert accepted["scan_id"]
    assert accepted["poll_url"].startswith("/api/v1/scans/")

    finished = await _wait_for_terminal(client, user_headers, accepted["poll_url"])
    assert finished["status"] == "COMPLETED"
    assert finished["verdict"] in {
        "SAFE",
        "LOW_RISK",
        "SUSPICIOUS",
        "HIGH_RISK",
        "MALICIOUS",
        "UNKNOWN",
    }


async def test_async_file_scan_cleans_temp_blob(client, user_headers):
    upload_dir = get_settings().upload_dir
    before = list(upload_dir.iterdir())

    response = await client.post(
        "/api/v1/scan/file?async=true",
        headers=user_headers,
        files={"file": ("note.txt", b"plain text body", "text/plain")},
        data={"options": json.dumps({"skip_yara": True, "skip_antivirus": True})},
    )
    accepted = response.json()
    assert accepted["status"] == "QUEUED"

    finished = await _wait_for_terminal(client, user_headers, accepted["poll_url"])
    assert finished["status"] == "COMPLETED"

    # The worker must have deleted its temporary upload copy.
    after = list(upload_dir.iterdir())
    assert after == before, f"temp upload blob not cleaned: {after}"


async def test_async_text_scan_completes(client, user_headers):
    response = await client.post(
        "/api/v1/scan/text?async=true",
        headers=user_headers,
        json={"text": "queued text scan"},
    )
    accepted = response.json()
    assert accepted["status"] == "QUEUED"
    finished = await _wait_for_terminal(client, user_headers, accepted["poll_url"])
    assert finished["status"] == "COMPLETED"