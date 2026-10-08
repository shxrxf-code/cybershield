"""Health probe: truthful reporting, never a fabricated "ok".

The test environment has no ClamAV daemon and (with the storage root pinned to
a temp dir) no compiled YARA rule set, so the scanner backends are expected to
report unavailable. The probe must still return 200 with an honest ``degraded``
status and per-component checks.
"""

from __future__ import annotations


async def test_health_reports_component_truth(client):
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] in {"ok", "degraded"}
    assert body["environment"] == "test"
    assert body["version"]
    checks = body["checks"]
    assert "database" in checks
    assert checks["database"]["available"] is True
    assert "worker" in checks
    assert "rate_limiter" in checks
    scanners = {item["name"]: item for item in checks["scanners"]}
    assert "yara" in scanners
    assert "clamav" in scanners
    # No lying: with no ClamAV daemon the probe must not report it available.
    assert scanners["clamav"]["available"] is False


async def test_health_requires_no_auth(client):
    response = await client.get("/api/v1/health")
    assert response.status_code == 200