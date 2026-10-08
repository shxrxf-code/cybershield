# Threat intelligence & health endpoints

Both routes are prefixed with `/api/v1`.

---

## Intel search

Look up every **cached** answer one indicator has from the threat-intelligence
aggregator. Requires `scan:read`.

Query parameters:

| Param | Type | Meaning |
| --- | --- | --- |
| `indicator` | string (≤ 512 after trim) | URL, domain, IP, hash, email, … |
| `provider` | string (optional) | Filter to one provider's answers |

Critical properties:

- This endpoint is **cache-only**. It reads `threat_intel_cache` and **never**
  makes an outbound query and never submits anything to a third party. The
  cache is filled during scans, and only when the scan's
  `consent.third_party_lookup` permitted it.
- **A missing entry means "unknown from our cache", never "clean".** The
  response says so explicitly, and an empty cache for an indicator is an
  actionable `404 not_found` (see below) rather than an empty result set.
- Answers are bounded by the cache TTL (default 900 s, provider-specific 300 /
  120 s per provider rules in the aggregator) and `expires_at`.

`200` — cached answers plus consensus:

```json
{
  "indicator": "https://evil.example/…",
  "answers": [
    {
      "provider": "virustotal",
      "indicator_type": "url",
      "is_malicious": true,
      "confidence": 0.95,
      "detection_ratio": 18,
      "categories": ["phishing"],
      "threat_type": "phishing",
      "source_name": "…",
      "reference": "…",
      "hit_count": 3,
      "cached_until": "…",
      "metadata": {}
    }
  ],
  "consensus": "malicious",
  "note": "Cached data only; nothing was sent to a third party by this request."
}
```

`consensus` is computed from the returned answers only:

- `malicious` — every answer is malicious.
- `mixed` — some (not all) malicious.
- `clean` — none malicious.

`404 not_found` — no cached reputation for the indicator, with a message that
explicitly states a missing entry means *unknown from our cache*, never
*clean*.

---

## Health

Liveness/readiness probe. This endpoint reports exactly what is true and no
more — it deliberately does **not** fabricate a healthy status when a backend
is absent, because the scan *reports* will say so and the operator should not
learn it here first.

`200` — `HealthResponse`:

```json
{
  "status": "degraded",
  "version": "1.0.0",
  "environment": "development",
  "uptime_seconds": 0.128,
  "checks": {
    "database": { "available": true },
    "worker": { "running": true, "pending": 0 },
    "rate_limiter": {
      "degraded": true,
      "note": "In-process fallback in use; limits are per process, not global."
    },
    "scanners": [
      {
        "name": "yara",
        "available": true,
        "detail": "rules compiled",
        "signal_count": 512
      },
      {
        "name": "clamav",
        "available": false,
        "detail": "unreachable"
      }
    ]
  }
}
```

`status` is one of:

- `ok` — database reachable, the worker is running, and **all** scanners are
  available.
- `degraded` — database reachable but the worker is stopped **or** at least one
  scanner is unavailable.
- `unavailable` — the database probe failed.

`checks` detail:

- `database` — a `SELECT 1` probe; a failure includes a short detail.
- `worker` — whether the in-process queue worker is running and how many jobs
  are pending.
- `rate_limiter` — `degraded: true` exactly when the in-process fallback is in
  use (no Redis), per [architecture/README.md](../architecture/README.md). The
  note explains the consequence (per-process limits).
- `scanners` — one entry each for `yara` and `clamav` with availability, a
  short human detail (`rules compiled`, a ClamAV version string, or the error
  `detail` truncated to 200 chars) and — for YARA — the compiled rule count.

No credentials are required to hit this endpoint.