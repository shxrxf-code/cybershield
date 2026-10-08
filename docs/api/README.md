# CyberShield API

This is the reference for the CyberShield HTTP API. Every route lives under the
base path `/api/v1` (`api_v1_prefix`, see
[architecture/configuration.md](../architecture/configuration.md)).

The API is a **static-analysis** threat scanner. It accepts a URL, an RFC 5322
email message, free text, a binary file, or an APK, and returns an
evidence-based risk assessment (score, verdict, confidence, reasons, and
signals). Nothing is executed: files and APKs are only ever inspected
statically, and URL fetch is a controlled, opt-in HTTP fetch (see
[SSRF protection](../architecture/security-controls.md#ssrf-protection)).

## At a glance

| Area | Routes | Detail page |
| --- | --- | --- |
| Authentication | 5 | [auth.md](auth.md) |
| Users & API keys | 6 + 3 | [users-and-api-keys.md](users-and-api-keys.md) |
| Scans (submit, history, reports, dashboard, signal search) | 10 | [scans.md](scans.md) |
| Threat intelligence | 1 | [intel-and-health.md](intel-and-health.md) |
| Quarantine | 5 | [quarantine.md](quarantine.md) |
| Health | 1 | [intel-and-health.md](intel-and-health.md) |
| **Total** | **31** | |

Every endpoint is listed with its exact method and path in the sections below.
The OpenAPI schema is served at `/docs` (Swagger UI) and `/redoc` when
`docs_enabled` is true; both are disabled in the hardened production profile.

## Authentication

Two credential formats are accepted, mutually exclusively per request:

1. **Bearer JWT** — `Authorization: Bearer <access_token>`
2. **API key** — `X-API-Key: <key>` (keys look like `cs_live_<40 hex>` or
   `cs_test_<40 hex>`)

A request that presents **no** credential and reaches a protected route returns
`401 auth_required`. A request that presents an **invalid** credential (bad,
expired, revoked, for a disabled account) returns `401 auth_invalid` — invalid
credentials are never silently treated as anonymous access. Both credential
types resolve to the same `AuthPrincipal`, so routes do not care which one was
used. Full details in [auth.md](auth.md).

## Scopes

Ordinary accounts carry exactly these four scopes:

| Scope | Grants |
| --- | --- |
| `scan:read` | Scan history, reports, dashboard, signal search, intel lookup |
| `scan:write` | Submitting new scans (`/scan/*`), feedback |
| `quarantine:read` | Listing quorum metadata, downloading/releasing files |
| `quarantine:write` | Releasing and deleting quarantined items |

Administrators additionally carry `admin:read`, which is a marker scope
(issued at login) and is how the API distinguishes administrator credentials;
administrator-only routes additionally enforce `require_admin` on the account
itself. API keys may be minted with any supported subset of the scopes (default
`scan:read`); unknown requested scopes are dropped rather than rejected. See
[users-and-api-keys.md](users-and-api-keys.md#api-keys) and
[architecture/security-controls.md](../architecture/security-controls.md#scopes-and-roles).

## Common response surface

### The report

Every scan response and every `ScanDetail` row shares the same core fields:

```json
{
  "scan_id": "uuid",
  "scan_type": "url",
  "object_type": "url",
  "status": "COMPLETED",
  "score": 71.25,
  "verdict": "HIGH_RISK",
  "confidence": 0.72,
  "recommendation": "block",
  "recommendation_text": "Block this destination ...",
  "signals": [],
  "reasons": [],
  "indicators": [],
  "score_breakdown": null,
  "disclaimer": "CyberShield produces automated, evidence-based risk assessments. ...",
  "created_at": "2026-01-01T00:00:00Z"
}
```

Key vocabulary (exact enum values, never invented strings):

- **`verdict`**: `SAFE` | `LOW_RISK` | `SUSPICIOUS` | `HIGH_RISK` | `MALICIOUS` | `UNKNOWN`.
  `UNKNOWN` is a first-class outcome used when the analysis could not reach a
  defensible conclusion; it is **never** silently downgraded to `SAFE`.
- **Score bands** (half-open intervals, `low <= score < next_low`):
  `SAFE` 0–19, `LOW_RISK` 20–39, `SUSPICIOUS` 40–59, `HIGH_RISK` 60–79,
  `MALICIOUS` 80–100.
- **`confidence`**: 0–1 reliability of the overall assessment.
- **`recommendation`**: one of `none` | `monitor` | `verify_sender` |
  `do_not_open` | `do_not_download` | `do_not_install` | `quarantine` |
  `delete` | `block` | `report` | `manual_review`, with a human-readable
  `recommendation_text` attached.
- **`status`** (async scans): `QUEUED` | `SCANNING` | `ANALYZING` |
  `COMPLETED` | `FAILED`.

How the score and verdict are derived — and the exact rule that an incomplete
analysis resolves to `UNKNOWN` — is documented in
[project-report/detection-methodology.md](../project-report/detection-methodology.md).

### Synchronous vs asynchronous scans

Every `/scan/*` submission accepts `?async=true`.

- **Synchronous (default)**: the request runs the pipeline and returns the full
  report (`200`), replaced only by an error if one occurs.
- **Asynchronous**: the request is validated, a scan row is inserted, and the
  job is handed to the worker queue. The response is `202 Accepted`:

  ```json
  {
    "scan_id": "uuid",
    "status": "QUEUED",
    "object_type": "url",
    "poll_url": "/api/v1/scans/<scan_id>"
  }
  ```

  The report is fetched with `GET /api/v1/scans/{scan_id}` until `status`
  becomes `COMPLETED` or `FAILED`. Async file uploads are parked in the upload
  store under an opaque key until the worker consumes them.

## Errors

**Every** error — including Starlette/HTTP-level ones — is returned inside one
stable envelope. There is **no top-level `detail` key**; clients must read
`error.*` (the Flutter client parses `error.code`, `error.message`, and the
optional `error.details`).

```json
{
  "error": {
    "code": "scan_failed",
    "message": "The security scan could not be completed.",
    "status_code": 500,
    "correlation_id": "4f1a2b3c4d5e6f70",
    "details": {}
  }
}
```

- `code` — a stable machine-readable string (see the table below).
- `message` — a human-readable summary. Internal detail (stack traces, file
  paths, provider payloads) is never placed here; it is logged server-side and
  correlated via `correlation_id`.
- `status_code` — the HTTP status.
- `correlation_id` — the same value echoed in the `X-Request-ID` response
  header. Quote it when reporting an issue.
- `details` — **present only when relevant** (e.g. validation `fields`, the
  `retry_after_seconds` on `429`).

`validation_error` responses carry `details.fields`, a list of
`{"field": "body.url", "reason": "string_too_long"}` entries. The field path
points at the exact location, and the reason is the Pydantic error type.

### Error codes

The canonical vocabulary is defined once in
`backend/app/core/exceptions.py` (`ErrorCode`). Two codes are added by
specialised exceptions in `security/`:

| HTTP | `code` | When |
| --- | --- | --- |
| 400 | `ssrf_blocked` | A URL resolves to a forbidden/private network destination |
| 400 | `unsafe_path` | A path traversal is detected or storage path escapes its root |
| 401 | `auth_required` | No credential was presented to a protected route (Starlette mapping) |
| 401 | `auth_invalid` | Bad/expired/revoked credential, disabled or locked account, unsupported auth header |
| 403 | `forbidden` | Authenticated but the credential lacks the required scope |
| 404 | `not_found` | Missing scan/user/key/quarantine item — **including** owner mismatches, which are deliberately collapsed to 404 |
| 409 | `conflict` | e.g. feedback already exists for a scan |
| 413 | `payload_too_large` | Upload or body exceeds a limit |
| 415 | `unsupported_type` | The detected content type is not supported for analysis |
| 422 | `validation_error` | Request payload failed validation (`details.fields` present) |
| 422 | `password_policy_violation` | A new/registering password fails the enforced policy |
| 429 | `rate_limited` | Rate limit exceeded (`Retry-After` header + `details.retry_after_seconds`) |
| 500 | `scan_failed` | A scan could not be completed (including scan timeouts) |
| 500 | `quarantine_error` | A quarantine read/release/delete failed |
| 500 | `internal_error` | An unexpected, unhandled error (generic handler) |
| 503 | `service_unavailable` | A required analysis service is unavailable |

The constants `auth_expired`, `scan_timeout`, and `scanner_error` are part of
the canonical vocabulary but are **not emitted by the current code**: expired
tokens surface as `auth_invalid`, scan timeouts surface as `scan_failed`, and
unavailable scanners degrade the report or surface as `service_unavailable`.
Clients should still recognise the three constants so they keep working if
future versions emit them.

## Rate limiting

Authenticated requests are rate-limited on the account
(`user:<id>` identity); anonymous requests on the client IP
(`ip:<address>` identity). Buckets (requests per minute, env-configurable):

| Bucket | Default | Applied to |
| --- | --- | --- |
| `default` | 60/min | API-key creation, fallback |
| `auth` | 10/min | Login, refresh, change-password, password-strength |
| `scan` | 30/min | URL / email / text scan submission |
| `file_scan` | 10/min | File and APK upload scans |

Every limited response carries:

- `X-RateLimit-Limit` — the bucket's per-minute window.
- `X-RateLimit-Remaining` — remaining requests in the current window.

On overflow the response is `429 rate_limited` with:

- a `Retry-After` header (seconds),
- `details.retry_after_seconds`,
- an audit event in `rate_limit_events` so abuse patterns are visible even
  after an attacker rotates identities.

The limiter is a sliding window backed by Redis when configured, and falls
back to an **in-process per-process** window otherwise. In the fallback mode
limits are per process, not global, and the health endpoint reports
`rate_limiter.degraded: true` — see
[intel-and-health.md#health](intel-and-health.md#health) and
[architecture/configuration.md](../architecture/configuration.md#rate-limiting).

## Request correlation

Every response carries `X-Request-ID`. If the client supplies its own
`x-request-id` header it is honoured; otherwise the server generates a
16-hex-char id. The same value appears in error envelopes as
`correlation_id` and is threaded through async scan jobs so a report can be
traced back to the request that created it.

## Cross-references

- [Auth endpoints](auth.md)
- [Scan endpoints](scans.md)
- [Users & API keys](users-and-api-keys.md)
- [Quarantine endpoints](quarantine.md)
- [Intel & health endpoints](intel-and-health.md)
- [Architecture](../architecture/README.md)
- [Project report (what this does and cannot do)](../project-report/README.md)
- [Detection methodology](../project-report/detection-methodology.md)
- [Threat model](../threat-model/README.md)