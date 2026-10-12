# Architecture

This document describes how the CyberShield backend is assembled. It is
organized as:

- **This page** — component map and the two request lifecycles
  (synchronous and asynchronous).
- [configuration.md](configuration.md) — every environment variable and its
  default.
- [database.md](database.md) — the data model, migrations, and storage.
- [security-controls.md](security-controls.md) — authentication, tokens,
  passwords, rate limiting, SSRF defense, sanitisation, and quarantine
  encryption.

Mermaid sequence diagrams for the two lifecycles (and for auth and quarantine)
live in [../diagrams/](../diagrams/README.md).

## Component map

The backend is a FastAPI application in `backend/app`. Import boundaries are
deliberate: the **API layer** never talks to detectors directly, and detectors
never compute scores.

```
                     ┌─────────────────────────────────────────────────┐
  HTTP client        │  API process (single ASGI app)                  │
  (Flutter app,      │                                                 │
   CLI, CI) ────────▶│  app.main: RequestContextMiddleware + CORS     │
                     │        │                                        │
                     │        ▼                                        │
                     │  app.api.routes  (31 endpoints under /api/v1)   │
                     │        │  app.api.deps  (auth, scopes,          │
                     │        │                 rate-limit identity)   │
                     │        ▼                                        │
                     │  app.services                                  │
                     │    scan_service  (pipelines + report assembly)  │
                     │    risk_engine   (the ONLY scorer)              │
                     │    quarantine    (encrypted-blob store)         │
                     │    url_fetcher   (consent-gated HTTP fetch)     │
                     │    audit         (audit log writer)             │
                     │        │                                        │
                     │        ├───────────────┬──────────────────┐     │
                     │        ▼               ▼                  ▼     │
                     │  detection_engine  scanners         threat_     │
                     │  (url/email/file/   (clamav, yara)   intelligence│
                     │   apk/phishing)      └── external ──▶ aggregator │
                     │        │                ClamAV daemon  (VT, URL- │
                     │        ▼                + YARA rules   haus, GS-, │
                     │  ml.model (advisory opinion; sees only           │
                     │       feature vectors, never raw content)        │
                     │                                                 │
                     │  workers.queue: asyncio ScanQueue worker        │
                     │        │                                        │
                     └────────┼────────────────────────────────────────┘
                              ▼
                     ┌──────────────────┐
                     │ data stores      │
                     │  SQLite/Postgres │  models (9 tables, Alembic)
                     │  storage_root/   │  uploads/, quarantine/, tmp/
                     │  Redis (optional)│  rate-limit windows + queue
                     └──────────────────┘
```

### Layer responsibilities

| Component | Files | Responsibility |
| --- | --- | --- |
| Entry point | `app/main.py` | App factory, middleware (`X-Request-ID`, rate-limit headers), CORS, lifespan (dirs, schema init for dev/test SQLite, queue start/stop) |
| API layer | `app/api/router.py`, `app/api/routes/*.py` | 31 endpoints under `/api/v1`; validation, auth wiring, audit calls, response shaping |
| Dependencies | `app/api/deps.py` | Credential resolution (JWT or API key → `AuthPrincipal`), scope checks, client IP, rate-limit dependency |
| Scan orchestration | `app/services/scan_service.py` | Runs every pipeline; tracks scanner coverage; assembles the report; wires ML and intel; persists scans |
| Risk engine | `app/services/risk_engine.py` | The **only** component that assigns score/verdict/confidence/reasons/recommendation. Detectors emit signals; they never score |
| Detection engines | `app/detection_engine/{url,email,file,apk,phishing,web}/…` | Parse and analyse without executing anything; produce `DetectionSignal`s |
| Scanners | `app/scanners/{clamav,yara_scanner}.py` | External ClamAV daemon and local YARA rules; availability-aware |
| ML opinion | `app/ml/{model,features}.py` | Advisory statistical risk opinion over the feature vector; rule-based fallback; can at most add an `ml.risk_underestimate` signal |
| Threat intel | `app/threat_intelligence/…` | Fan-out to VirusTotal/URLhaus/Google Safe Browsing/AbuseIPDB with per-provider timeout, consensus, and bounded cache |
| Quarantine | `app/services/quarantine.py` | AES-256-GCM encrypted blob store (`CBSQ1` envelope), integrity hash, expiry reap, fail-closed reads |
| Queue | `app/workers/queue.py` | In-process asyncio worker for async scans; jobs are lost on restart (by design — see below) |
| Security helpers | `app/security/{tokens,passwords,api_keys,rate_limit,ssrf,sanitize}.py` | The control surface (see [security-controls.md](security-controls.md)) |
| Config | `app/core/config.py` | Environment-driven `Settings`; hardened production validation; runtime dirs |
| Errors | `app/core/exceptions.py` | The single error envelope with 17 canonical codes |
| DB | `app/db/session.py`, `app/models/*.py` | Async engine/session; ORM models (9 tables) |

### Key invariants

- **Signals, not verdicts.** A detector creates `DetectionSignal`s
  (`code`, `title`, `severity`, `category`, `source`, `confidence`,
  `evidence`, `indicators`). Only `risk_engine.assess_risk` aggregates them.
- **Coverage is tracked honestly.** Each pipeline records which checks ran
  (`_Coverage`). When `scanner_coverage` ratio falls below **0.5** the
  analysis is marked incomplete (`analysis_incomplete: true`) and, absent an
  authoritative finding, the result is forced to `UNKNOWN` rather than a false
  all-clear.
- **Nothing is executed.** Files and APKs are static-analysis only. URL fetch
  is consent-gated and SSRF-defended (see
  [security-controls.md#ssrf-protection](security-controls.md#ssrf-protection)).
- **Outbound calls are consent-gated.** Reputation lookups and DNS resolution
  run only when the request's `consent` flags permit them.
- **The worker is an in-process asyncio queue.** `use_redis_queue=false`
  (default) runs a single worker task on the app's event loop. Jobs are
  consumed or lost on restart — a job is by design re-submittable, and a
  failed job marks its scan row `FAILED` (never retried in a loop, so a bad
  provider cannot be hammered).

## Request lifecycles

### Synchronous scan

1. Client calls `POST /api/v1/scan/url?async=false` (default) with a Bearer
   JWT or `X-API-Key`.
2. `app.api.deps` resolves the credential to an `AuthPrincipal`, checks the
   `scan:write` scope, and enforces the `scan` rate-limit bucket (attaching
   `X-RateLimit-Limit`/`X-RateLimit-Remaining` via `request.state`).
3. The route builds the validated request schema and calls the matching
   `ScanService.scan_*`.
4. The pipeline runs: detection engines → (consent-gated) intel/reputation →
   `_apply_ml` → `risk_engine.assess_risk`. Scan coverage is accumulated and
   the report (score/verdict/confidence/reasons/signals/indicators/breakdown)
   is persisted on the `scans` row.
5. The route returns the `200` report and writes an `audit_events` row
   (`scan.submit`).

### Asynchronous scan

1. Client calls the same endpoint with `?async=true`.
2. The request is validated, a `Scan` row is created with
   `status=QUEUED`, and for file/APK uploads the blob is stored under an
   opaque key in `storage_root/uploads/`.
3. The row is committed **before** enqueueing (so the worker never races a
   not-yet-visible row), then a `ScanJob` is pushed to the asyncio queue.
4. The route returns `202 Accepted` with `{scan_id, status: "QUEUED",
   object_type, poll_url: "/api/v1/scans/{scan_id}"}`.
5. The worker pops the job, rebuilds the exact request schema from the stored
   options, loads the blob if any, and runs the same `ScanService.scan_*`
   with the pre-created `scan_id`. On completion the row transitions
   `SCANNING → ANALYZING → COMPLETED`. Any exception is caught at the worker
   boundary: the row becomes `FAILED` with a bounded `error_message`.
6. The temp blob is deleted after the job unless `keep_files_after_scan` is
   set.
7. The client polls `GET /api/v1/scans/{scan_id}` until `status` is terminal.

The two diagrams in [../diagrams/request-lifecycle.md](../diagrams/request-lifecycle.md)
show both flows.

## Storage layout

Default root: `PROJECT_ROOT/var` (i.e. `/home/sharaf/Projects/cybershield/var`);
overridable with `STORAGE_ROOT`. The `.env.example` uses `./data` for local
dev.

| Directory | Purpose |
| --- | --- |
| `var/uploads/` | Async-upload staging blobs (opaque `.upload` keys), deleted after the worker runs |
| `var/quarantine/` | Encrypted (optionally) evidence blobs, keyed by opaque storage keys |
| `var/tmp/` | Scratch space for extraction/text pass-through |

See [configuration.md](configuration.md) for the exact environment variables
that control paths, retention, and behaviour.

## Deployment shapes

- **Single process (dev / small deployments)** — in-process worker, SQLite,
  in-process rate-limit fallback, optional in-memory intel cache. This is the
  default and what the dev instructions in
  [../README.md](../README.md#running-the-backend-for-development) describe.
- **Multi-replica / production profile** — PostgreSQL via
  `DATABASE_URL=postgresql+asyncpg://…`; schema managed exclusively by
  Alembic; `USE_REDIS_QUEUE=true` switches rate-limit counters to a shared Redis
  store so limits are global rather than per process; production hardening
  refuses insecure configs (see
  [configuration.md#production-hardening](configuration.md#production-hardening)).
  Note: the **distributed scan queue is not implemented yet** — the API always
  runs its scan worker in-process (see `app/main.py` and
  [../../infrastructure/README.md](../../infrastructure/README.md#5-the-worker-service-and-use_redis_queue-read-this)),
  so a separate `worker` service is not operational today. Until it is, scale by
  adding `api` containers and keep the queue work in-process.

If you are new to this codebase, start with
[../README.md](../README.md) (orientation and run instructions), then the API
reference in [../api/README.md](../api/README.md).