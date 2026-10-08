# CyberShield Documentation

CyberShield is a **static-analysis threat scanner**. It takes URLs, raw RFC 5322
email messages, pasted text, arbitrary files, and Android APKs, runs a battery of
*static* detectors plus (with explicit consent) optional third-party reputation
lookups, and returns an evidence-based risk assessment.

The backend is a FastAPI application living in `backend/`. The Flutter client
lives in `client/` and talks to the HTTP API only.

> **Ground rule for this documentation set:** every claim below is backed by the
> source in `backend/`. CyberShield never claims with certainty what the
> evidence cannot support: files and APKs are **never executed**, collected
> samples are never run, and every report carries an explicit disclaimer.

## Repository layout

| Path | Purpose |
| --- | --- |
| `backend/app` | FastAPI application (routes, services, security, ML, scanners) |
| `backend/app/api/routes` | All 31 HTTP endpoints |
| `backend/app/detection_engine` | Static analyzers (url, email, phishing, file, apk, archive, document) |
| `backend/app/scanners` | External scanners: ClamAV (`clamav.py`), YARA (`yara_scanner.py`) |
| `backend/app/threat_intelligence` | Provider fan-out: VirusTotal, URLhaus, Google Safe Browsing, AbuseIPDB |
| `backend/app/ml` | Advisory risk-opinion models (`model.py`, `features.py`) |
| `backend/app/security` | Rate limiting, JWT tokens, passwords, API keys, SSRF, sanitisation |
| `backend/app/workers` | In-process async scan queue (`queue.py`) |
| `backend/app/models` | SQLAlchemy models (9 tables) |
| `backend/alembic` | Migrations (`alembic upgrade head` for non-SQLite databases) |
| `backend/tests` | Pytest suite (`cd backend && ../.venv/bin/python -W ignore -m pytest`) |
| `client/` | Flutter mobile client (consumes the REST API) |
| `detection-engine/yara/rules` | YARA rule set used when YARA is available |
| `docs/` | This documentation set |

## Documentation index

| Section | Content |
| --- | --- |
| [`docs/api/`](api/README.md) | Every endpoint, authentication, scopes, the exact error envelope, rate limiting |
| [`docs/architecture/`](architecture/README.md) | Component architecture, configuration, database, security controls |
| [`docs/project-report/`](project-report/README.md) | Authentic project status, honest non-guarantees, detection methodology, testing |
| [`docs/threat-model/`](threat-model/README.md) | STRIDE-style threat model: assets, trust boundaries, adversary goals, mitigations, residual risks |
| [`docs/diagrams/`](diagrams/README.md) | Mermaid diagrams: architecture, request lifecycle, auth flow, quarantine flow |

## Running the backend for development

Prerequisites: the project virtualenv at `.venv` (Python **3.14**).

```bash
cd /home/sharaf/Projects/cybershield

# 1. Install dependencies (idempotent; already installed in a fresh clone this project)
.venv/bin/pip install -r backend/requirements.txt

# 2. Optional: create a .env from the template
cp backend/.env.example backend/.env        # then edit values; see architecture/configuration.md

# 3. Start the API from the backend directory (package imports resolve there)
cd backend
../.venv/bin/uvicorn app.main:app --reload --port 8000
```

Notes on the default (zero-config) development run:

- **Database:** SQLite by default — `DATABASE_URL=sqlite+aiosqlite:///./cybershield.db`
  (file `backend/cybershield.db`). In `development`/`test`, the schema is created
  automatically at boot (`init_models`). For PostgreSQL or any existing/migrated
  database you must run `alembic upgrade head` yourself — the app never mutates a
  managed schema. See [`docs/architecture/database.md`](architecture/database.md).
- **Secret key:** `SECRET_KEY` is auto-generated per process when unset, which
  invalidates tokens on restart — fine for local development, **forbidden in
  production** (production refuses to boot with a generated key).
- **Redis / queues:** with defaults, no Redis is used. The scan queue worker is
  in-process and rate limiting uses its per-process fallback; `/api/v1/health`
  will report `rate_limiter.degraded: true`, which is expected and truthful.
- **Endpoints after start:**
  - Interactive API docs: <http://localhost:8000/docs> (Swagger) and `/redoc`
  - Root: <http://localhost:8000/> (service info)
  - Health probe: `GET http://localhost:8000/api/v1/health`
  - The service root points at `/api/v1` for every functional route.

### Running the test suite

```bash
cd /home/sharaf/Projects/cybershield/backend
../.venv/bin/python -W ignore -m pytest
```

This runs the full suite (**87 tests** across 11 files). `conftest.py` pins
`ENVIRONMENT=test`, repoints the database and storage to a temp directory, sets a
test `SECRET_KEY` and `QUARANTINE_ENCRYPTION_KEY`, raises the rate limits, and
strips any VirusTotal/OTX/IPQS keys from the environment so no test can make a
live outbound lookup. See [`docs/project-report/testing.md`](project-report/testing.md).

## Quick orientation

1. **Scan something** — `POST /api/v1/scan/url` (and siblings) accepts an object
   and returns a report: `score` (0–100), `verdict`, `confidence`, `reasons`,
   `signals`, a `recommendation`, and the standing disclaimer. For big uploads,
   pass `?async=true` to get a `202` and a `poll_url`.
2. **Verification vocabulary** — every report uses one of
   `SAFE` / `LOW_RISK` / `SUSPICIOUS` / `HIGH_RISK` / `MALICIOUS` / `UNKNOWN`.
   `UNKNOWN` is first-class: it means the analysis could not reach a defensible
   conclusion and is **never** silently downgraded to `SAFE`.
3. **Errors** — every failure is a single envelope, `{"error": {code, message,
   status_code, correlation_id, details?}}`. There is **no top-level `detail`
   key** — clients parse `error.*`. See [`docs/api/README.md`](api/README.md#errors).
4. **Authentication** — either `Authorization: Bearer <access JWT>` or
   `X-API-Key: <key>`. Tokens carry OAuth-style scopes
   (`scan:read`, `scan:write`, `quarantine:read`, `quarantine:write`, `admin:read`).

## Cross-cutting guarantees (read the full list in the project report)

- **Static only.** Files and APKs are parsed structurally or scanned by external
  signatures; nothing is executed, mounted, installed, or instrumented.
  (`backend/app/services/scan_service.py`).
- **Coverage is reported, not hidden.** If an expected check could not run
  (ClamAV down, YARA rules missing, unparseable blob), `scanner_coverage` drops
  and `analysis_incomplete` is set. Coverage below 0.5 with no authoritative
  finding forces `UNKNOWN` — an unavailable detector is never recorded as "clean".
- **Third-party lookups need consent.** Each scan request carries per-scan
  consent toggles (`third_party_lookup`, `dns_lookup`, `active_fetch`); a
  declined lookup returns an explicit "not asked" state, never a clean result.
- **Quarantine is an evidence locker.** Samples are stored under opaque keys,
  integrity-verified and optionally AES-256-GCM-encrypted at rest, expire after
  14 days, and are never executed.
- **Best-effort, in-process state.** Token revocation, the scan queue and the
  rate-limiter fallback are per-process; multi-replica deployments need shared
  state for immediate cross-node logout/garanties. Details in the project report.