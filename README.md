# CyberShield

CyberShield scans URLs, email messages, free text, files and APK builds for
malicious content without executing anything. Every report carries a verdict
(`SAFE` / `LOW_RISK` / `SUSPICIOUS` / `HIGH_RISK` / `MALICIOUS` / `UNKNOWN`)
alongside the **confidence** behind it, the **reasons**, the signals that led
to it, the analyzers that actually ran, and a recommendation.

> Honest assessment is a product requirement, not a tagline. CyberShield never
> claims 100% certainty, never reports a verdict for analyzers that did not
> run, and never presents "unknown from our cache" as "clean". See
> [`docs/project-report`](docs/project-report/) for the limits it is honest
> about.

## Repository layout

| Path | What lives there |
|---|---|
| `backend/` | FastAPI + SQLAlchemy (async) + Pydantic + Alembic API. Dev default is SQLite; production is PostgreSQL with Redis for distributed rate limiting. |
| `client/` | Flutter client (Android / iOS / Windows / Linux / macOS) consuming `/api/v1` — device-folder & file scans, reports, quarantine, intel, installed-apps list. |
| `detection-engine/` | Static analyzers and the built-in YARA rule set. |
| `docs/` | API reference, architecture, threat model, diagrams, and an honest project report. |
| `infrastructure/` | Dockerfile, `docker-compose.yml`, nginx, database and deployment runbook. |
| `scripts/` | Support scripts (e.g. secret generation). |

## Backend — run for development

Requirements: Python 3.14 (a `.venv` is expected at the repo root).

```bash
cd backend
cp .env.example .env            # then set SECRET_KEY and any overrides
../.venv/bin/pip install -r requirements.txt   # + requirements-scan.txt / requirements-ml.txt for full features
../.venv/bin/uvicorn app.main:app --reload     # http://127.0.0.1:8000, docs at /docs
```

Settings are environment-only (12-factor) and read from `.env` (or `../.env`)
in the working directory — see `backend/.env.example` for the full surface.

### Run the test suite

```bash
cd backend
../.venv/bin/python -W ignore -m pytest
```

The suite (87 tests) runs against a shared in-process SQLite database and
never makes outbound network, DNS or reputation calls. It covers auth,
lockout, token rotation, API keys, every scan entry point, async scans,
quarantine, rate limiting, threat-intel cache honesty (`404` = *unknown from
our cache*, never *clean*), the advisory ML layer, and the health probe's "no
fabricated healthy status" rule.

### Migrations

Schema is owned by Alembic (`backend/alembic/`). The app only auto-creates
tables for SQLite outside production.

```bash
cd backend
../.venv/bin/alembic upgrade head     # apply migrations (needs DATABASE_URL set)
```

## Flutter client

```bash
cd client
/home/sharaf/flutter/bin/flutter run                        # default device
/home/sharaf/flutter/bin/flutter run --dart-define=API_BASE_URL=http://127.0.0.1:8000
```

The API base URL defaults to `http://localhost:8000`. The GUI itself has no
login screen — it boots straight to the shell and relies on a remembered
session (see `client/README.md`). The API's own auth supports both account
credentials (JWT with refresh rotation) and API keys (`X-API-Key`), which the
client library attaches automatically when a session is stored.

## Production deployment

See [`infrastructure/README.md`](infrastructure/README.md). The stack is
PostgreSQL 16 + Redis 7 + the API image behind nginx, with Alembic applied at
boot, quarantine blobs encrypted at rest, mandatory secrets, and an optional
ClamAV/YARA scanner profile. Quick start:

```bash
scripts/generate-secrets.sh     # fill the three secrets into infrastructure/.env
cd infrastructure
docker compose up -d --build    # http://127.0.0.1:8000, /api/v1/health
```

## API

- Interactive docs at `/docs`, OpenAPI JSON at `/openapi.json`.
- Reference: [`docs/api/`](docs/api/README.md).
- Errors share one envelope `{"error": {code, message, status_code, correlation_id, details?}}` — there is **no** top-level `detail` key.
- Rate limiting reports `X-RateLimit-Limit` / `X-RateLimit-Remaining`; every response carries an `X-Request-ID` correlation id.

## Security posture

- Argon2 password hashing; JWT access/refresh with refresh-token rotation and logout revocation; account lockout after repeated failures.
- SSRF defences on URL/normalisation/redirect paths; path-traversal and MIME sanitisation on uploads.
- All analysis is **static** — nothing is executed, mounted, or installed.
- Third-party threat-intel lookups happen only with explicit user consent, and the intel cache is never presented as a guarantee.
- API keys are shown in plaintext exactly once and stored only as SHA-256 digests.
- Quarantined samples are encrypted at rest; downloads/releases are audited.