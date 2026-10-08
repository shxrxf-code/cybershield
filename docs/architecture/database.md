# Database

The backend uses **SQLAlchemy 2.x async** ORM. The default
`DATABASE_URL` is SQLite (`sqlite+aiosqlite:///./cybershield.db` — a file
`cybershield.db` beside the `backend/` folder when run from there) for
local development and tests; deployments use PostgreSQL
(`postgresql+asyncpg://…`).

## Conventions

- **UUID primary keys** (`uuid4`, generated in Python). An id in an API
  response never reveals object counts, and objects are addressable before
  being flushed.
- **Timestamps** are timezone-aware UTC (`created_at`, `updated_at`),
  server-defaulted *and* set by the ORM, so rows created by raw SQL still
  carry sane timestamps.
- **JSON columns for detector-defined shapes.** Signal bundles, score
  breakdowns, and metadata live in JSON because the shape of a finding is
  detector-defined. Anything that is queried or sorted on is a **real
  column**, never JSON (e.g. `score`, `verdict`, `target_host`).
- The logical JSON type is `JSONType`: it is `JSONB` on PostgreSQL and `JSON`
  elsewhere, chosen at bind time, so the same models run on SQLite and
  PostgreSQL unchanged.
- **Explicit constraint names** via a naming convention, so Alembic
  autogenerates a stable, reviewable history instead of database-chosen names.
- Engine tuning: SQLite uses `NullPool` plus a 30 s busy timeout (a shared
  in-process connection breaks under concurrent access); other engines use
  `pool_size`/`max_overflow`, `pool_pre_ping`, and `pool_recycle=1800`
  (`app/db/session.py`).

## Schema management

- **Development/test SQLite**: `app.main._maybe_init_models` runs
  `Base.metadata.create_all` at boot *only* when `ENVIRONMENT` is
  `development` or `test` and the URL starts with `sqlite`. Boot never mutates
  a managed database.
- **Everything else — Alembic.** Run migrations against the configured
  environment:

  ```bash
  cd backend
  ../.venv/bin/alembic upgrade head
  ```

  Alembic's `env.py` imports `app.models` for its registration side effect
  (all tables on `Base.metadata`), then takes `DATABASE_URL` from
  `get_settings()` when `alembic.ini` does not provide one — so migrations
  track the configured environment. `compare_type=True` is set so column-type
  drift is caught by `--autogenerate`.

  ```bash
  # To generate a new migration after a model change:
  ../.venv/bin/alembic revision --autogenerate -m "describe change"
  ../.venv/bin/alembic upgrade head
  ```

## Tables (9 application tables)

The initial migration `a91c98690983_initial_schema` creates all application
tables. (Alembic also manages its own `alembic_version` bookkeeping table.)

| Table | Purpose and notable columns |
| --- | --- |
| `rate_limit_events` | Every rate-limit rejection (`identifier`, `rule`, `limit`, `window_seconds`, `path`, `occurred_at`) so abuse patterns are visible even across rotated identities. |
| `threat_intel_cache` | Cached provider answers (`provider`, `indicator_type`, `indicator`, `is_malicious`, `confidence`, `detection_ratio`, `categories`, `threat_type`, `source_name`, `reference`, `hit_count`, `expires_at`). Unique index on `(provider, indicator_type, indicator)`. |
| `users` | Accounts: `email` (unique, indexed), `password_hash`, `full_name`, `is_active`, `is_admin`, `is_verified`, `failed_login_count`, `locked_until`, `last_login_at`, `password_changed_at`. |
| `api_keys` | Machine credentials: `user_id` (FK, CASCADE), `name`, `prefix`, `key_hash` (SHA-256, unique), `key_prefix_pepper`, `scopes`, `is_active`, `expires_at`, `last_used_at`, `revoked_at`. Only digests are stored — a dump of this table is not a credential dump. |
| `audit_events` | Action log: `action`, `outcome`, `actor_id` (FK, SET NULL), `actor_label`, `target_type`, `target_id`, `source_ip`, `user_agent`, `request_id`, `details` (JSON), `message`. Indexed on `(action, created_at)` and `(actor_id, created_at)`. |
| `scans` | Scan rows and persisted reports: `user_id` (FK, SET NULL), `scan_type`, `status`, `object_type`, `target_*` (label/url/host/email/subject/filename), `storage_key`, `size_bytes`, hash columns (`sha256`/`sha1`/`md5`/`object_hash`), `score`, `verdict`, `confidence`, `recommendation`, `reasons` (JSON), `signals` (JSON), `score_breakdown` (JSON), `metadata_json` (JSON), `duration_ms`, `analyzers_run`, `is_quarantined`, `error_message`, `expires_at`. Indexed on `(user_id, created_at)`, `(object_hash, scan_type)`, `sha256`, `verdict`, `status`, `target_host`, `target_email`, `expires_at`. |
| `quarantine_items` | Evidence blobs: `scan_id` (FK, SET NULL), `user_id`, `storage_key` (unique), `original_filename`, `size_bytes`, `sha256`, `sha1`, `md5`, `detected_type`, `verdict`, `score`, `reason`, `stored_integrity_hash`, `is_encrypted`, `encryption_algorithm`, `metadata_json`, `is_released`, `released_at`, `expires_at`. |
| `scan_feedback` | One verdict label per scan: `scan_id` (unique, FK, CASCADE), `label`, `comment`. |
| `quarantine_access_log` | Audit of every quarantine read/release/delete/reap: `quarantine_id` (FK, CASCADE), `user_id` (FK, SET NULL), `action`, `source_ip`, `user_agent`. |

Referential integrity:

- Deleting a **user** cascades to its `api_keys` and `scan_feedback` rows;
  `scans`, `audit_events`, and `quarantine_*` records keep the user id
  prefixed with `SET NULL` (audit history survives account deletion).
- Deleting a **scan** cascades its feedback; `quarantine_items` keep the
  `scan_id` nullable so an indicator can be cleaned while the sample remains.
- Deleting a **quarantine item** cascades its access log.

## Retention and reaping

- `scans.expires_at` = `created_at + scan_retention_days` (90). The scan row
  can expire while a quarantined copy is still held — deliberately, so an
  indicator can be cleaned while the sample remains.
- `quarantine_items.expires_at` = `created_at + quarantine_retention_days`
  (14). A maintenance sweep reaps expired items and records the `reap` action
  in `quarantine_access_log`.
- `threat_intel_cache.expires_at` is enforced by the provider cache TTLs on
  read (positive hits 900 s, clean 300 s, unknown 120 s), and the `/intel`
  endpoint only returns answers newer than `expires_at`.

## Test isolation

The test suite boots isolated instances: `conftest.py` pins
`ENVIRONMENT=test`, points `DATABASE_URL` at a temp SQLite file (or in-memory
style) and `STORAGE_ROOT` at a temp directory, so tests never touch a
development or production database. See
[../project-report/testing.md](../project-report/testing.md).