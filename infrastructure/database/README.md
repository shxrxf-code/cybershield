# CyberShield PostgreSQL — migrations, backups, recovery

The backing store is PostgreSQL >= 14 (compose runs `postgres:16-alpine`).
This file covers schema management with Alembic, backups with `pg_dump`, and
point-in-time recovery.

## Why `alembic upgrade head` must run before the app starts

CyberShield has two schema paths (see `backend/app/main.py`,
`_maybe_init_models`):

| Environment | Schema owner |
|---|---|
| SQLite **development/test** | `Base.metadata.create_all` at boot (`init_models`) |
| Everything else (all PostgreSQL) | **Alembic only** |

Production boot **never** mutates the database. If a fresh PostgreSQL volume is
mounted and the API starts without a migration, requests that touch
`users`, `scans`, `quarantine_items`, ... fail with `relation does not exist`
and the health probe's database check fails. The container entrypoint
(`infrastructure/docker/entrypoint.sh`) therefore blocks until the DB accepts
connections and runs `alembic upgrade head` *before* exec'ing uvicorn. The same
entrypoint guards the optional `worker` service.

The Alembic URL is read from the application's `DATABASE_URL` environment
variable, not from `alembic.ini` — `backend/alembic/env.py` builds an async
engine from `get_settings().database_url`, so migrations always target the same
database the API serves.

## Migration workflow

### Authoring a revision (on the host, against source)

`backend/alembic.ini` uses `prepend_sys_path = .`, so run alembic from the
`backend` directory. The repo's virtualenv is at the repository root (`.venv`).

```bash
cd backend
../.venv/bin/python -m alembic revision --autogenerate -m "describe the change"
```

Review the generated file in `backend/alembic/versions/` — autogenerate is a
draft, not a verdict. Confirm it matches the intent (indexes, defaults, data
backfills) before committing. Always keep `downgrade()` implemented so a bad
release can be rolled back cleanly.

### Applying on a deployment

Migrations run automatically at container start, and are idempotent
(`alembic_version` stamps the current head). To apply manually or ahead of a
deploy:

```bash
cd infrastructure
docker compose run --rm api alembic upgrade head
```

or inside a running container:

```bash
docker compose exec api alembic upgrade head
```

### Rolling back a release

```bash
docker compose exec api alembic downgrade -1
```

See the rollback notes in [`../README.md`](../README.md#migration-rollback).
`downgrade()` in the initial schema (`a91c98690983_initial_schema.py`) drops
every table in dependency order; future revisions must provide their own.

## Backups

The DB container does not publish a port by default — run `pg_dump` inside the
container and copy the file out.

### Logical backup (pg_dump)

```bash
cd infrastructure

# custom format — compression + selective restore; the recommended one
docker compose exec db pg_dump -U cybershield -d cybershield -Fc -f /tmp/cybershield.dump
docker compose cp db:/tmp/cybershield.dump ./backups/cybershield-$(date +%F).dump

# plain SQL — greppable, easy to review; larger
docker compose exec -T db pg_dump -U cybershield -d cybershield > ./backups/cybershield-$(date +%F).sql
```

Restore to a scratch database (or after dropping the old one):

```bash
docker compose exec -T db pg_restore -U cybershield -d cybershield --clean --if-exists \
  < ./backups/cybershield-2026-10-06.dump
```

Automate with a cron entry on the host:

```cron
15 2 * * * cd /opt/cybershield/infrastructure && docker compose exec -T db \
  pg_dump -U cybershield -d cybershield -Fc | gzip > backups/cybershield-$(date +\%F).dump.gz
```

Rotate at least the last 14 days and copy backups off the host (object store,
another server).

### Point-in-time recovery (WAL archiving)

Logical dumps capture a single instant. For recovery to arbitrary points you
need continuous WAL archiving. These settings are off by default; apply them as
the `postgres` superuser and restart:

```sql
ALTER SYSTEM SET wal_level = 'replica';        -- default in PG16; keep explicit
ALTER SYSTEM SET archive_mode = 'on';
ALTER SYSTEM SET archive_command = 'cp %p /backups/db/wal/%f';  -- local dir, or an object-store client
ALTER SYSTEM SET archive_timeout = '300s';     -- at least one segment every 5 min
```

(`/backups/db/wal` must live on a persistent volume mounted into the `db`
service — add a bind mount or volume in `docker-compose.yml`.)

Recovery drill:

1. Base backup:
   ```bash
   docker compose exec -T db pg_basebackup -h 127.0.0.1 -U cybershield -D /tmp/base -Fp -P
   ```
2. Bring up a disposable PostgreSQL container on the copied `base` directory,
   create `recovery.signal` (PG12+), and set `restore_command` to replay the
   archived WAL:
   ```conf
   restore_command = 'cp /backups/db/wal/%f %p'
   recovery_target_time = '2026-10-06 09:30:00 UTC'
   recovery_target_action = 'promote'
   ```
3. Start, let it replay to the target time, promote, dump the recovering data
   out, and restore it into the production database.

Sandbox the whole sequence once before you need it in anger.

## Backend / container notes

- The container image carries `backend/alembic/` (env.py, script.py.mako,
  versions/`a91c98690983_initial_schema.py`), so `alembic upgrade head` in the
  entrypoint is always runnable.
- `DATABASE_URL` for Compose:
  `postgresql+asyncpg://cybershield:<password>@db:5432/cybershield`.
  If `POSTGRES_PASSWORD` ever contains characters reserved in a URL (`@ : /`),
  percent-encode them. The generated secrets are `token_urlsafe`, i.e. safe.
- Pool settings (`DATABASE_POOL_SIZE`=10, `DATABASE_MAX_OVERFLOW`=20 in
  `backend/.env.example`) are per-container; scale them with `docker compose
  scale api=N` mindfully.
- The `db` container should stay unexposed on the network (`ports:` is
  commented out). Localhost-only publishing is acceptable for `pg_dump` from
  the host.
- Consider `POSTGRES_INITDB_ARGS: "--locale=C.UTF-8 --encoding=UTF8"` on the
  `db` service for fully deterministic collation across hosts.