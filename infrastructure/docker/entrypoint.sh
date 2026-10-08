#!/usr/bin/env bash
#
# CyberShield container entrypoint.
#
#   1. Wait until the PostgreSQL server named by DATABASE_URL accepts TCP
#      connections (stdlib-only probe — the image has no pg_isready/psql/nc).
#   2. Apply schema migrations with `alembic upgrade head`. This is mandatory:
#      production boot NEVER auto-creates tables (see app/main.py,
#      `_maybe_init_models` only targets SQLite dev/test), so the migration is
#      the only path that builds the schema.
#   3. exec the command from the image CMD / docker-compose `command:` override
#      (uvicorn for `api`; `python -m app.workers.queue` for the optional
#      Redis `worker` service).

set -euo pipefail

log() { printf '[%s] entrypoint: %s\n' "$(date -u +%FT%TZ)" "$*"; }

: "${DB_WAIT_TIMEOUT:=90}"    # seconds to keep probing the DB port
: "${DB_WAIT_INTERVAL:=2}"    # seconds between probes

log "waiting for PostgreSQL (max ${DB_WAIT_TIMEOUT}s)..."
python /srv/cybershield/docker/wait-for-db.py \
    --timeout "$DB_WAIT_TIMEOUT" \
    --interval "$DB_WAIT_INTERVAL"

log "applying database migrations (alembic upgrade head)"
alembic upgrade head

log "starting: $*"
exec "$@"