# CyberShield — containerisation & deployment infrastructure

Everything needed to run the CyberShield FastAPI + SQLAlchemy backend as a
self-hosted Docker stack: image, orchestration, PostgreSQL/Redis, reverse proxy,
and the operational playbook.

> **Nothing here builds or runs in this environment by itself** — you need a
> machine with Docker Engine + Compose v2. All files are *produced* here and
> consumed wherever you deploy.

---

## 1. Architecture

```
                  internet / LAN
                        │
                        ▼
              ┌──────────────────┐     80/443 HTTP(S)
              │  nginx           │  nginx.conf (profile: proxy)
              │  TLS, gzip,      │  client_max_body_size 110m
              │  security headers│  X-Forwarded-For/X-Request-ID
              └────────┬─────────┘
                       │  docker network "cybershield_default"
                       ▼
              ┌──────────────────┐   ┌──────────────────┐
              │  api             │──▶│  redis:7           │  rate limiting (future
              │  uvicorn :8000   │   │  (+appendonly)    │   durable queue)
              │  in-process scan │   └──────────────────┘
              │  queue           │
              └───┬───────┬──────┘
                  │       │
          storage │       │ DATABASE_URL (asyncpg)
          /data   │       ▼
          (volume)│   ┌──────────────────┐
                  │   │  db: postgres:16 │  pgdata volume
                  └──▶└──────────────────┘
                       ┌──────────────────┐
                       │  clamav (profile:│  clamd on :3310, optional
                       │  scanner)        │
                       └──────────────────┘
```

| Service | Image | Profiles | Purpose |
|---|---|---|---|
| `db` | `postgres:16-alpine` | always | Schema owned by Alembic; `pgdata` volume |
| `redis` | `redis:7-alpine` | always | Redis rate-limiter backend; `redisdata` volume |
| `api` | `cybershield-api:local` (built) | always | FastAPI on `0.0.0.0:8000`; `cybershield-data:/data` |
| `worker` | same image | `worker` | **Not yet operational** — see §5 |
| `clamav` | `clamav/clamav:stable` | `scanner` | clamd for signature scanning; `clamav-db` volume |
| `nginx` | `nginx:1.27-alpine` | `proxy` | Reverse proxy + TLS termination |

### Repository layout

```
infrastructure/
├── docker-compose.yml      # the stack definition
├── .env.example            # secrets template (copy → .env)
├── README.md               # this file
├── docker/
│   ├── Dockerfile          # multi-stage python:3.14-slim, non-root
│   ├── entrypoint.sh       # wait-for-db → alembic upgrade head → exec cmd
│   └── wait-for-db.py      # stdlib TCP probe (no pg_isready/nc needed)
├── database/
│   └── README.md           # migrations, pg_dump backups, PITR
└── nginx/
    ├── nginx.conf          # proxy + TLS-ready config
    └── README.md           # TLS/certbot runbook
```

## 2. Quick start

Prerequisites: Docker Engine ≥ 24, Compose v2 (`docker compose`).

```bash
# 1. Generate secrets (POSTGRES_PASSWORD, SECRET_KEY, QUARANTINE_ENCRYPTION_KEY)
scripts/generate-secrets.sh

# 2. Create the compose environment
cp infrastructure/.env.example infrastructure/.env   # paste the generated values
#    optionally set CORS_ORIGINS / ENVIRONMENT

# 3. Build and start everything, including optional services
cd infrastructure
docker compose --profile proxy --profile scanner up -d --build

# 4. Verify
curl http://127.0.0.1/api/v1/health      # status "ok" when clamav is up
curl http://127.0.0.1/                   # service banner
```

Minimum profile (`docker compose up -d --build`) runs `db`, `redis`, `api`
only — fine for development behind your own tooling. The health endpoint will
report `degraded` because no ClamAV is reachable (see §4).

## 3. Configuration & secrets

Secrets are **env-only**. Nothing is written into the image; compose injects
them at runtime. Required variables come from `infrastructure/.env`
(auto-loaded by Compose) or the process environment:

| Variable | Required | Notes |
|---|---|---|
| `POSTGRES_PASSWORD` | yes | `db` user password + embedded in `DATABASE_URL` |
| `SECRET_KEY` | yes | Token signing secret. **Never** let the app generate one per process — production boot refuses it (`app/core/config.py`) because tokens would invalidate on every restart. |
| `QUARANTINE_ENCRYPTION_KEY` | yes | 64 hex chars (32 bytes). AES-256-GCM at rest for quarantined blobs. **Never rotate** — stored quarantined samples become unreadable. |
| `ENVIRONMENT` | no | default `production` |
| `CORS_ORIGINS` | no | comma-separated; default `http://localhost:3000` |

Every other runtime setting follows `backend/.env.example` defaults; add any of
them to the `api` service's `environment:` block to override (`RATE_LIMIT_*`,
`MAX_UPLOAD_BYTES`, `DOCS_ENABLED`, `LOG_LEVEL`, ...).

Generate keys yourself when you prefer the one-liners:

```bash
python - <<'PY'
import secrets
print("SECRET_KEY              =", secrets.token_urlsafe(64))
print("POSTGRES_PASSWORD        =", secrets.token_urlsafe(32))
print("QUARANTINE_ENCRYPTION_KEY=", secrets.token_hex(32))
PY
```

## 4. Health, storage, scanning model

- **Health probe:** `GET /api/v1/health`. The app refuses to fake a healthy
  status: `ok` requires database reachable **and** the scan queue running **and**
  every scanner available (YARA compiled rules + reachable ClamAV). Without
  ClamAV (`--profile scanner`) you get `degraded`, not `ok` — that is intended,
  not a bug.
- **Storage:** scan uploads, quarantined (encrypted) blobs and temp files live
  under `STORAGE_ROOT=/data`, persisted by the `cybershield-data` volume.
  Back it up with the database: it is evidence. Quarantine retention is
  `QUARANTINE_RETENTION_DAYS` (default 14); blobs are AES-256-GCM envelopes
  (`CBSQ1` magic) tied to `QUARANTINE_ENCRYPTION_KEY`.
- **Scan queue:** `app/workers/queue.py` runs an **in-process** asyncio worker
  started by `create_app()` at boot. Jobs are lost on restart; structured scans
  are re-submittable, and the app treats that as acceptable.
- **Redis:** the only Redis-backed feature today is the rate limiter. Setting
  `USE_REDIS_QUEUE=true` switches rate-limit counters to a shared Redis store
  (so limits are global rather than per process); it does **not** provide a
  distributed scan queue. The scan worker still starts in-process.

## 5. The `worker` service and `USE_REDIS_QUEUE` (read this)

`docker-compose.yml` scaffolds a `worker` service behind the `worker` profile.
**Do not enable it yet.** The backend's `queue.py` implements only the
in-process queue — there is no Redis consumer and no `__main__` entrypoint, so
`python -m app.workers.queue` currently exits without consuming anything.
`USE_REDIS_QUEUE` controls only the rate limiter's Redis store; the API always
starts its in-process scan worker, so scans never silently stall.

- The default topology (single `api` container) is the correct one.
- When the upstream Redis consumer lands, enable `worker` by running
  `docker compose --profile worker up -d` and wiring the queue to it.
- Scale-out today: run readonly replicas of the whole `api` service without the
  Redis flag, remembering rate-limit counters are per-process in that mode.

Replica guidance: `uvicorn --workers 1` (the image default) because the scan
queue is tied to the process event loop. Scale by adding containers.

## 6. Image size / feature-parity trade-off

The image installs **all three** requirement sets to match the app's feature
surface (`yara-python`, `python-magic`, `scikit-learn`, `joblib`, `numpy`).
This is the size-heavy option. The app degrades gracefully without the extras
(`app/main.py` and the scanners report themselves unavailable; verdicts remain
computable), so you can shrink the image per deployment:

```bash
docker compose build --build-arg INSTALL_SCAN=false --build-arg INSTALL_ML=false api
```

| Args | Effect |
|---|---|
| `INSTALL_SCAN=false` | drops YARA engine + libmagic bindings → no signature scanning |
| `INSTALL_ML=false` | drops scikit-learn → model signal removed from the risk engine |

`requirements.txt` (framework, db, security) is always installed; `cryptography`
is non-optional in practice because quarantine fails closed to plaintext when
the key is set (see `app/services/quarantine.py`).

## 7. Operations runbook

### Health

```bash
curl -s http://127.0.0.1/api/v1/health | python3 -m json.tool
docker compose ps            # healthy/unhealthy per service
docker compose events        # stream container lifecycle events
```

A `degraded` status is explained by the `checks` object (`database`, `worker`,
`rate_limiter`, `scanners`). The most common cause is no ClamAV host.

### Logs

```bash
docker compose logs -f api       # uvicorn + structured JSON logs
docker compose logs -f db redis nginx clamav
docker compose logs api | grep '"scan_id"'   # correlate scan jobs
```

Log correlation: the API echoes `X-Request-ID` (set by nginx `$request_id`);
it lands in `X-Request-ID` response headers, audit rows, and scan job logs.

### Restart / upgrade

```bash
# clean restart of the API only (in-flight in-process queue jobs are lost)
docker compose restart api

# rebuild + recreate after a backend change
docker compose up -d --build --remove-orphans
alembic upgrade head runs automatically inside the container on boot
```

### Migration rollback

```bash
docker compose exec api alembic downgrade -1     # one revision
docker compose exec api alembic downgrade a91c98690983   # all the way to base
```

Rules: a `downgrade()` in every revision; migrations are run one-at-a-time
(a single `upgrade head` is already nonlinear-safe via the stamp). Never
`downgrade` past a release boundary while queries are being written against the
new schema — coordinate with the client/app rollout. Data changed or dropped by
the migration is not restored by `downgrade`; recover from backups if needed.
See [`database/README.md`](database/README.md) for backup/restore.

### Backup

See [`database/README.md`](database/README.md): `pg_dump -Fc` daily + copy off
the host, and PITR via WAL archiving if you need surgical recovery. Treat the
`cybershield-data` volume (uploads + encrypted quarantine) as equally
critical — `docker run --rm -v cybershield_cybershield-data:/data -v "$PWD":/backup alpine tar czf /backup/data.tgz /data`.

## 8. Security hardening checklist

**The stack**

- [ ] Secrets live only in `infrastructure/.env`; never commit it.
- [ ] `POSTGRES_PASSWORD`, `SECRET_KEY`, `QUARANTINE_ENCRYPTION_KEY` are
      strong, per-environment, and generated via `scripts/generate-secrets.sh`.
- [ ] `QUARANTINE_ENCRYPTION_KEY` never rotated (documented procedure for
      rotation: decrypt-and-reencrypt blobs on a maintenance window, or accept
      orphaned quarantine archives).
- [ ] API runs as non-root (Dockerfile `USER app`, UID 1000).
- [ ] `TRUST_PROXY_HEADERS=true` **only** because nginx overwrites the
      headers. Never enable on a directly-exposed host.
- [ ] `DEBUG=false`, `ENVIRONMENT=production` (both enforced by the app's
      production validator).

**Network / API**

- [ ] Do **not** publish `db` (5432) to the host. The commented `ports:` is
      localhost-only for pg_dump.
- [ ] `api` publishes only `127.0.0.1:8000` (debug); delete it in production so
      all traffic enters through nginx.
- [ ] nginx TLS: modern ciphers, HTTP→HTTPS redirect, HSTS once live
      (commented block in `nginx.conf`), certbot renewal automated.
- [ ] Firewall: allow 80/443 from the internet; 22 only from admin nets; deny
      8000/5432/6379/3310 externally.
- [ ] PostgreSQL authentication is password-based (`md5`/`scram-sha-256`).
      Consider `POSTGRES_HOST_AUTH_METHOD=scram-sha-256` on fresh clusters.
- [ ] Keep ClamAV signatures fresh — the image's `freshclam` does this; the
      `clamav-db` volume must persist.

**General**

- [ ] Keep images updated (`docker compose pull`, rebuild with `--no-cache` on
      security releases of `python`, `postgres`, `redis`, `nginx`).
- [ ] `client_max_body_size 110m` matches `MAX_UPLOAD_BYTES` (100 MiB).
- [ ] Audit logs are in PostgreSQL (`audit_events`); back up with the DB.
- [ ] Enable `LOG_LEVEL=INFO` and keep `LOG_JSON=true` for machine-parsable logs.

## 9. Assumptions & deviations from upstream

- **Python 3.14 slim** base per the requirement; `requirements.txt` documents
  3.12–3.14 support.
- **`worker` service is a scaffold**, not a working consumer (see §5). Default
  `USE_REDIS_QUEUE=false` everywhere.
- **ClamAV** is an optional profile-provided `clamd`; without it health is
  `degraded` by design.
- **YARA rules** are the built-in ones under `detection-engine/yara/rules`,
  baked into the image. Mount your own rules read-only over
  `/srv/cybershield/detection-engine/yara/rules` or point `YARA_RULES_DIR` at a
  volume to ship live rules.
- **nginx upstream name** (`api`) matches the compose service; changing the
  service name requires changing `nginx.conf`.
- **Alembic runs from `backend/`** (`prepend_sys_path = .`), so any manual
  `alembic` invocation must use the container WORKDIR or the host `backend/` dir.