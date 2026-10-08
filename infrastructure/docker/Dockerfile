# syntax=docker/dockerfile:1

# =============================================================================
# CyberShield backend — production image
# =============================================================================
# Multi-stage build:
#
#   builder  python:3.14-slim + build toolchain -> installs every requirement
#            set into an isolated virtualenv at /opt/venv.
#   runtime  python:3.14-slim + libmagic (for python-magic) -> carries the venv,
#            the application package, the Alembic tree, and the built-in YARA
#            rules. The API runs as an unprivileged user (UID 1000).
#
# Build args (feature parity is the default; see infrastructure/README.md for
# the size trade-off):
#   INSTALL_SCAN=true   requirements-scan.txt  (yara-python, python-magic)
#   INSTALL_ML=true     requirements-ml.txt    (scikit-learn, joblib, numpy)
#
# Startup contract: the entrypoint waits for PostgreSQL, applies migrations
# with `alembic upgrade head` (production schema ownership is 100% Alembic —
# app/main.py only auto-creates tables for SQLite dev/test), then execs the
# service command. See docker/entrypoint.sh.
# =============================================================================

FROM python:3.14-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

# Compiler toolchain for the packages that may need to build from source on
# less common platforms (on x86_64/aarch64 the wheels are prebuilt).
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt \
     backend/requirements-scan.txt \
     backend/requirements-ml.txt \
     /tmp/cybershield-requirements/

RUN python -m venv /opt/venv

ARG INSTALL_SCAN=true
ARG INSTALL_ML=true
RUN /opt/venv/bin/pip install --no-cache-dir \
        -r /tmp/cybershield-requirements/requirements.txt \
 && if [ "${INSTALL_SCAN}" = "true" ]; then \
      /opt/venv/bin/pip install --no-cache-dir \
          -r /tmp/cybershield-requirements/requirements-scan.txt; \
    fi \
 && if [ "${INSTALL_ML}" = "true" ]; then \
      /opt/venv/bin/pip install --no-cache-dir \
          -r /tmp/cybershield-requirements/requirements-ml.txt; \
    fi

# ---- Runtime stage ----------------------------------------------------------

FROM python:3.14-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/opt/venv/bin:$PATH"

LABEL org.opencontainers.image.title="cybershield-api" \
      org.opencontainers.image.description="CyberShield static-analysis threat scanner backend (FastAPI + SQLAlchemy async)" \
      org.opencontainers.image.vendor="CyberShield"

# libmagic.so.1 is required at runtime by python-magic (requirements-scan.txt).
RUN apt-get update \
 && apt-get install -y --no-install-recommends libmagic1 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv

# Unprivileged application user — the API never runs as root.
RUN groupadd --system --gid 1000 app \
 && useradd --system --uid 1000 --gid app \
      --home-dir /srv/cybershield --shell /usr/sbin/nologin app

WORKDIR /srv/cybershield

# Application package + Alembic tree (schema lives in migrations; the full
# backend/alembic/ directory — env.py, script.py.mako, versions/ — is kept).
COPY backend/app ./backend/app
COPY backend/alembic ./backend/alembic
COPY backend/alembic.ini ./backend/alembic.ini

# Built-in YARA rule set. The app resolves its default rules dir to
# PROJECT_ROOT/detection-engine/yara/rules — exactly this path.
COPY detection-engine/yara/rules ./detection-engine/yara/rules

# Container orchestration support files.
COPY infrastructure/docker/entrypoint.sh ./docker/entrypoint.sh
COPY infrastructure/docker/wait-for-db.py ./docker/wait-for-db.py

# Storage root for uploads, quarantined blobs and temp files. docker-compose
# mounts a named volume here (cybershield-data:/data).
RUN mkdir -p /data \
 && chown -R app:app /srv/cybershield /data \
 && chmod 0755 /srv/cybershield/docker/entrypoint.sh

USER app

# The backend directory becomes CWD so that Alembic (`prepend_sys_path = .`
# in alembic.ini) and `uvicorn app.main:app` both resolve the `app` package.
WORKDIR /srv/cybershield/backend

EXPOSE 8000

# Liveness/re-readiness: the compose file overrides with its own healthcheck;
# this one makes standalone `docker run` behave sensibly too.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=4)"]

# --workers 1 is deliberate: the scan queue is an in-process asyncio worker
# (app/workers/queue.py), and the rate limiter falls back to per-process
# counters. Scale replica *containers* instead of worker threads.
ENTRYPOINT ["/srv/cybershield/docker/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "1", "--proxy-headers", "--forwarded-allow-ips", "*"]