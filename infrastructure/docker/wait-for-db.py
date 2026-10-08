#!/usr/bin/env python3
"""TCP readiness probe for the database named by ``DATABASE_URL``.

The CyberShield API image intentionally ships no PostgreSQL client tools and
may not have ``nc``, so this probe uses only the Python standard library:
parse ``DATABASE_URL`` (including the ``+asyncpg`` driver suffix) and attempt a
TCP connect to the host/port in a loop.

This checks *connectivity only*. ``alembic upgrade head`` then performs the
real handshake; if the cluster is still initialising it will fail loudly and
the container restarts (``restart: unless-stopped`` in compose).

Exit codes: 0 = database reachable (or nothing to wait for),
             1 = gave up after ``--timeout`` seconds.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import time
from urllib.parse import urlsplit


def parse_db_host_and_port(url: str) -> tuple[str | None, int | None]:
    parts = urlsplit(url)
    return parts.hostname, parts.port


def parse_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.environ.get("DATABASE_URL", ""))
    parser.add_argument(
        "--timeout",
        type=float,
        default=parse_int_env("DB_WAIT_TIMEOUT", 90),
        help="total seconds to keep probing before giving up",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=parse_int_env("DB_WAIT_INTERVAL", 2),
        help="seconds between probes",
    )
    parser.add_argument("--host", help="override host parsed from DATABASE_URL")
    parser.add_argument("--port", type=int, help="override port parsed from DATABASE_URL")
    args = parser.parse_args()

    url = (args.url or "").strip()
    if not url:
        print("wait-for-db: DATABASE_URL is not set; nothing to wait for", file=sys.stderr)
        return 0

    # SQLite is only used for local development/tests outside containers.
    if url.startswith("sqlite"):
        print("wait-for-db: SQLite URL detected; nothing to wait for", file=sys.stderr)
        return 0

    if url.startswith("postgresql+asyncpg://"):
        host, port = parse_db_host_and_port(url)
        if host is None:
            print(f"wait-for-db: could not parse host from URL: {url}", file=sys.stderr)
            return 1
    else:
        # Unknown scheme: fall back to env-provided host/port so the probe never
        # silently skips a non-standard deployment.
        host = args.host or os.environ.get("POSTGRES_HOST")
        port = args.port or parse_int_env("POSTGRES_PORT", 5432)
        if host is None:
            print(
                f"wait-for-db: unsupported scheme and no POSTGRES_HOST fallback: {url}",
                file=sys.stderr,
            )
            return 1

    host = args.host or host
    port = args.port or port

    deadline = time.monotonic() + args.timeout
    while True:
        try:
            with socket.create_connection((host, port), timeout=args.interval):
                print(f"wait-for-db: {host}:{port} is accepting connections")
                return 0
        except OSError as exc:
            if time.monotonic() >= deadline:
                print(
                    f"wait-for-db: timed out after {args.timeout}s waiting for "
                    f"{host}:{port}: {exc}",
                    file=sys.stderr,
                )
                return 1
            print(
                f"wait-for-db: {host}:{port} not ready ({exc}); "
                f"retrying in {args.interval}s",
                file=sys.stderr,
            )
            time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())