"""Application factory and ASGI entrypoint.

Booting the app:

1. **Directories** are ensured (uploads, quarantine, temp).
2. **Schema initialisation** runs only for SQLite in development/test, where
   ``init_models`` reflects the ORM straight into the file database. Production
   schemas are managed by Alembic, so boot never mutates a managed database.
3. The **scan queue worker** is started on the same event loop so asynchronous
   scans progress without an external broker. When ``use_redis_queue`` is set,
   the worker is expected to run in a separate service; the API process in that
   mode only publishes jobs.
4. On shutdown the queue is stopped and the engine disposed so tests and the
   worker console exit cleanly.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.router import api_router
from app.core.config import Settings, get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import request_id_ctx
from app.schemas.common import DISCLAIMER


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a request id and copy recorded rate-limit headers out.

    The request id is used for correlation across scan jobs spawned from a
    request and is echoed back as ``X-Request-ID``. ``request.state.rate_headers``
    (set by ``app.api.deps.rate_limit``) is copied onto the response so clients
    can observe ``X-RateLimit-Limit``/``X-RateLimit-Remaining``.
    """

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        token = request_id_ctx.set(request_id)
        try:
            response = await call_next(request)
        finally:
            request_id_ctx.reset(token)
        response.headers.setdefault("X-Request-ID", request_id)
        rate_headers = getattr(request.state, "rate_headers", None)
        if rate_headers:
            for name, value in rate_headers.items():
                response.headers.setdefault(name, value)
        return response


async def _maybe_init_models(settings: Settings) -> None:
    """Create tables for SQLite development/test only; Alembic owns the rest."""
    if (
        settings.database_url.startswith("sqlite")
        and settings.environment in ("development", "test")
    ):
        from app.db.session import init_models

        await init_models(settings)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build an application instance bound to ``settings`` (or the env defaults).

    Tests pass a ``Settings`` with a temp database and upload root so they can
    boot isolated instances in the same process.
    """
    cfg = settings or get_settings()

    @asynccontextmanager
    async def _lifespan(app: FastAPI):
        cfg.ensure_directories()
        await _maybe_init_models(cfg)

        from app.workers.queue import get_scan_queue, shutdown_scan_queue

        if not cfg.use_redis_queue:
            get_scan_queue().start()

        yield

        await shutdown_scan_queue()
        from app.db.session import dispose_engine

        await dispose_engine()
        # Drop process-level singletons so a new ``create_app`` in the same
        # process rebuilds services against the new settings/database.
        from app.services.scan_service import set_scan_service

        set_scan_service(None)

    app = FastAPI(
        title=cfg.app_name,
        version=cfg.app_version,
        description=(
            "CyberShield static-analysis threat scanner. Reports carry a score, "
            "verdict, confidence, reasons, and an explicit disclaimer - nothing "
            "is claimed with certainty the evidence cannot support. "
            f"{DISCLAIMER}"
        ),
        docs_url="/docs" if cfg.docs_enabled else None,
        redoc_url="/redoc" if cfg.docs_enabled else None,
        lifespan=_lifespan,
    )

    register_exception_handlers(app)
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(cfg.cors_origins),
        allow_credentials=cfg.cors_allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(api_router, prefix="/api/v1")

    @app.get("/", include_in_schema=False)
    async def root() -> dict[str, object]:
        return {
            "service": cfg.app_name,
            "version": cfg.app_version,
            "environment": cfg.environment,
            "docs": "/docs" if cfg.docs_enabled else None,
            "health": "/api/v1/health",
        }

    return app


app = create_app()