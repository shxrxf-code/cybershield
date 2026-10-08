"""Async engine, session factory and the request-scoped session dependency."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.core.config import Settings, get_settings
from app.models.base import Base

logger = logging.getLogger(__name__)

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def _engine_kwargs(settings: Settings) -> dict[str, object]:
    """Pool and echo configuration appropriate to the backing database."""
    is_sqlite = settings.database_url.startswith("sqlite")
    kwargs: dict[str, object] = {
        "echo": settings.debug,
        "future": True,
    }
    if is_sqlite:
        # SQLite has no meaningful connection pool, and sharing a single
        # in-process connection across concurrent tasks breaks under load.
        # NullPool plus a busy timeout is the safe combination for tests/dev.
        kwargs["poolclass"] = NullPool
        kwargs["connect_args"] = {"timeout": 30}
    else:
        kwargs["pool_size"] = settings.database_pool_size
        kwargs["max_overflow"] = settings.database_max_overflow
        kwargs["pool_pre_ping"] = True
        kwargs["pool_recycle"] = 1800
    return kwargs


def create_engine(settings: Settings | None = None) -> AsyncEngine:
    """Build a new async engine. Prefer :func:`get_engine` in application code."""
    resolved = settings or get_settings()
    return create_async_engine(resolved.database_url, **_engine_kwargs(resolved))


def get_engine(settings: Settings | None = None) -> AsyncEngine:
    """Return the process-wide engine, creating it on first use."""
    global _engine
    if _engine is None:
        resolved = settings or get_settings()
        _engine = create_engine(resolved)
        logger.info(
            "Database engine created",
            extra={"dialect": _engine.dialect.name, "echo": bool(resolved.debug)},
        )
    return _engine


def get_sessionmaker(settings: Settings | None = None) -> async_sessionmaker[AsyncSession]:
    """Return the process-wide session factory, creating it on first use."""
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(
            bind=get_engine(settings),
            expire_on_commit=False,
            autoflush=False,
            class_=AsyncSession,
        )
    return _sessionmaker


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a session with commit/rollback handling.

    The session is closed on the way out whether or not the handler raised, so a
    failed request cannot leak a connection.
    """
    factory = get_sessionmaker()
    session = factory()
    try:
        yield session
        # The route owns its transaction. Autocommit here would make it
        # impossible for a handler to roll back, so commit explicitly instead.
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Context-managed session for background workers and scripts."""
    factory = get_sessionmaker()
    session = factory()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def init_models(settings: Settings | None = None) -> None:
    """Create tables directly from metadata.

    Intended for tests and first-run SQLite development. Production deployments
    use Alembic so that schema changes are reviewable and reversible.
    """
    engine = get_engine(settings)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)


async def dispose_engine() -> None:
    """Close pooled connections. Called on application shutdown."""
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None


__all__ = [
    "create_engine",
    "dispose_engine",
    "get_db",
    "get_engine",
    "get_sessionmaker",
    "init_models",
    "session_scope",
]