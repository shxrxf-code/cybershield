"""Alembic environment: async engine, settings-driven URL, full model registry.

Migrations target the same database the application reads from (``DATABASE_URL``
via :func:`app.core.config.get_settings`). The models package is imported for
its side effect: every table is registered on ``Base.metadata`` before Alembic
computes a diff, which is what makes ``--autogenerate`` correct.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from app.core.config import get_settings
from app.models import Base  # noqa: F401 - registers all tables on metadata

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Take the URL from settings when alembic.ini does not provide one (the normal
# case), so migrations track the configured environment.
database_url = (config.get_main_option("sqlalchemy.url") or "").strip()
if not database_url or database_url.startswith("driver://"):
    database_url = get_settings().database_url
config.set_main_option("sqlalchemy.url", database_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode, emitting SQL without a live DB."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()