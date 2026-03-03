import asyncio
import os
import urllib.parse
from logging.config import fileConfig

from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import pool

from alembic import context

# Alembic config object
config = context.config

# Set up logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import models so autogenerate can detect schema changes
from app.models import Base  # noqa: E402
target_metadata = Base.metadata


def _get_db_url() -> str:
    """Resolve DATABASE_URL from environment, applying the same normalisation
    that main.py uses (postgres:// → postgresql+asyncpg://, strip SSL params)."""
    url = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:////tmp/commission.db").strip()

    # Strip pgBouncer-incompatible SSL query params
    try:
        p = urllib.parse.urlsplit(url)
        qs = [
            (k, v)
            for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True)
            if k.lower() not in {"sslmode", "sslrootcert", "sslcert", "sslkey"}
        ]
        url = urllib.parse.urlunsplit(
            (p.scheme, p.netloc, p.path, urllib.parse.urlencode(qs), p.fragment)
        )
    except Exception:
        pass

    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgresql://") and "+asyncpg" not in url:
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)

    return url


def run_migrations_offline() -> None:
    """Run migrations without a live DB connection (generates SQL script)."""
    url = _get_db_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations with an async engine."""
    url = _get_db_url()
    connectable = create_async_engine(url, poolclass=pool.NullPool)

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
