"""Async SQLAlchemy engine and session management."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings


class Base(DeclarativeBase):
    """Declarative base for all SQLAlchemy models."""

    pass


# ── Engine & session factory (lazily initialised) ───────────────────────

_engine = None
async_session_factory: async_sessionmaker[AsyncSession] = None  # type: ignore[assignment]


def _build_engine():
    """Create the async engine from current settings."""
    settings = get_settings()
    return create_async_engine(
        settings.database_url,
        echo=settings.debug,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
    )


async def init_db() -> None:
    """Initialise the engine, session factory, and (dev-only) create tables."""
    global _engine, async_session_factory

    _engine = _build_engine()
    async_session_factory = async_sessionmaker(
        bind=_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    # In development, create tables that don't exist yet.
    # Production should rely on Alembic migrations.
    settings = get_settings()
    if settings.debug:
        async with _engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)


async def dispose_engine() -> None:
    """Dispose of the engine's connection pool on shutdown."""
    global _engine
    if _engine is not None:
        await _engine.dispose()
        _engine = None


async def get_async_session():
    """Async generator yielding a session — usable as a FastAPI dependency."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
