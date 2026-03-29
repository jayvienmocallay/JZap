"""Shared FastAPI dependency-injection helpers."""

from __future__ import annotations

from typing import AsyncGenerator

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.db.session import async_session_factory


# ── Database session ────────────────────────────────────────────────────
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async SQLAlchemy session, ensuring cleanup."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ── Redis client ────────────────────────────────────────────────────────
async def get_redis(request: Request):
    """Return the Redis client stored on app state."""
    return request.app.state.redis


# ── Settings (cacheable) ───────────────────────────────────────────────
def get_current_settings() -> Settings:
    """Return the cached Settings instance (Depends-compatible)."""
    return get_settings()


# ── API-key verification ───────────────────────────────────────────────
async def verify_api_key(
    x_api_key: str = Header(..., alias="X-API-Key"),
    settings: Settings = Depends(get_current_settings),
) -> str:
    """Validate the incoming API key.

    Currently accepts the raw secret_key for bootstrapping.
    TODO (Phase 6): look up hashed key per-tenant in the database.
    """
    if x_api_key != settings.secret_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key",
        )
    return x_api_key
