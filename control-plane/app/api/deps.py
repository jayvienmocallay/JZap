"""Shared FastAPI dependency-injection helpers."""

from __future__ import annotations

from typing import AsyncGenerator

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.db.session import async_session_factory
from app.models.tenant import Tenant
from app.services.security import hash_api_key


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
    db: AsyncSession = Depends(get_db),
) -> str:
    """Validate the incoming API key.

    The configured `secret_key` remains an admin bootstrap key. Tenant API
    keys are stored hashed and scoped in later phases.
    """
    if x_api_key == settings.secret_key:
        return "bootstrap"

    api_key_hash = hash_api_key(x_api_key)
    result = await db.execute(
        select(Tenant.id).where(
            Tenant.api_key_hash == api_key_hash,
            Tenant.enabled.is_(True),
        )
    )
    if result.scalar_one_or_none() is not None:
        return "tenant"

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid or missing API key",
    )
