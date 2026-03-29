"""Health-check endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_redis

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("")
async def health():
    """Basic liveness probe."""
    return {
        "status": "ok",
        "service": "jzap-control-plane",
        "version": "0.1.0",
    }


@router.get("/ready")
async def readiness(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Readiness probe — verifies DB and Redis connectivity."""
    checks: dict[str, str] = {}

    # Database
    try:
        await db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:
        checks["database"] = f"error: {exc}"

    # Redis
    try:
        redis = request.app.state.redis
        await redis.ping()
        checks["redis"] = "ok"
    except Exception as exc:
        checks["redis"] = f"error: {exc}"

    all_ok = all(v == "ok" for v in checks.values())
    status_code = 200 if all_ok else 503

    from fastapi.responses import JSONResponse

    return JSONResponse(
        content={
            "status": "ready" if all_ok else "degraded",
            "checks": checks,
        },
        status_code=status_code,
    )
