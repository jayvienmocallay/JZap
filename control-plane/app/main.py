"""JZap Control Plane — FastAPI application entry-point."""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import get_settings
from app.db.session import init_db, dispose_engine

# ── Route imports ───────────────────────────────────────────────────────
from app.api.routes.health import router as health_router
from app.api.routes.rules import router as rules_router
from app.api.routes.tenants import router as tenants_router
from app.api.routes.blocklist import router as blocklist_router


# ── Lifespan ────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle hook."""
    settings = get_settings()

    # Startup: initialise database connection pool & Redis
    await init_db()

    # Store a Redis connection on app state for convenience
    import redis.asyncio as aioredis

    app.state.redis = aioredis.from_url(
        settings.redis_url, decode_responses=True
    )

    yield

    # Shutdown: close connections
    await app.state.redis.aclose()
    await dispose_engine()


# ── App factory ─────────────────────────────────────────────────────────
app = FastAPI(
    title="JZap Control Plane",
    version="0.1.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)


# ── Middleware ──────────────────────────────────────────────────────────
settings = get_settings()

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Inject a unique X-Request-ID header into every request/response."""

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


app.add_middleware(RequestIDMiddleware)


# ── Routers ─────────────────────────────────────────────────────────────
app.include_router(health_router, prefix="/api/v1")
app.include_router(rules_router, prefix="/api/v1")
app.include_router(tenants_router, prefix="/api/v1")
app.include_router(blocklist_router, prefix="/api/v1")
