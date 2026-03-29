# =============================================================================
# JZap Control Plane — FastAPI Application
# =============================================================================
# Multi-stage build for the central control plane API that orchestrates
# proxy nodes, agents, and DNS modules.
# -----------------------------------------------------------------------------

# --------------- Stage 1: Builder -------------------------------------------
FROM python:3.12-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# --------------- Stage 2: Runtime -------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

LABEL maintainer="JZap Team"
LABEL description="FastAPI control plane for JZap orchestration"

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy application code
COPY app/ /app/app/

# Copy Alembic config for database migrations
COPY alembic.ini /app/alembic.ini

# Run as non-root
RUN useradd --no-create-home --shell /bin/false appuser
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
