#!/bin/bash
# =============================================================================
# JZap — Full Stack Setup Script
# One-command setup: generates certificates, builds images, starts services.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

echo "=============================================="
echo "  JZap — Full Stack Setup"
echo "=============================================="
echo ""

# ---------------------------------------------------------------------------
# Step 1: Check prerequisites
# ---------------------------------------------------------------------------
log_info "Checking prerequisites..."

MISSING=0

if ! command -v docker &>/dev/null; then
    log_error "docker is not installed or not in PATH"
    MISSING=1
fi

if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null 2>&1; then
    log_error "docker-compose is not installed or not in PATH"
    MISSING=1
fi

if ! command -v openssl &>/dev/null; then
    log_error "openssl is not installed or not in PATH"
    MISSING=1
fi

if [ "$MISSING" -ne 0 ]; then
    log_error "Missing prerequisites. Please install the above tools and try again."
    exit 1
fi

log_ok "All prerequisites found"

# ---------------------------------------------------------------------------
# Step 2: Environment configuration
# ---------------------------------------------------------------------------
log_info "Setting up environment configuration..."

if [ ! -f "${PROJECT_ROOT}/.env" ]; then
    if [ -f "${PROJECT_ROOT}/.env.example" ]; then
        cp "${PROJECT_ROOT}/.env.example" "${PROJECT_ROOT}/.env"
        log_ok "Copied .env.example to .env"
        log_warn "Review ${PROJECT_ROOT}/.env and update secrets before production use"
    else
        log_warn "No .env.example found — skipping .env creation"
    fi
else
    log_ok ".env already exists"
fi

# ---------------------------------------------------------------------------
# Step 3: Generate mTLS certificates
# ---------------------------------------------------------------------------
log_info "Generating mTLS certificates..."

CERTS_DIR="${PROJECT_ROOT}/certs"

# Generate CA (if not already present)
if [ ! -f "${CERTS_DIR}/ca/ca.pem" ]; then
    log_info "Generating root CA..."
    bash "${CERTS_DIR}/generate-ca.sh"
    log_ok "Root CA generated"
else
    log_ok "Root CA already exists — skipping"
fi

# Generate service certificates
for service in proxy agent control-plane; do
    CERT_FILE="${CERTS_DIR}/${service}/${service}.pem"
    if [ ! -f "${CERT_FILE}" ]; then
        log_info "Generating ${service} certificate..."
        bash "${CERTS_DIR}/generate-${service}-cert.sh"
        log_ok "${service} certificate generated"
    else
        log_ok "${service} certificate already exists — skipping"
    fi
done

# ---------------------------------------------------------------------------
# Step 4: Build Docker images
# ---------------------------------------------------------------------------
log_info "Building Docker images..."

cd "${PROJECT_ROOT}"

if docker compose version &>/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
else
    COMPOSE_CMD="docker-compose"
fi

${COMPOSE_CMD} build
log_ok "Docker images built"

# ---------------------------------------------------------------------------
# Step 5: Start services
# ---------------------------------------------------------------------------
log_info "Starting services..."

${COMPOSE_CMD} up -d
log_ok "Services started"

# ---------------------------------------------------------------------------
# Step 6: Wait for health checks
# ---------------------------------------------------------------------------
log_info "Waiting for services to become healthy..."

MAX_WAIT=60
ELAPSED=0
INTERVAL=5

while [ $ELAPSED -lt $MAX_WAIT ]; do
    UNHEALTHY=$(${COMPOSE_CMD} ps --format json 2>/dev/null | grep -c '"unhealthy"' || true)
    STARTING=$(${COMPOSE_CMD} ps --format json 2>/dev/null | grep -c '"starting"' || true)

    if [ "$UNHEALTHY" -eq 0 ] && [ "$STARTING" -eq 0 ]; then
        break
    fi

    sleep $INTERVAL
    ELAPSED=$((ELAPSED + INTERVAL))
    log_info "Waiting... (${ELAPSED}s / ${MAX_WAIT}s)"
done

if [ $ELAPSED -ge $MAX_WAIT ]; then
    log_warn "Some services may not be healthy yet. Check with: ${COMPOSE_CMD} ps"
fi

# ---------------------------------------------------------------------------
# Step 7: Print status
# ---------------------------------------------------------------------------
echo ""
echo "=============================================="
echo "  JZap — Setup Complete"
echo "=============================================="
echo ""

${COMPOSE_CMD} ps

echo ""
log_ok "Access URLs:"
echo "  Control Plane API:  http://localhost:8000"
echo "  Control Plane Docs: http://localhost:8000/docs"
echo "  Grafana Dashboard:  http://localhost:3000  (admin/admin)"
echo "  Prometheus:         http://localhost:9090"
echo "  Proxy (HTTPS):      https://localhost:8443"
echo ""
log_info "Run '${COMPOSE_CMD} logs -f' to follow service logs."
log_info "Run 'bash scripts/health-check.sh' to verify all services."
