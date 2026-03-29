#!/bin/bash
# =============================================================================
# JZap — Health Check Script
# Checks all JZap service endpoints and reports status.
# =============================================================================
set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS="${GREEN}OK${NC}"
FAIL="${RED}FAIL${NC}"
WARN="${YELLOW}WARN${NC}"

FAILURES=0

# Check a service endpoint via HTTP
check_http() {
    local name="$1"
    local url="$2"
    local expected_code="${3:-200}"
    local extra_args="${4:-}"

    printf "  %-30s " "${name}"

    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 ${extra_args} "${url}" 2>/dev/null || echo "000")

    if [ "$HTTP_CODE" = "$expected_code" ]; then
        echo -e "[${PASS}]  (HTTP ${HTTP_CODE})"
    elif [ "$HTTP_CODE" = "000" ]; then
        echo -e "[${FAIL}]  (Connection refused / timeout)"
        FAILURES=$((FAILURES + 1))
    else
        echo -e "[${WARN}]  (HTTP ${HTTP_CODE}, expected ${expected_code})"
        FAILURES=$((FAILURES + 1))
    fi
}

# Check a TCP port
check_tcp() {
    local name="$1"
    local host="$2"
    local port="$3"

    printf "  %-30s " "${name}"

    if timeout 5 bash -c "echo > /dev/tcp/${host}/${port}" 2>/dev/null; then
        echo -e "[${PASS}]  (port ${port} open)"
    else
        echo -e "[${FAIL}]  (port ${port} closed)"
        FAILURES=$((FAILURES + 1))
    fi
}

echo "=============================================="
echo "  JZap — Service Health Check"
echo "=============================================="
echo ""

# --- Control Plane ---
echo "Control Plane:"
check_http "API Health" "http://localhost:8000/health"
check_http "API Docs" "http://localhost:8000/docs"
check_http "Metrics" "http://localhost:8000/metrics"
echo ""

# --- Proxy ---
echo "Proxy:"
check_http "HTTPS Endpoint" "https://localhost:8443/health" "200" "--insecure"
check_http "Metrics" "https://localhost:8443/metrics" "200" "--insecure"
echo ""

# --- DNS Module ---
echo "DNS Module:"
check_tcp "DNS (UDP)" "localhost" "5353"
check_http "Metrics" "http://localhost:9092/metrics"
echo ""

# --- Host Agent ---
echo "Host Agent:"
check_http "Metrics" "http://localhost:9091/metrics"
echo ""

# --- Rust Sidecar ---
echo "Rust Sidecar:"
check_http "Metrics" "http://localhost:9090/metrics"
echo ""

# --- Redis ---
echo "Redis:"
check_tcp "Redis Port" "localhost" "6379"
echo ""

# --- PostgreSQL ---
echo "PostgreSQL:"
check_tcp "PostgreSQL Port" "localhost" "5432"
echo ""

# --- Monitoring ---
echo "Monitoring:"
check_http "Prometheus" "http://localhost:9090/-/ready"
check_http "Grafana" "http://localhost:3000/api/health"
echo ""

# --- Summary ---
echo "=============================================="
if [ "$FAILURES" -eq 0 ]; then
    echo -e "  Result: ${GREEN}All services healthy${NC}"
    echo "=============================================="
    exit 0
else
    echo -e "  Result: ${RED}${FAILURES} service(s) unhealthy${NC}"
    echo "=============================================="
    exit 1
fi
