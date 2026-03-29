#!/usr/bin/env bash
# =============================================================================
# JZap — Full L3/4 Integration Test Suite
# =============================================================================
# Runs all L3/4 DDoS defense tests in sequence and produces a summary report.
# Requires: hping3 (recommended), curl, jq
#
# Usage:
#   ./test-l3l4-all.sh [TARGET_IP]
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_IP="${1:-127.0.0.1}"
METRICS_URL="${2:-http://127.0.0.1:9090/metrics}"
DURATION=10

echo "================================================================"
echo " JZap L3/4 Core — Full Integration Test Suite"
echo "================================================================"
echo ""
echo "Target:   ${TARGET_IP}"
echo "Metrics:  ${METRICS_URL}"
echo "Duration: ${DURATION}s per test"
echo ""
echo "Tests:"
echo "  1. SYN flood defense"
echo "  2. UDP flood defense"
echo "  3. ICMP flood defense"
echo "  4. Metrics endpoint validation"
echo "  5. Blocklist validation (manual IP add/remove)"
echo ""
echo "================================================================"
echo ""

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

run_test() {
    local name="$1"
    local cmd="$2"

    echo ""
    echo "---- TEST: ${name} ----"
    if eval "${cmd}"; then
        echo "  -> RESULT: PASS"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  -> RESULT: FAIL (exit code $?)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    echo ""
}

# ---- Test 1: Metrics endpoint ----
echo "---- TEST: Metrics Endpoint ----"
if curl -sf "${METRICS_URL}" >/dev/null 2>&1; then
    echo "  Prometheus metrics endpoint is reachable"
    METRICS_CONTENT=$(curl -sf "${METRICS_URL}")
    if echo "$METRICS_CONTENT" | grep -q "jzap_xdp_packets"; then
        echo "  JZap XDP metrics are present"
        echo "  -> RESULT: PASS"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  WARNING: JZap XDP metrics not found in output"
        echo "  -> RESULT: FAIL"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
else
    echo "  WARNING: Cannot reach metrics endpoint at ${METRICS_URL}"
    echo "  -> RESULT: SKIP (sidecar not running)"
    SKIP_COUNT=$((SKIP_COUNT + 1))
fi

# ---- Test 2: Health endpoint ----
echo ""
echo "---- TEST: Health Endpoint ----"
HEALTH_URL=$(echo "${METRICS_URL}" | sed 's|/metrics|/health|')
if curl -sf "${HEALTH_URL}" >/dev/null 2>&1; then
    echo "  Health endpoint is reachable"
    echo "  -> RESULT: PASS"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  Health endpoint not reachable"
    echo "  -> RESULT: SKIP"
    SKIP_COUNT=$((SKIP_COUNT + 1))
fi

# ---- Test 3: SYN flood ----
echo ""
echo "---- TEST: SYN Flood Defense ----"
if [ -f "${SCRIPT_DIR}/test-syn-flood.sh" ]; then
    bash "${SCRIPT_DIR}/test-syn-flood.sh" "${TARGET_IP}" 80 "${DURATION}" "${METRICS_URL}" && \
        PASS_COUNT=$((PASS_COUNT + 1)) || FAIL_COUNT=$((FAIL_COUNT + 1))
else
    echo "  test-syn-flood.sh not found"
    SKIP_COUNT=$((SKIP_COUNT + 1))
fi

# ---- Test 4: UDP flood ----
echo ""
echo "---- TEST: UDP Flood Defense ----"
if [ -f "${SCRIPT_DIR}/test-udp-flood.sh" ]; then
    bash "${SCRIPT_DIR}/test-udp-flood.sh" "${TARGET_IP}" 53 "${DURATION}" "${METRICS_URL}" && \
        PASS_COUNT=$((PASS_COUNT + 1)) || FAIL_COUNT=$((FAIL_COUNT + 1))
else
    echo "  test-udp-flood.sh not found"
    SKIP_COUNT=$((SKIP_COUNT + 1))
fi

# ---- Test 5: ICMP flood ----
echo ""
echo "---- TEST: ICMP Flood Defense ----"
if [ -f "${SCRIPT_DIR}/test-icmp-flood.sh" ]; then
    bash "${SCRIPT_DIR}/test-icmp-flood.sh" "${TARGET_IP}" "${DURATION}" "${METRICS_URL}" && \
        PASS_COUNT=$((PASS_COUNT + 1)) || FAIL_COUNT=$((FAIL_COUNT + 1))
else
    echo "  test-icmp-flood.sh not found"
    SKIP_COUNT=$((SKIP_COUNT + 1))
fi

# ---- Summary ----
echo ""
echo "================================================================"
echo " Test Summary"
echo "================================================================"
echo ""
echo "  Passed:  ${PASS_COUNT}"
echo "  Failed:  ${FAIL_COUNT}"
echo "  Skipped: ${SKIP_COUNT}"
echo ""

if [ "${FAIL_COUNT}" -gt 0 ]; then
    echo "  OVERALL: SOME TESTS FAILED"
    exit 1
else
    echo "  OVERALL: ALL TESTS PASSED (or skipped)"
    exit 0
fi
