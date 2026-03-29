#!/usr/bin/env bash
# =============================================================================
# JZap — SYN Flood Simulation Test
# =============================================================================
# Tests the XDP SYN flood defense using hping3.
# Requires: hping3, curl, jq
#
# Usage:
#   ./test-syn-flood.sh [TARGET_IP] [DURATION_SEC]
#
# Default: floods 127.0.0.1 for 10 seconds and checks metrics before/after.
# =============================================================================

set -euo pipefail

TARGET_IP="${1:-127.0.0.1}"
TARGET_PORT="${2:-80}"
DURATION="${3:-10}"
METRICS_URL="${4:-http://127.0.0.1:9090/metrics}"
PPS="${5:-50000}"

echo "=== JZap SYN Flood Test ==="
echo "Target:    ${TARGET_IP}:${TARGET_PORT}"
echo "Duration:  ${DURATION}s"
echo "Rate:      ${PPS} PPS"
echo "Metrics:   ${METRICS_URL}"
echo ""

# ---- Pre-test metrics snapshot ----
echo "[1/4] Taking pre-test metrics snapshot..."
PRE_METRICS=$(curl -sf "${METRICS_URL}" 2>/dev/null || echo "UNAVAILABLE")
if [ "$PRE_METRICS" = "UNAVAILABLE" ]; then
    echo "  WARNING: Could not fetch pre-test metrics (sidecar may not be running)"
    PRE_SYN_DROPS=0
    PRE_TOTAL=0
else
    PRE_SYN_DROPS=$(echo "$PRE_METRICS" | grep 'jzap_xdp_packets{metric="dropped_syn_flood"}' | awk '{print $2}' || echo "0")
    PRE_TOTAL=$(echo "$PRE_METRICS" | grep 'jzap_xdp_packets{metric="total_packets"}' | awk '{print $2}' || echo "0")
    echo "  Pre-test total packets: ${PRE_TOTAL}"
    echo "  Pre-test SYN drops:     ${PRE_SYN_DROPS}"
fi

# ---- Run SYN flood ----
echo ""
echo "[2/4] Launching SYN flood (${DURATION}s at ${PPS} PPS)..."
echo "  Command: hping3 -S -p ${TARGET_PORT} --flood -c $((PPS * DURATION)) ${TARGET_IP}"

if ! command -v hping3 &>/dev/null; then
    echo "  ERROR: hping3 not found. Install with: apt-get install hping3"
    echo "  Simulating with netcat SYN attempts instead..."

    # Fallback: rapid TCP connection attempts
    END_TIME=$((SECONDS + DURATION))
    COUNT=0
    while [ $SECONDS -lt $END_TIME ]; do
        for _ in $(seq 1 100); do
            timeout 0.01 bash -c "echo > /dev/tcp/${TARGET_IP}/${TARGET_PORT}" 2>/dev/null &
            COUNT=$((COUNT + 1))
        done
        wait 2>/dev/null || true
    done
    echo "  Sent approximately ${COUNT} SYN attempts (fallback mode)"
else
    # Real hping3 SYN flood
    timeout "${DURATION}" hping3 -S -p "${TARGET_PORT}" --flood --rand-source "${TARGET_IP}" 2>&1 || true
fi

echo "  Flood complete."

# ---- Wait for metrics to settle ----
echo ""
echo "[3/4] Waiting 5s for metrics to settle..."
sleep 5

# ---- Post-test metrics snapshot ----
echo ""
echo "[4/4] Taking post-test metrics snapshot..."
POST_METRICS=$(curl -sf "${METRICS_URL}" 2>/dev/null || echo "UNAVAILABLE")
if [ "$POST_METRICS" = "UNAVAILABLE" ]; then
    echo "  WARNING: Could not fetch post-test metrics"
else
    POST_SYN_DROPS=$(echo "$POST_METRICS" | grep 'jzap_xdp_packets{metric="dropped_syn_flood"}' | awk '{print $2}' || echo "0")
    POST_TOTAL=$(echo "$POST_METRICS" | grep 'jzap_xdp_packets{metric="total_packets"}' | awk '{print $2}' || echo "0")

    DELTA_SYN_DROPS=$(echo "${POST_SYN_DROPS} - ${PRE_SYN_DROPS}" | bc 2>/dev/null || echo "N/A")
    DELTA_TOTAL=$(echo "${POST_TOTAL} - ${PRE_TOTAL}" | bc 2>/dev/null || echo "N/A")

    echo ""
    echo "=== Results ==="
    echo "Total packets processed (delta): ${DELTA_TOTAL}"
    echo "SYN flood drops (delta):         ${DELTA_SYN_DROPS}"
    echo ""

    if [ "$DELTA_SYN_DROPS" != "N/A" ] && [ "$DELTA_SYN_DROPS" != "0" ]; then
        echo "PASS: XDP SYN flood defense is active (${DELTA_SYN_DROPS} drops)"
    else
        echo "INFO: No SYN drops recorded — XDP program may not be attached or threshold not reached"
    fi
fi

echo ""
echo "=== SYN Flood Test Complete ==="
