#!/usr/bin/env bash
# =============================================================================
# JZap — UDP Flood Simulation Test
# =============================================================================
# Tests the XDP UDP flood rate limiting using hping3 in UDP mode.
# Requires: hping3, curl
#
# Usage:
#   ./test-udp-flood.sh [TARGET_IP] [DURATION_SEC]
# =============================================================================

set -euo pipefail

TARGET_IP="${1:-127.0.0.1}"
TARGET_PORT="${2:-53}"
DURATION="${3:-10}"
METRICS_URL="${4:-http://127.0.0.1:9090/metrics}"

echo "=== JZap UDP Flood Test ==="
echo "Target:    ${TARGET_IP}:${TARGET_PORT}"
echo "Duration:  ${DURATION}s"
echo "Metrics:   ${METRICS_URL}"
echo ""

# ---- Pre-test metrics ----
echo "[1/4] Taking pre-test metrics snapshot..."
PRE_METRICS=$(curl -sf "${METRICS_URL}" 2>/dev/null || echo "UNAVAILABLE")
if [ "$PRE_METRICS" != "UNAVAILABLE" ]; then
    PRE_UDP_DROPS=$(echo "$PRE_METRICS" | grep 'jzap_xdp_packets{metric="dropped_udp_flood"}' | awk '{print $2}' || echo "0")
    echo "  Pre-test UDP drops: ${PRE_UDP_DROPS}"
else
    PRE_UDP_DROPS=0
    echo "  WARNING: Could not fetch pre-test metrics"
fi

# ---- Run UDP flood ----
echo ""
echo "[2/4] Launching UDP flood (${DURATION}s)..."

if ! command -v hping3 &>/dev/null; then
    echo "  hping3 not found. Using netcat UDP fallback..."
    END_TIME=$((SECONDS + DURATION))
    COUNT=0
    while [ $SECONDS -lt $END_TIME ]; do
        for _ in $(seq 1 200); do
            echo "JZAP_UDP_TEST_PAYLOAD" | timeout 0.01 nc -u -w0 "${TARGET_IP}" "${TARGET_PORT}" 2>/dev/null &
            COUNT=$((COUNT + 1))
        done
        wait 2>/dev/null || true
    done
    echo "  Sent approximately ${COUNT} UDP packets (fallback mode)"
else
    timeout "${DURATION}" hping3 --udp -p "${TARGET_PORT}" --flood --rand-source "${TARGET_IP}" 2>&1 || true
fi

echo "  Flood complete."

# ---- Wait and collect ----
echo ""
echo "[3/4] Waiting 5s for metrics to settle..."
sleep 5

echo ""
echo "[4/4] Taking post-test metrics snapshot..."
POST_METRICS=$(curl -sf "${METRICS_URL}" 2>/dev/null || echo "UNAVAILABLE")
if [ "$POST_METRICS" != "UNAVAILABLE" ]; then
    POST_UDP_DROPS=$(echo "$POST_METRICS" | grep 'jzap_xdp_packets{metric="dropped_udp_flood"}' | awk '{print $2}' || echo "0")
    DELTA=$(echo "${POST_UDP_DROPS} - ${PRE_UDP_DROPS}" | bc 2>/dev/null || echo "N/A")

    echo ""
    echo "=== Results ==="
    echo "UDP flood drops (delta): ${DELTA}"
    echo ""

    if [ "$DELTA" != "N/A" ] && [ "$DELTA" != "0" ]; then
        echo "PASS: XDP UDP flood defense is active (${DELTA} drops)"
    else
        echo "INFO: No UDP drops recorded"
    fi
fi

echo ""
echo "=== UDP Flood Test Complete ==="
