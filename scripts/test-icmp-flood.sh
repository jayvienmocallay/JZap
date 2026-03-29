#!/usr/bin/env bash
# =============================================================================
# JZap — ICMP Flood Simulation Test
# =============================================================================
# Tests the XDP ICMP flood rate limiting using hping3 in ICMP mode.
# Requires: hping3 or ping, curl
#
# Usage:
#   ./test-icmp-flood.sh [TARGET_IP] [DURATION_SEC]
# =============================================================================

set -euo pipefail

TARGET_IP="${1:-127.0.0.1}"
DURATION="${2:-10}"
METRICS_URL="${3:-http://127.0.0.1:9090/metrics}"

echo "=== JZap ICMP Flood Test ==="
echo "Target:    ${TARGET_IP}"
echo "Duration:  ${DURATION}s"
echo "Metrics:   ${METRICS_URL}"
echo ""

# ---- Pre-test metrics ----
echo "[1/4] Taking pre-test metrics snapshot..."
PRE_METRICS=$(curl -sf "${METRICS_URL}" 2>/dev/null || echo "UNAVAILABLE")
if [ "$PRE_METRICS" != "UNAVAILABLE" ]; then
    PRE_ICMP_DROPS=$(echo "$PRE_METRICS" | grep 'jzap_xdp_packets{metric="dropped_icmp_flood"}' | awk '{print $2}' || echo "0")
    echo "  Pre-test ICMP drops: ${PRE_ICMP_DROPS}"
else
    PRE_ICMP_DROPS=0
    echo "  WARNING: Could not fetch pre-test metrics"
fi

# ---- Run ICMP flood ----
echo ""
echo "[2/4] Launching ICMP flood (${DURATION}s)..."

if command -v hping3 &>/dev/null; then
    timeout "${DURATION}" hping3 --icmp --flood --rand-source "${TARGET_IP}" 2>&1 || true
else
    echo "  hping3 not found. Using ping flood fallback (requires root)..."
    if [ "$(id -u)" -eq 0 ]; then
        timeout "${DURATION}" ping -f -s 1400 "${TARGET_IP}" 2>&1 || true
    else
        echo "  Not root — using regular rapid ping..."
        timeout "${DURATION}" ping -i 0.001 -s 1400 "${TARGET_IP}" 2>&1 || true
    fi
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
    POST_ICMP_DROPS=$(echo "$POST_METRICS" | grep 'jzap_xdp_packets{metric="dropped_icmp_flood"}' | awk '{print $2}' || echo "0")
    DELTA=$(echo "${POST_ICMP_DROPS} - ${PRE_ICMP_DROPS}" | bc 2>/dev/null || echo "N/A")

    echo ""
    echo "=== Results ==="
    echo "ICMP flood drops (delta): ${DELTA}"
    echo ""

    if [ "$DELTA" != "N/A" ] && [ "$DELTA" != "0" ]; then
        echo "PASS: XDP ICMP flood defense is active (${DELTA} drops)"
    else
        echo "INFO: No ICMP drops recorded"
    fi
fi

echo ""
echo "=== ICMP Flood Test Complete ==="
