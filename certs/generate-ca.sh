#!/bin/bash
# =============================================================================
# JZap — Generate Root Certificate Authority
# Creates a self-signed ECDSA P-256 CA certificate for mTLS between services.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CA_DIR="${SCRIPT_DIR}/ca"

echo "=== JZap CA Certificate Generation ==="

# Create output directory
mkdir -p "${CA_DIR}"

# Generate ECDSA P-256 private key for the CA
echo "[1/2] Generating CA private key (ECDSA P-256)..."
openssl ecparam -genkey -name prime256v1 -noout -out "${CA_DIR}/ca-key.pem"

# Set restrictive permissions on the private key
chmod 600 "${CA_DIR}/ca-key.pem"

# Generate self-signed CA certificate (10 year validity)
echo "[2/2] Generating self-signed CA certificate (3650 days)..."
openssl req -new -x509 \
    -key "${CA_DIR}/ca-key.pem" \
    -out "${CA_DIR}/ca.pem" \
    -days 3650 \
    -subj "/C=US/ST=California/L=San Francisco/O=JZap/OU=Infrastructure/CN=JZap Root CA"

echo ""
echo "=== CA Certificate Generated Successfully ==="
echo "  CA Key:         ${CA_DIR}/ca-key.pem"
echo "  CA Certificate: ${CA_DIR}/ca.pem"
echo ""
echo "Keep the CA private key secure. It is used to sign all service certificates."
