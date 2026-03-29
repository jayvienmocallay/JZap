#!/bin/bash
# =============================================================================
# JZap — Generate Proxy Node mTLS Certificate
# Creates an ECDSA P-256 certificate signed by the JZap CA.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CA_DIR="${SCRIPT_DIR}/ca"
OUT_DIR="${SCRIPT_DIR}/proxy"

echo "=== JZap Proxy Certificate Generation ==="

# Verify CA exists
if [ ! -f "${CA_DIR}/ca.pem" ] || [ ! -f "${CA_DIR}/ca-key.pem" ]; then
    echo "ERROR: CA certificate not found. Run generate-ca.sh first."
    exit 1
fi

# Create output directory
mkdir -p "${OUT_DIR}"

# Generate ECDSA P-256 private key
echo "[1/4] Generating proxy private key (ECDSA P-256)..."
openssl ecparam -genkey -name prime256v1 -noout -out "${OUT_DIR}/proxy-key.pem"
chmod 600 "${OUT_DIR}/proxy-key.pem"

# Create SAN configuration for the CSR
echo "[2/4] Creating SAN configuration..."
cat > "${OUT_DIR}/proxy-san.cnf" <<EOF
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
C = US
ST = California
L = San Francisco
O = JZap
OU = Proxy
CN = jzap-proxy

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = proxy
DNS.2 = jzap-proxy
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF

# Generate Certificate Signing Request
echo "[3/4] Generating CSR..."
openssl req -new \
    -key "${OUT_DIR}/proxy-key.pem" \
    -out "${OUT_DIR}/proxy.csr" \
    -config "${OUT_DIR}/proxy-san.cnf"

# Sign with CA (1 year validity)
echo "[4/4] Signing certificate with CA..."
openssl x509 -req \
    -in "${OUT_DIR}/proxy.csr" \
    -CA "${CA_DIR}/ca.pem" \
    -CAkey "${CA_DIR}/ca-key.pem" \
    -CAcreateserial \
    -out "${OUT_DIR}/proxy.pem" \
    -days 365 \
    -extensions v3_req \
    -extfile "${OUT_DIR}/proxy-san.cnf"

# Clean up CSR and temp config
rm -f "${OUT_DIR}/proxy.csr" "${OUT_DIR}/proxy-san.cnf"

echo ""
echo "=== Proxy Certificate Generated Successfully ==="
echo "  Key:         ${OUT_DIR}/proxy-key.pem"
echo "  Certificate: ${OUT_DIR}/proxy.pem"
echo "  CA:          ${CA_DIR}/ca.pem"
echo ""
echo "SANs: DNS:proxy, DNS:jzap-proxy, DNS:localhost, IP:127.0.0.1"
