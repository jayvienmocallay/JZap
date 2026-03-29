# =============================================================================
# JZap DNS Module — Custom CoreDNS with ShieldProxy Plugin
# =============================================================================
# Multi-stage build for the DNS module that provides intelligent DNS-level
# filtering and GeoIP-aware routing via a custom CoreDNS plugin.
# -----------------------------------------------------------------------------

# --------------- Stage 1: Builder -------------------------------------------
FROM golang:1.22-bookworm AS builder

WORKDIR /build

# Copy dependency manifests first for caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy plugin source and main entry point
COPY plugin/ plugin/
COPY cmd/ cmd/
COPY *.go ./

# Build the custom DNS server binary with the shieldproxy plugin
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o dns-module ./cmd/dns-module

# --------------- Stage 2: Runtime -------------------------------------------
FROM debian:bookworm-slim AS runtime

LABEL maintainer="JZap Team"
LABEL description="CoreDNS-based DNS module with shieldproxy plugin"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    bind9-dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/dns-module /app/dns-module

# DNS listens on both UDP and TCP
EXPOSE 53/udp 53/tcp

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD dig @127.0.0.1 -p 53 health.check.local A +short +time=2 || exit 1

CMD ["/app/dns-module"]
