# =============================================================================
# JZap Agent — Go Host Agent
# =============================================================================
# Multi-stage build for the host-level agent that manages nftables rules,
# eBPF programs, and reports telemetry to the control plane.
#
# NOTE: Runtime uses debian (NOT alpine) because nftables requires glibc
# and the full nft userspace toolchain.
# -----------------------------------------------------------------------------

# --------------- Stage 1: Builder -------------------------------------------
FROM golang:1.22-bookworm AS builder

WORKDIR /build

# Copy dependency manifests first for caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy all source code
COPY . .

# Static binary — no CGO needed
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o agent ./cmd/agent

# --------------- Stage 2: Runtime -------------------------------------------
FROM debian:bookworm-slim AS runtime

LABEL maintainer="JZap Team"
LABEL description="Host agent for nftables management and telemetry"

RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables \
    iptables \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/agent /app/agent

EXPOSE 9091

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app/agent", "healthcheck"]

CMD ["/app/agent"]
