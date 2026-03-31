<p align="center">
  <img src="assets/readme/jzap-neon-banner.svg" alt="JZap neon lightning banner" width="100%" />
</p>

<p align="center">
  <strong>JZap</strong> is a hybrid DDoS defense platform combining eBPF/XDP filtering, a Rust sidecar engine, OpenResty Lua controls, and a FastAPI control plane.
</p>

<p align="center">
  <img alt="License" src="https://img.shields.io/badge/license-AGPL--3.0-1d9bf0?style=for-the-badge" />
  <img alt="Platform" src="https://img.shields.io/badge/platform-Linux%20%7C%20Docker-00d084?style=for-the-badge" />
  <img alt="Status" src="https://img.shields.io/badge/status-active%20development-7c83fd?style=for-the-badge" />
</p>

## What It Does

- Filters high-volume L3/L4 attack traffic at kernel level using eBPF/XDP.
- Applies L7 controls in OpenResty (Lua) for challenge and request inspection flows.
- Syncs blocklists and policies through a central FastAPI control plane.
- Uses Redis for fast state and pub/sub propagation.
- Tracks observability with Prometheus + Grafana dashboards.

## Architecture

| Component | Responsibility |
|---|---|
| `proxy/ebpf` | XDP programs for blocklist, rate limiting, amplification protection |
| `proxy/rust` | eBPF loader, telemetry, baseline and sync engines |
| `proxy/nginx` + `proxy/lua` | OpenResty proxy and L7 policy hooks |
| `control-plane` | API, tenant/rule management, DB-backed policy control |
| `agent` | Host-level sync/fallback and firewall orchestration |
| `dns-module` | DNS protections and response-rate limiting |
| `monitoring` | Prometheus and Grafana provisioning |

## Quick Start

```bash
cp .env.example .env
# Set all required secret values in .env before starting

docker compose up -d --build
```

Check core services:

- Control plane health: `http://localhost:8000/api/v1/health`
- Proxy health: `http://localhost/health`
- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000`

## Security Notes Before Public Deployment

- Never commit real `.env` files, certificates, keys, or runtime data.
- Generate certificates per environment using scripts in `certs/`.
- Rotate DB, Redis, and control-plane secrets before production exposure.
- Keep operational secret bundles in a separate private repository.

## Repository Layout

```text
agent/              # host daemon
control-plane/      # FastAPI API and DB layer
proxy/              # OpenResty, Lua, Rust sidecar, eBPF programs
dns-module/         # DNS defense module
db/                 # schema and seed
audit/              # internal audit notes (ignored from push)
docs/progress/      # local progress logs (ignored from push)
```

## Development Stack

- Rust (workspace crates + sidecar)
- Go (agent + DNS module)
- Python (FastAPI + Alembic)
- Lua (OpenResty)
- C (eBPF programs)
- Docker Compose for local orchestration

## License

AGPL-3.0
