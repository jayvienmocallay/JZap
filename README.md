```ansi
[1;96m ██████╗[1;94m██████╗[1;97m     [1;96m██████╗ [1;94m███████╗ [1;96m█████╗  [1;94m██████╗ [1;96m██████╗ [1;94m███╗   ██╗[0m
[1;94m██╔════╝[1;96m╚════██╗[1;97m    [1;94m██╔══██╗[1;96m██╔════╝[1;94m██╔══██╗[1;96m██╔════╝[1;94m██╔═══██╗[1;96m████╗  ██║[0m
[1;96m██║     [1;94m █████╔╝[1;97m    [1;96m██████╔╝[1;94m█████╗  [1;96m███████║[1;94m██║     [1;96m██║   ██║[1;94m██╔██╗ ██║[0m
[1;94m██║     [1;96m██╔═══╝ [1;97m    [1;94m██╔══██╗[1;96m██╔══╝  [1;94m██╔══██║[1;96m██║     [1;94m██║   ██║[1;96m██║╚██╗██║[0m
[1;96m╚██████╗[1;94m███████╗[1;97m    [1;96m██████╔╝[1;94m███████╗[1;96m██║  ██║[1;94m╚██████╗[1;96m╚██████╔╝[1;94m██║ ╚████║[0m
[1;94m ╚═════╝[1;96m╚══════╝[1;97m    [1;94m╚═════╝ [1;96m╚══════╝[1;94m╚═╝  ╚═╝ [1;96m╚═════╝ [1;94m╚═════╝ [1;96m╚═╝  ╚═══╝[0m
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Project%20%232-red?style=flat&logo=github)](https://github.com)
[![Rust](https://img.shields.io/badge/Rust-stable-000000?style=flat&logo=rust)](https://www.rust-lang.org)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat&logo=docker)](https://www.docker.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat)](https://attack.mitre.org/)

> Hybrid DDoS defense platform with eBPF/XDP filtering, OpenResty L7 controls, Rust sidecar engines, and a FastAPI control plane.

*This is a quick overview. Architecture and implementation details are documented in project source structure and audit notes.*

## What It Does

- eBPF/XDP packet filtering for L3/L4 threat mitigation (blocklist, rate limiting, amplification controls)
- OpenResty Lua request processing for L7 policy enforcement and challenge workflows
- Real-time rule and blocklist synchronization between control plane and edge components
- Redis-backed low-latency state and pub/sub propagation for distributed policy updates
- TimescaleDB-backed persistence for control-plane data and long-range analysis
- Prometheus and Grafana observability for traffic, health, and defense metrics

## Quick Start

```bash
cp .env.example .env
# Set required secret values in .env
docker compose up -d --build
```

Visit:

- `http://localhost:8000/api/v1/health` (Control Plane)
- `http://localhost/health` (Proxy)
- `http://localhost:9090` (Prometheus)
- `http://localhost:3000` (Grafana)

## Stack

**Backend:** FastAPI, SQLAlchemy, Alembic, Redis, TimescaleDB

**Data Plane:** eBPF/XDP (C), OpenResty/Lua, Rust sidecar

**Agent/Infra:** Go agent, CoreDNS plugin module, Docker Compose

## Learn

This project includes practical implementation references in-source and through audit history.

| Module | Topic |
|--------|-------|
| `proxy/ebpf` | Kernel-level filtering and mitigation logic |
| `proxy/rust` | eBPF loading, sync engine, metrics, baseline logic |
| `proxy/lua` | L7 request handling and policy hooks |
| `control-plane/app` | API routes, models, schemas, and orchestration |
| `agent/internal` | Host enforcement, sync, telemetry, fallback behavior |


## License

AGPL 3.0
