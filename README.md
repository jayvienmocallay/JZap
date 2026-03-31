<pre align="center">
	 ██╗███████╗ █████╗ ██████╗
	 ██║╚══███╔╝██╔══██╗██╔══██╗
	 ██║  ███╔╝ ███████║██████╔╝
██   ██║ ███╔╝  ██╔══██║██╔═══╝
╚█████╔╝███████╗██║  ██║██║
 ╚════╝ ╚══════╝╚═╝  ╚═╝╚═╝
</pre>

<p align="center"><strong>Hybrid DDoS Defense Platform</strong></p>

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
