# Audit Log — 2026-03-09

## Phase 0: Foundation

### Summary

Initial project scaffolding for JZap (ShieldProxy) — a hybrid DDoS protection platform. Established the full monorepo structure, Docker Compose stack, component scaffolds for all 6 services, mTLS certificate generation, CI/CD pipeline, database schemas, monitoring infrastructure, and utility scripts.

### Architecture Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Proxy approach | Nginx/OpenResty + Rust hybrid | OpenResty for battle-tested HTTP proxy; Rust for eBPF loading, TLS fingerprinting, and rate limit engine |
| Admin panel separation | Separate repo (JZap-Admin) | API-first architecture; security isolation; independent deployment and versioning |
| eBPF tooling | Aya crate (pure Rust) | No libbpf C dependency; native Rust integration |
| Rust workspace | 4 crates (shared, ebpf-loader, fingerprint, ratelimit-engine) | Clean separation of concerns; independent compilation |
| Database | PostgreSQL 16 + TimescaleDB | Time-series hypertables for traffic data; compression and retention policies |
| Rate limit state | Redis 7 (allkeys-lru, no persistence) | Ephemeral counters; sub-millisecond reads; pub/sub for rule propagation |
| Audit log integrity | Hash-chained rows (prev_hash + row_hash) | Tamper-evident append-only log per SRS Section 7.4 |

### Components Created

- [x] Monorepo directory structure (14 top-level directories)
- [x] .gitignore, .editorconfig, .env.example
- [x] docker-compose.yml (9 services: proxy, rust-sidecar, control-plane, agent, dns-module, timescaledb, redis, prometheus, grafana)
- [x] 5 Dockerfiles (proxy, rust-sidecar, agent, control-plane, dns-module)
- [x] Proxy Node: nginx.conf, default.conf, 4 Lua scripts (init, access, log, metrics)
- [x] eBPF/XDP: common.h, blocklist.c, ratelimit.c, Makefile
- [x] Rust workspace: 4 crates with stub implementations + sidecar main binary
- [x] Host Agent (Go): entrypoint, config, firewall, sync, telemetry, fallback modules
- [x] Control Plane (Python/FastAPI): full API scaffold with routes, models, schemas, services, DB session, Alembic migrations
- [x] DNS Module (Go): CoreDNS plugin scaffold with RRL, handler, standalone entrypoint
- [x] Bot Engine: SHA-256 PoW challenge (JS), challenge page (HTML), JA3 signature database (JSON seed)
- [x] Database: init.sql (full schema + TimescaleDB hypertables), seed.sql (default tenant, rules, allowlist)
- [x] Redis: redis.conf optimized for rate limiting workload
- [x] Monitoring: Prometheus scrape config, Grafana datasource + dashboard provisioning, pre-built overview dashboard
- [x] mTLS: 4 certificate generation scripts (CA, proxy, agent, control-plane)
- [x] CI/CD: GitHub Actions pipeline (Rust, Go x2, Python, Docker, eBPF compile check)
- [x] Utility scripts: setup.sh (one-command deploy), health-check.sh
- [x] TASKS.md (master checklist for all phases)

### File Count

~80+ files created across the monorepo.

### Languages Used

| Language | Files | Purpose |
|----------|-------|---------|
| Rust | ~10 | eBPF loader, TLS fingerprinting, rate limit engine, sidecar binary |
| Go | ~10 | Host agent, DNS module |
| Python | ~18 | Control Plane API (FastAPI) |
| Lua | 4 | OpenResty L7 proxy logic |
| C | 3 | eBPF/XDP kernel programs |
| JavaScript | 1 | Browser PoW challenge |
| HTML | 1 | Challenge page |
| SQL | 2 | Database schema and seed data |
| YAML | 6 | Docker Compose, CI/CD, Prometheus, Grafana |
| Bash | 6 | mTLS certs, setup, health check |
| TOML | 5 | Rust Cargo manifests |

### Known Limitations

- eBPF programs cannot be compiled or tested on Windows — require Linux kernel 5.10+ with kernel headers
- Rust workspace depends on `aya` crate which requires Linux for eBPF operations
- All component stubs have TODO markers for logic to be implemented in subsequent phases
- Python LSP errors for `redis.asyncio` and `alembic` are expected — dependencies not installed locally
- Docker images not yet built or tested (requires Docker daemon)

### Next Steps

Phase 1: L3/4 Core — Implement full eBPF/XDP programs, Rust eBPF loader with aya, and integration tests for SYN/UDP/ICMP flood mitigation.
