# JZap (ShieldProxy) — Project Tasks

> Master checklist tracking all development phases and deliverables.
> Updated as work progresses. Dates reflect when work was completed.

---

## Phase 0: Foundation [2026-03-09]

### Monorepo & Configuration
- [x] Create monorepo directory structure
- [x] Create .gitignore
- [x] Create .editorconfig
- [x] Create .env.example with all configuration variables
- [x] Initialize Git repository

### Docker & Infrastructure
- [x] Create docker-compose.yml (full stack orchestration)
- [x] Create Proxy Node Dockerfile (OpenResty)
- [x] Create Rust Sidecar Dockerfile
- [x] Create Host Agent Dockerfile (Go)
- [x] Create Control Plane Dockerfile (Python/FastAPI)
- [x] Create DNS Module Dockerfile (Go)
- [x] Create Redis configuration (redis.conf)

### Proxy Node Scaffold
- [x] Create nginx.conf (main OpenResty config)
- [x] Create default.conf (server blocks, TLS, proxy pass)
- [x] Create init.lua (shared state, default config)
- [x] Create access.lua (L7 access phase stub)
- [x] Create log.lua (logging phase stub)
- [x] Create metrics.lua (Prometheus exporter)

### eBPF/XDP Scaffold
- [x] Create common.h (shared macros, maps, helpers)
- [x] Create blocklist.c (XDP IP blocklist program)
- [x] Create ratelimit.c (XDP per-IP rate limiter)
- [x] Create eBPF Makefile

### Rust Workspace Scaffold
- [x] Create workspace Cargo.toml
- [x] Create shared crate (types, config, errors)
- [x] Create ebpf-loader crate (stub)
- [x] Create fingerprint crate (stub)
- [x] Create ratelimit-engine crate (stub)
- [x] Create main.rs sidecar orchestrator

### Host Agent Scaffold (Go)
- [x] Create go.mod
- [x] Create cmd/agent/main.go (entrypoint)
- [x] Create internal/config/config.go
- [x] Create internal/firewall/nftables.go (stub)
- [x] Create internal/sync/blocklist.go (stub)
- [x] Create internal/telemetry/reporter.go (stub)
- [x] Create internal/fallback/autonomous.go (stub)

### Control Plane Scaffold (Python/FastAPI)
- [x] Create requirements.txt
- [x] Create alembic.ini
- [x] Create app/main.py (FastAPI entry)
- [x] Create app/config.py (Pydantic Settings)
- [x] Create app/api/deps.py (dependency injection)
- [x] Create app/api/routes/health.py
- [x] Create app/api/routes/rules.py (stub)
- [x] Create app/api/routes/tenants.py (stub)
- [x] Create app/api/routes/blocklist.py (stub)
- [x] Create app/models/ (Rule, Tenant, AuditLog, BlocklistEntry)
- [x] Create app/schemas/rule.py
- [x] Create app/services/redis_pubsub.py (stub)
- [x] Create app/db/session.py
- [x] Create app/db/migrations/env.py

### DNS Module Scaffold (Go)
- [x] Create go.mod
- [x] Create plugin/shieldproxy/setup.go
- [x] Create plugin/shieldproxy/handler.go (stub)
- [x] Create plugin/shieldproxy/rrl.go (stub)
- [x] Create cmd/main.go (standalone entrypoint)

### Bot Engine Scaffold
- [x] Create challenge/pow.js (SHA-256 PoW)
- [x] Create challenge/challenge.html (challenge page)
- [x] Create fingerprints/ja3_signatures.json (seed data)

### Database
- [x] Create db/init.sql (PostgreSQL + TimescaleDB schema)
- [x] Create db/seed.sql (default tenant, rules, allowlist)

### Monitoring
- [x] Create prometheus/prometheus.yml (scrape config)
- [x] Create grafana datasource provisioning
- [x] Create grafana dashboard provisioning
- [x] Create jzap-overview.json (pre-built dashboard)

### Security (mTLS)
- [x] Create certs/generate-ca.sh
- [x] Create certs/generate-proxy-cert.sh
- [x] Create certs/generate-agent-cert.sh
- [x] Create certs/generate-control-plane-cert.sh

### CI/CD
- [x] Create .github/workflows/ci.yml (Rust, Go, Python, Docker, eBPF)

### Utility Scripts
- [x] Create scripts/setup.sh
- [x] Create scripts/health-check.sh

### Documentation & Audit
- [x] Create TASKS.md (this file)
- [x] Create audit/2026-03-09_phase-0-foundation.md

---

## Phase 1: L3/4 Core [2026-03-09]

### eBPF/XDP Programs
- [x] Implement full XDP IP blocklist with dynamic map updates
- [x] Implement SYN cookie enforcement via XDP
- [x] Implement UDP flood per-IP rate limiting
- [x] Implement ICMP flood per-IP rate limiting
- [x] Implement per-IP PPS counters with sliding window
- [x] Implement geo-based filtering (MaxMind GeoIP2 in eBPF map)
- [x] Implement traffic baseline learning (N-sigma deviation alerting)
- [x] Implement amplification/reflection attack defense (DNS/NTP/SSDP/Memcached/CHARGEN)

### Rust eBPF Loader
- [x] Implement aya-based eBPF program loading and attachment
- [x] Implement blocklist map management (add/remove IPs)
- [x] Implement config map management (tunable parameters)
- [x] Implement metrics reading from per-CPU maps
- [x] Implement eBPF program hot-reload without traffic interruption
- [x] Implement geo filter map management
- [x] Implement traffic baseline stats reading

### Sidecar Modules
- [x] Implement Prometheus metrics exporter (HTTP /metrics endpoint)
- [x] Implement blocklist sync from Control Plane API (periodic polling)
- [x] Implement config sync from Control Plane API
- [x] Implement traffic baseline engine (rolling N-sigma anomaly detection)
- [x] Implement structured traffic logging pipeline (JSON to stdout)
- [x] Wire all modules together in main.rs orchestrator

### Integration
- [x] Wire eBPF loader to Control Plane API for blocklist updates
- [x] Wire eBPF metrics to Prometheus exporter
- [x] Integration test: simulated SYN flood (hping3)
- [x] Integration test: simulated UDP flood
- [x] Integration test: simulated ICMP flood
- [x] Integration test: full L3/4 test suite runner
- [x] Traffic logging to stdout/file

### Infrastructure
- [x] Update Rust sidecar Dockerfile with eBPF build support (clang, llvm, libbpf)
- [x] Update shared crate with Phase 1 types, constants, and eBPF map/metric IDs
- [x] Create audit/2026-03-09_phase-1-l3l4-core.md

---

## Phase 2: L7 Proxy

### OpenResty Lua Implementation
- [ ] Implement Redis-backed sliding window rate limiter (per-IP, per-path, per-UA)
- [ ] Implement slowloris defense (minimum header/body timeout enforcement)
- [ ] Implement HTTP flood detection (sliding window counters + threshold)
- [ ] Implement browser challenge redirect (integrate with bot-engine)
- [ ] Implement suspicious header filtering (no UA, bad Accept, etc.)
- [ ] Implement path-level rules (regex + prefix match, allow/block/challenge)
- [ ] Implement connection concurrency limits per IP
- [ ] Implement request body size enforcement
- [ ] Wire Lua to Rust sidecar via Unix socket for rate limit decisions

### Rust Rate Limit Engine
- [ ] Implement Redis-backed distributed sliding window counters
- [ ] Implement Unix socket server for Lua IPC
- [ ] Implement per-IP, per-path, per-UA rate limit keys
- [ ] Implement burst allowance logic

### Testing
- [ ] HTTP flood simulation test (wrk/vegeta at 200% threshold)
- [ ] Slowloris simulation test
- [ ] Header filtering test suite
- [ ] Path rule matching test suite

---

## Phase 3: Bot Engine

### TLS Fingerprinting
- [ ] Implement JA3 fingerprint extraction from TLS ClientHello
- [ ] Implement HTTP/2 SETTINGS frame fingerprinting (AKAMAI method)
- [ ] Implement JA3 hash matching against signature database
- [ ] Implement signature database loading from signed manifest

### Behavioral Scoring
- [ ] Implement request timing entropy analysis
- [ ] Implement path traversal pattern detection
- [ ] Implement header ordering fingerprinting
- [ ] Implement cookie handling behavior analysis
- [ ] Implement composite bot score calculation

### Challenge System
- [ ] Finalize JS proof-of-work challenge (SHA-256 puzzle)
- [ ] Implement CAPTCHA integration for high-score bots
- [ ] Implement challenge cookie verification (signed, time-limited)
- [ ] Implement challenge bypass for API-key authenticated clients

### Bot Management
- [ ] Implement known good bot allowlist (Googlebot, Bingbot)
- [ ] Implement reverse DNS + ASN validation for crawlers
- [ ] Implement ASN reputation scoring
- [ ] Implement weekly fingerprint database update mechanism

### Testing
- [ ] Test against headless Chromium
- [ ] Test against curl, Python requests, Go net/http
- [ ] Test against known bot JA3 signatures
- [ ] False positive rate validation

---

## Phase 4: DNS Module

### CoreDNS Plugin
- [ ] Implement DNS Response Rate Limiting (RRL)
- [ ] Implement NXDOMAIN flood detection and throttling
- [ ] Implement per-source-IP DNS query rate limiting
- [ ] Implement DNS amplification blocking (response/query ratio)
- [ ] Implement anycast-compatible stateless design
- [ ] Implement Redis-backed query counters

### Testing
- [ ] DNS flood simulation (dnsperf at 10x normal rate)
- [ ] NXDOMAIN flood simulation (random subdomain attack)
- [ ] RRL validation test

---

## Phase 5: Host Agent

### Core Agent
- [ ] Implement nftables rule management (add/remove/sync blocklist)
- [ ] Implement IP-level rate limiting via nftables
- [ ] Implement blocklist sync from Control Plane (30s poll interval)
- [ ] Implement gRPC telemetry streaming (10s interval)
- [ ] Implement autonomous fallback mode (last-known blocklist on CP disconnect)
- [ ] Implement systemd watchdog integration
- [ ] Implement Prometheus metrics endpoint

### Resource Constraints
- [ ] Validate <50MB RAM usage at idle
- [ ] Validate <2% CPU usage at idle
- [ ] Validate <5% CPU under active attack traffic (10k req/sec)

### Testing
- [ ] Autonomous fallback test (simulate CP outage during traffic)
- [ ] Blocklist sync accuracy test
- [ ] Agent crash recovery test (systemd watchdog)

---

## Phase 6: Control Plane

### REST API
- [ ] Implement rule CRUD with versioned configuration
- [ ] Implement tenant management with isolated rule sets
- [ ] Implement blocklist management (add/remove/bulk)
- [ ] Implement Redis pub/sub rule propagation to proxies and agents
- [ ] Implement API key authentication with per-key rate limiting and scoping
- [ ] Implement mTLS enforcement for all inter-component communication

### Audit Log
- [ ] Implement append-only audit log with hash chaining
- [ ] Implement actor identity, timestamp, before/after state tracking
- [ ] Implement source IP logging for all configuration changes
- [ ] Implement tamper-evidence detection (hash chain validation)

### Notifications
- [ ] Implement email alert integration
- [ ] Implement Slack webhook integration
- [ ] Implement PagerDuty integration
- [ ] Implement alert rules (attack detection, anomaly threshold)

### Testing
- [ ] API endpoint integration tests (100% route coverage)
- [ ] Audit log tamper-evidence test
- [ ] Pub/sub propagation latency test

---

## Phase 7: Hardening

### Security
- [ ] Security code review (all components)
- [ ] mTLS enforcement verification (certificate rejection test)
- [ ] Control Plane API penetration test
- [ ] Dependency pinning and CVE audit
- [ ] Control Plane self-protection rate limiting
- [ ] Dashboard IP allowlist enforcement
- [ ] Secret management review (no secrets in env vars)

### Performance
- [ ] Load test at 10 Gbps clean traffic forwarding
- [ ] Validate p99 latency <5ms under load
- [ ] Validate <0.1% false positive rate with synthetic traffic
- [ ] Validate attack detection MTTR <10 seconds (3 independent runs)
- [ ] Validate 100k HTTP req/sec per proxy node

### Observability
- [ ] Verify Prometheus metrics endpoints for all components
- [ ] Create Grafana dashboards (traffic, drops, bot scores, attack events)
- [ ] Load test script configs (wrk, vegeta, hping3, dnsperf)

---

## Phase 8: Documentation & GA

### Documentation
- [ ] Operator deployment guide
- [ ] API reference (auto-generated from FastAPI OpenAPI)
- [ ] Attack response runbooks
- [ ] Architecture decision records

### Release
- [ ] Changelog (v1.0)
- [ ] Full stack deployment test on fresh Ubuntu 22.04 VPS (<15 min)
- [ ] Runbook review by independent engineer

---

## Phase 9: Admin Panel (JZap-Admin — Separate Repo)

### Dashboard
- [ ] React + Vite + Recharts project setup
- [ ] Real-time traffic volume charts (5s refresh)
- [ ] Attack event timeline
- [ ] Blocked IPs table with manual unblock
- [ ] Bot scores visualization
- [ ] Alert configuration UI (email, Slack, PagerDuty)
- [ ] Per-tenant view switching

### Authentication
- [ ] Username/password login with bcrypt
- [ ] TOTP second factor (mandatory for operators)
- [ ] Session management

### Deployment
- [ ] Dockerfile for static SPA build
- [ ] Docker Compose for standalone deployment
- [ ] Nginx config for SPA routing
