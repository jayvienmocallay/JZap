-- =============================================================================
-- JZap Database Initialization
-- PostgreSQL + TimescaleDB
-- =============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- TENANTS
-- =============================================================================
CREATE TABLE IF NOT EXISTS tenants (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            TEXT NOT NULL UNIQUE,
    api_key_hash    TEXT NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    plan            TEXT NOT NULL DEFAULT 'free',
    max_bandwidth   BIGINT NOT NULL DEFAULT 10737418240,  -- 10 GB default
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tenants_name ON tenants (name);
CREATE INDEX idx_tenants_api_key_hash ON tenants (api_key_hash);

-- =============================================================================
-- RULES
-- =============================================================================
CREATE TABLE IF NOT EXISTS rules (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT,
    rule_type       TEXT NOT NULL,          -- 'rate_limit', 'threshold', 'block', 'allow', 'challenge'
    target          TEXT NOT NULL,           -- 'ip', 'cidr', 'asn', 'country', 'user_agent', 'path'
    condition       JSONB NOT NULL,          -- {"operator": "gt", "value": 100, "field": "req_per_sec"}
    action          TEXT NOT NULL,           -- 'block', 'challenge', 'rate_limit', 'log', 'allow'
    priority        INT NOT NULL DEFAULT 0,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rules_tenant_id ON rules (tenant_id);
CREATE INDEX idx_rules_rule_type ON rules (rule_type);
CREATE INDEX idx_rules_is_active ON rules (is_active);
CREATE INDEX idx_rules_priority ON rules (tenant_id, priority);

-- =============================================================================
-- BLOCKLIST ENTRIES
-- =============================================================================
CREATE TABLE IF NOT EXISTS blocklist_entries (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ip_address      INET,
    cidr            CIDR,
    asn             INT,
    country_code    CHAR(2),
    reason          TEXT NOT NULL,           -- 'manual', 'auto_ratelimit', 'auto_bot', 'allowlist'
    source          TEXT NOT NULL DEFAULT 'manual', -- 'manual', 'system', 'api'
    expires_at      TIMESTAMPTZ,             -- NULL = permanent
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_blocklist_tenant_id ON blocklist_entries (tenant_id);
CREATE INDEX idx_blocklist_ip ON blocklist_entries (ip_address);
CREATE INDEX idx_blocklist_cidr ON blocklist_entries USING gist (cidr inet_ops);
CREATE INDEX idx_blocklist_reason ON blocklist_entries (reason);
CREATE INDEX idx_blocklist_expires ON blocklist_entries (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_blocklist_active ON blocklist_entries (tenant_id, is_active);

-- =============================================================================
-- AUDIT LOG
-- =============================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    actor           TEXT NOT NULL,           -- user email, 'system', or API key ID
    action          TEXT NOT NULL,           -- 'create_rule', 'delete_rule', 'update_blocklist', etc.
    resource_type   TEXT NOT NULL,           -- 'rule', 'blocklist', 'tenant', 'config'
    resource_id     TEXT,
    details         JSONB,
    ip_address      INET,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_tenant_id ON audit_log (tenant_id);
CREATE INDEX idx_audit_created_at ON audit_log (created_at);
CREATE INDEX idx_audit_action ON audit_log (action);
CREATE INDEX idx_audit_actor ON audit_log (actor);

-- =============================================================================
-- TRAFFIC EVENTS (Time-series with TimescaleDB)
-- =============================================================================
CREATE TABLE IF NOT EXISTS traffic_events (
    time                TIMESTAMPTZ NOT NULL,
    tenant_id           UUID NOT NULL,
    source_ip           INET NOT NULL,
    request_count       BIGINT NOT NULL DEFAULT 0,
    bytes_in            BIGINT NOT NULL DEFAULT 0,
    bytes_out           BIGINT NOT NULL DEFAULT 0,
    blocked_count       BIGINT NOT NULL DEFAULT 0,
    challenged_count    BIGINT NOT NULL DEFAULT 0,
    bot_score           FLOAT DEFAULT 0.0
);

-- Convert to TimescaleDB hypertable for efficient time-series queries
SELECT create_hypertable('traffic_events', 'time');

CREATE INDEX idx_traffic_tenant_time ON traffic_events (tenant_id, time DESC);
CREATE INDEX idx_traffic_source_ip ON traffic_events (source_ip, time DESC);

-- =============================================================================
-- ATTACK EVENTS
-- =============================================================================
CREATE TABLE IF NOT EXISTS attack_events (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    attack_type         TEXT NOT NULL,       -- 'syn_flood', 'udp_flood', 'http_flood', 'dns_amplification', 'slowloris', etc.
    started_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at            TIMESTAMPTZ,         -- NULL = still active
    peak_pps            BIGINT DEFAULT 0,    -- peak packets per second
    peak_gbps           FLOAT DEFAULT 0.0,   -- peak gigabits per second
    source_count        INT DEFAULT 0,       -- distinct source IPs
    mitigation_action   TEXT NOT NULL,        -- 'rate_limit', 'block', 'challenge', 'null_route', 'scrub'
    resolved            BOOLEAN NOT NULL DEFAULT false,
    notes               TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_attack_tenant_id ON attack_events (tenant_id);
CREATE INDEX idx_attack_started ON attack_events (started_at DESC);
CREATE INDEX idx_attack_type ON attack_events (attack_type);
CREATE INDEX idx_attack_active ON attack_events (resolved) WHERE resolved = false;

-- =============================================================================
-- COMPRESSION & RETENTION POLICIES (TimescaleDB)
-- =============================================================================

-- Compress traffic_events data older than 7 days to save storage
ALTER TABLE traffic_events SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'tenant_id',
    timescaledb.compress_orderby = 'time DESC'
);

SELECT add_compression_policy('traffic_events', INTERVAL '7 days');

-- Drop traffic_events data older than 90 days
-- Adjust the interval as needed for your retention requirements
SELECT add_retention_policy('traffic_events', INTERVAL '90 days');
