-- =============================================================================
-- JZap Seed Data
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Default tenant
-- -----------------------------------------------------------------------------
-- The api_key_hash is a placeholder — replace with a real bcrypt hash in production.
INSERT INTO tenants (id, name, api_key_hash, is_active, plan)
VALUES (
    'a0000000-0000-0000-0000-000000000001',
    'default',
    '$2b$12$placeholder_hash_replace_in_production_setup',
    true,
    'free'
) ON CONFLICT (name) DO NOTHING;

-- -----------------------------------------------------------------------------
-- Default protection rules
-- -----------------------------------------------------------------------------

-- Global rate limit: 100 requests/sec per source IP
INSERT INTO rules (tenant_id, name, description, rule_type, target, condition, action, priority)
VALUES (
    'a0000000-0000-0000-0000-000000000001',
    'Global IP Rate Limit',
    'Limit all source IPs to 100 requests per second',
    'rate_limit',
    'ip',
    '{"field": "req_per_sec", "operator": "gt", "value": 100}',
    'rate_limit',
    100
);

-- SYN flood threshold: 1000 PPS
INSERT INTO rules (tenant_id, name, description, rule_type, target, condition, action, priority)
VALUES (
    'a0000000-0000-0000-0000-000000000001',
    'SYN Flood Detection',
    'Block source IPs exceeding 1000 SYN packets per second',
    'threshold',
    'ip',
    '{"field": "syn_pps", "operator": "gt", "value": 1000}',
    'block',
    90
);

-- UDP flood threshold: 5000 PPS
INSERT INTO rules (tenant_id, name, description, rule_type, target, condition, action, priority)
VALUES (
    'a0000000-0000-0000-0000-000000000001',
    'UDP Flood Detection',
    'Block source IPs exceeding 5000 UDP packets per second',
    'threshold',
    'ip',
    '{"field": "udp_pps", "operator": "gt", "value": 5000}',
    'block',
    90
);

-- ICMP rate limit: 100 PPS
INSERT INTO rules (tenant_id, name, description, rule_type, target, condition, action, priority)
VALUES (
    'a0000000-0000-0000-0000-000000000001',
    'ICMP Rate Limit',
    'Rate limit ICMP packets to 100 per second per source IP',
    'rate_limit',
    'ip',
    '{"field": "icmp_pps", "operator": "gt", "value": 100}',
    'rate_limit',
    80
);

-- HTTP body size limit: 10 MB
INSERT INTO rules (tenant_id, name, description, rule_type, target, condition, action, priority)
VALUES (
    'a0000000-0000-0000-0000-000000000001',
    'HTTP Body Size Limit',
    'Block HTTP requests with body larger than 10 MB',
    'threshold',
    'ip',
    '{"field": "http_body_bytes", "operator": "gt", "value": 10485760}',
    'block',
    70
);

-- Connection concurrency limit: 100 per IP
INSERT INTO rules (tenant_id, name, description, rule_type, target, condition, action, priority)
VALUES (
    'a0000000-0000-0000-0000-000000000001',
    'Connection Concurrency Limit',
    'Limit concurrent connections to 100 per source IP',
    'threshold',
    'ip',
    '{"field": "concurrent_connections", "operator": "gt", "value": 100}',
    'rate_limit',
    75
);

-- -----------------------------------------------------------------------------
-- Known good bot allowlist
-- These are blocklist_entries with reason='allowlist' to indicate they should
-- bypass protection rules.
-- -----------------------------------------------------------------------------

-- Googlebot
INSERT INTO blocklist_entries (tenant_id, ip_address, reason, source)
VALUES
    ('a0000000-0000-0000-0000-000000000001', '66.249.64.0/19'::inet, 'allowlist', 'system');

-- Bingbot
INSERT INTO blocklist_entries (tenant_id, ip_address, reason, source)
VALUES
    ('a0000000-0000-0000-0000-000000000001', '157.55.39.0/24'::inet, 'allowlist', 'system');

-- Bingbot (additional range)
INSERT INTO blocklist_entries (tenant_id, ip_address, reason, source)
VALUES
    ('a0000000-0000-0000-0000-000000000001', '40.77.167.0/24'::inet, 'allowlist', 'system');

-- DuckDuckBot
INSERT INTO blocklist_entries (tenant_id, ip_address, reason, source)
VALUES
    ('a0000000-0000-0000-0000-000000000001', '72.94.249.34'::inet, 'allowlist', 'system');

-- Slurp (Yahoo)
INSERT INTO blocklist_entries (tenant_id, ip_address, reason, source)
VALUES
    ('a0000000-0000-0000-0000-000000000001', '68.180.228.0/24'::inet, 'allowlist', 'system');

-- Baiduspider
INSERT INTO blocklist_entries (tenant_id, ip_address, reason, source)
VALUES
    ('a0000000-0000-0000-0000-000000000001', '180.76.15.0/24'::inet, 'allowlist', 'system');

-- Yandex
INSERT INTO blocklist_entries (tenant_id, ip_address, reason, source)
VALUES
    ('a0000000-0000-0000-0000-000000000001', '141.8.142.0/24'::inet, 'allowlist', 'system');

-- Facebook External Hit
INSERT INTO blocklist_entries (tenant_id, ip_address, reason, source)
VALUES
    ('a0000000-0000-0000-0000-000000000001', '69.171.251.0/24'::inet, 'allowlist', 'system');

-- UptimeRobot
INSERT INTO blocklist_entries (tenant_id, ip_address, reason, source)
VALUES
    ('a0000000-0000-0000-0000-000000000001', '216.144.250.150'::inet, 'allowlist', 'system');
