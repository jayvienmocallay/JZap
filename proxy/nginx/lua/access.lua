-- =============================================================================
-- JZap (ShieldProxy) — OpenResty Access Phase
-- Runs on every request. Enforces L7 protection rules.
-- Stub implementation — full logic added in Phase 2.
-- =============================================================================

local blocklist_dict = ngx.shared.jzap_blocklist
local ratelimit_dict = ngx.shared.jzap_ratelimit
local config_dict    = ngx.shared.jzap_config
local metrics_dict   = ngx.shared.jzap_metrics

local client_ip = ngx.var.remote_addr

-- -------------------------------------------------------------------------
-- Stage 1: IP Blocklist check
-- -------------------------------------------------------------------------
local blocked = blocklist_dict:get(client_ip)
if blocked then
    metrics_dict:incr("blocked_requests", 1)
    ngx.log(ngx.WARN, "[JZap] Blocked IP: ", client_ip)
    return ngx.exit(ngx.HTTP_FORBIDDEN)
end

-- -------------------------------------------------------------------------
-- Stage 2: Rate limiting (sliding window — stub)
-- TODO: Implement Redis-backed sliding window in Phase 2
-- -------------------------------------------------------------------------

-- -------------------------------------------------------------------------
-- Stage 3: Header inspection (stub)
-- TODO: Implement suspicious header filtering in Phase 2
-- -------------------------------------------------------------------------

-- -------------------------------------------------------------------------
-- Stage 4: Bot score evaluation (stub)
-- TODO: Implement behavioral bot scoring in Phase 3
-- -------------------------------------------------------------------------

-- Set default bot score variable for upstream header
ngx.var.jzap_bot_score = "0"

-- -------------------------------------------------------------------------
-- Stage 5: Path-level rules (stub)
-- TODO: Implement per-path allow/block/challenge rules in Phase 2
-- -------------------------------------------------------------------------

-- Increment passed requests counter
metrics_dict:incr("total_requests", 1)
metrics_dict:incr("passed_requests", 1)
