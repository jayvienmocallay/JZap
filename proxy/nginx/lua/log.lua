-- =============================================================================
-- JZap (ShieldProxy) — OpenResty Log Phase
-- Runs after the response is sent. Records telemetry and metrics.
-- Stub implementation — full logic added in Phase 2.
-- =============================================================================

local metrics_dict = ngx.shared.jzap_metrics

local status = ngx.status
local client_ip = ngx.var.remote_addr
local request_time = ngx.var.request_time

-- -------------------------------------------------------------------------
-- Track upstream errors
-- -------------------------------------------------------------------------
if status >= 500 then
    metrics_dict:incr("upstream_errors", 1)
end

-- -------------------------------------------------------------------------
-- TODO (Phase 2): Send per-request telemetry to Rust sidecar via Unix socket
-- TODO (Phase 2): Update per-IP request counters for behavioral analysis
-- TODO (Phase 3): Update bot score history
-- -------------------------------------------------------------------------
