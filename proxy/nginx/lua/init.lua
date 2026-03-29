-- =============================================================================
-- JZap (ShieldProxy) — OpenResty Init Phase
-- Runs once when OpenResty starts. Sets up shared state and loads config.
-- =============================================================================

local _M = {}

-- Shared dictionaries (allocated in nginx.conf)
local ratelimit_dict = ngx.shared.jzap_ratelimit
local botscores_dict = ngx.shared.jzap_botscores
local blocklist_dict = ngx.shared.jzap_blocklist
local config_dict    = ngx.shared.jzap_config
local metrics_dict   = ngx.shared.jzap_metrics

-- -------------------------------------------------------------------------
-- Default configuration values
-- -------------------------------------------------------------------------
local defaults = {
    -- Rate limiting (FR-L7-01)
    rate_limit_per_ip_per_second    = 100,
    rate_limit_burst                = 200,

    -- Slowloris defense thresholds (FR-L7-02)
    min_header_timeout_ms           = 10000,
    min_body_timeout_ms             = 10000,

    -- HTTP flood detection (FR-L7-03)
    flood_window_seconds            = 60,
    flood_threshold_requests        = 600,

    -- Connection limits (FR-L7-07)
    max_connections_per_ip          = 100,

    -- Request size (FR-L7-08)
    max_body_size_bytes             = 10485760,  -- 10MB

    -- Bot scoring thresholds (FR-BOT-03)
    bot_score_challenge_threshold   = 50,
    bot_score_block_threshold       = 80,

    -- Challenge settings (FR-L7-04)
    challenge_cookie_ttl_seconds    = 3600,
    challenge_difficulty            = 4,  -- leading zeros in SHA-256
}

-- Load defaults into shared config dict
for key, value in pairs(defaults) do
    config_dict:safe_set(key, value)
end

-- -------------------------------------------------------------------------
-- Initialize metrics counters
-- -------------------------------------------------------------------------
local metric_keys = {
    "total_requests",
    "blocked_requests",
    "challenged_requests",
    "passed_requests",
    "rate_limited_requests",
    "bot_detected_requests",
    "upstream_errors",
}

for _, key in ipairs(metric_keys) do
    metrics_dict:safe_set(key, 0)
end

ngx.log(ngx.NOTICE, "[JZap] Init phase complete. Default configuration loaded.")

return _M
