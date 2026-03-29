-- =============================================================================
-- JZap (ShieldProxy) — Prometheus Metrics Exporter
-- Serves metrics in Prometheus exposition format
-- =============================================================================

local _M = {}

local metrics_dict = ngx.shared.jzap_metrics

function _M.serve()
    local metrics = {
        "total_requests",
        "blocked_requests",
        "challenged_requests",
        "passed_requests",
        "rate_limited_requests",
        "bot_detected_requests",
        "upstream_errors",
    }

    local lines = {}

    for _, key in ipairs(metrics) do
        local val = metrics_dict:get(key) or 0
        local prom_name = "jzap_proxy_" .. key
        table.insert(lines, string.format("# HELP %s JZap proxy metric: %s", prom_name, key))
        table.insert(lines, string.format("# TYPE %s counter", prom_name))
        table.insert(lines, string.format("%s %d", prom_name, val))
    end

    -- Active connections
    table.insert(lines, "# HELP jzap_proxy_active_connections Current active connections")
    table.insert(lines, "# TYPE jzap_proxy_active_connections gauge")
    table.insert(lines, string.format("jzap_proxy_active_connections %d", ngx.var.connections_active or 0))

    ngx.header.content_type = "text/plain; charset=utf-8"
    ngx.say(table.concat(lines, "\n"))
end

return _M
