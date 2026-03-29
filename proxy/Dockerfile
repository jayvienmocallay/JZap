# =============================================================================
# JZap Proxy — OpenResty reverse-proxy node
# =============================================================================
# Multi-stage build for the OpenResty-based proxy with Lua scripting support.
# -----------------------------------------------------------------------------

FROM openresty/openresty:alpine AS runtime

LABEL maintainer="JZap Team"
LABEL description="OpenResty proxy node with Lua-based bot-engine integration"

# Install runtime dependencies
RUN apk add --no-cache \
    curl \
    lua-resty-redis \
    && opm get openresty/lua-resty-core \
    && opm get openresty/lua-resty-lrucache

# Create required directories
RUN mkdir -p /etc/openresty/conf.d \
    && mkdir -p /usr/local/openresty/nginx/lua \
    && mkdir -p /usr/local/openresty/nginx/html/challenge

# Copy nginx configuration
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY conf.d/ /etc/openresty/conf.d/

# Copy Lua scripts
COPY lua/ /usr/local/openresty/nginx/lua/

# Copy bot-engine challenge files (JS challenges, CAPTCHA pages, etc.)
COPY --from=bot-engine html/ /usr/local/openresty/nginx/html/challenge/
# Fallback: copy local challenge assets if present
COPY html/ /usr/local/openresty/nginx/html/

EXPOSE 80 443 8443

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:80/health || exit 1

CMD ["openresty", "-g", "daemon off;"]
