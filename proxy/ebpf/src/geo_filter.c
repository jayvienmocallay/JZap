/* ===========================================================================
 * JZap (ShieldProxy) — XDP Geo-Based Rate Limiting / Filtering
 * FR-L3-06: Per-country traffic filtering and rate limiting
 *
 * This program is designed to be chained AFTER the blocklist program
 * (via XDP program chaining or loaded as a separate tail-call program).
 *
 * Flow:
 *   1. Parse IPv4 source address
 *   2. Look up source IP in LPM trie (jzap_geoip) → country code
 *   3. Look up country code in jzap_geo_filter → action
 *   4. action=0 (allow): XDP_PASS
 *      action=1 (drop):  XDP_DROP + increment METRIC_DROPPED_GEO
 *      action=2 (rate-limit): apply per-country rate limit
 *
 * The jzap_geoip LPM trie is populated from userspace with GeoIP data
 * (e.g., MaxMind GeoLite2 or similar databases).
 * =========================================================================== */

#include "common.h"

/* -------------------------------------------------------------------------
 * LPM trie key for GeoIP lookup
 * Stores a prefix length and an IPv4 address for longest-prefix-match.
 * ------------------------------------------------------------------------- */
struct geoip_key {
    __u32 prefixlen;
    __u32 addr;
};

/* -------------------------------------------------------------------------
 * Maps — GeoIP LPM trie (populated from userspace)
 * Key: { prefixlen, IPv4 address }, Value: country code (u16)
 *
 * BPF_F_NO_PREALLOC is required for LPM trie maps.
 * Max 256K entries should cover all country-level CIDR blocks.
 * ------------------------------------------------------------------------- */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 262144);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct geoip_key);
    __type(value, __u16);                /* ISO 3166-1 numeric country code */
} jzap_geoip SEC(".maps");

/* -------------------------------------------------------------------------
 * Maps — Per-country rate limit counters
 * Key: country code (u16), Value: rate_limit_entry
 * Allows per-country PPS enforcement when geo_action.action == 2.
 * ------------------------------------------------------------------------- */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_GEO_ENTRIES);
    __type(key, __u16);
    __type(value, struct rate_limit_entry);
} jzap_geo_ratelimit SEC(".maps");

/* -------------------------------------------------------------------------
 * Helper: Check per-country rate limit.
 * Returns 1 if rate limit exceeded, 0 if within limit.
 * ------------------------------------------------------------------------- */
static __always_inline int check_country_rate_limit(__u16 country_code,
                                                    __u32 pps_limit,
                                                    __u32 pkt_len)
{
    __u64 now = bpf_ktime_get_ns();
    struct rate_limit_entry *entry;

    entry = bpf_map_lookup_elem(&jzap_geo_ratelimit, &country_code);
    if (entry) {
        __u64 elapsed = now - entry->timestamp_ns;

        if (elapsed >= RATE_LIMIT_WINDOW_NS) {
            /* New window — reset counters */
            entry->timestamp_ns = now;
            entry->packet_count = 1;
            entry->bytes_count  = pkt_len;
            return 0;
        }

        entry->packet_count++;
        entry->bytes_count += pkt_len;

        if (entry->packet_count > pps_limit) {
            return 1;
        }

        return 0;
    }

    /* First packet for this country — create entry */
    struct rate_limit_entry new_entry = {
        .timestamp_ns = now,
        .packet_count = 1,
        .bytes_count  = pkt_len,
    };
    bpf_map_update_elem(&jzap_geo_ratelimit, &country_code, &new_entry,
                        BPF_ANY);

    return 0;
}

SEC("xdp")
int jzap_geo_filter_prog(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* -----------------------------------------------------------------
     * Check if geo filtering is enabled (config toggle)
     * ----------------------------------------------------------------- */
    __u64 geo_enabled = get_config(CFG_ENABLE_GEO_FILTER, 0);
    if (!geo_enabled) {
        return XDP_PASS;
    }

    /* -----------------------------------------------------------------
     * Parse Ethernet header
     * ----------------------------------------------------------------- */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    /* -----------------------------------------------------------------
     * Parse IPv4 header
     * ----------------------------------------------------------------- */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    if (iph->ihl < 5) {
        return XDP_DROP;
    }

    __u32 src_ip  = iph->saddr;
    __u32 pkt_len = data_end - data;

    /* -----------------------------------------------------------------
     * GeoIP lookup — longest prefix match on source IP
     * ----------------------------------------------------------------- */
    struct geoip_key lookup_key = {
        .prefixlen = 32,
        .addr      = src_ip,
    };

    __u16 *country_code = bpf_map_lookup_elem(&jzap_geoip, &lookup_key);
    if (!country_code) {
        /* No GeoIP data for this IP — allow by default */
        return XDP_PASS;
    }

    __u16 cc = *country_code;

    /* -----------------------------------------------------------------
     * Look up per-country action
     * ----------------------------------------------------------------- */
    struct geo_action *action = bpf_map_lookup_elem(&jzap_geo_filter, &cc);
    if (!action) {
        /* No geo policy for this country — allow */
        return XDP_PASS;
    }

    switch (action->action) {
    case 1:
        /* DROP — block all traffic from this country */
        metric_inc(METRIC_DROPPED_GEO);
        return XDP_DROP;

    case 2:
        /* RATE-LIMIT — apply per-country PPS limit */
        if (action->rate_limit_pps == 0) {
            return XDP_PASS;
        }
        if (check_country_rate_limit(cc, action->rate_limit_pps, pkt_len)) {
            metric_inc(METRIC_DROPPED_GEO);
            return XDP_DROP;
        }
        return XDP_PASS;

    default:
        /* action == 0 or unknown — ALLOW */
        return XDP_PASS;
    }
}

char _license[] SEC("license") = "GPL";
