/* ===========================================================================
 * JZap (ShieldProxy) — Common eBPF Headers
 * Shared macros, structs, and map definitions for XDP programs
 * =========================================================================== */

#ifndef JZAP_EBPF_COMMON_H
#define JZAP_EBPF_COMMON_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* -------------------------------------------------------------------------
 * Constants
 * ------------------------------------------------------------------------- */
#define MAX_BLOCKLIST_ENTRIES    1000000     /* 1M IPs in blocklist */
#define MAX_RATELIMIT_ENTRIES    500000      /* 500K per-IP rate limit entries */
#define MAX_GEO_ENTRIES          512         /* Max country-code geo filter rules */
#define MAX_SYN_COOKIE_ENTRIES   100000      /* Per-IP SYN cookie tracking */
#define MAX_AMPLIFICATION_ENTRIES 100000     /* Per-IP amplification tracking */
#define RATE_LIMIT_WINDOW_NS     1000000000ULL  /* 1 second in nanoseconds */
#define DEFAULT_PPS_LIMIT        10000       /* Default packets per second per IP */
#define DEFAULT_UDP_PPS_LIMIT    5000        /* Default UDP PPS limit */
#define DEFAULT_ICMP_PPS_LIMIT   100         /* Default ICMP PPS limit */
#define DEFAULT_SYN_PPS_LIMIT    1000        /* Default SYN PPS limit */
#define DEFAULT_AMPLIFICATION_RATIO 10       /* Max response/query byte ratio */
#define SYN_COOKIE_TTL_NS        30000000000ULL /* 30 seconds in nanoseconds */

/* -------------------------------------------------------------------------
 * Structs
 * ------------------------------------------------------------------------- */

/* Rate limit entry — per-IP packet counter with timestamp */
struct rate_limit_entry {
    __u64 timestamp_ns;     /* Last window start time */
    __u64 packet_count;     /* Packets in current window */
    __u64 bytes_count;      /* Bytes in current window */
};

/* Geo filter entry — per-country action: 0=allow, 1=drop, 2=rate-limit */
struct geo_action {
    __u8  action;
    __u32 rate_limit_pps;
};

/* SYN cookie state — per-IP SYN cookie tracking for handshake validation */
struct syn_cookie_state {
    __u64 cookie;
    __u64 timestamp_ns;
    __u8  validated;
};

/* Amplification tracking — per-IP query/response ratio monitoring */
struct amplification_entry {
    __u64 query_count;
    __u64 response_bytes;
    __u64 window_start;
};

/* Traffic baseline statistics — aggregate counters per time window */
struct traffic_stats {
    __u64 window_start;
    __u64 total_packets;
    __u64 total_bytes;
    __u64 tcp_packets;
    __u64 udp_packets;
    __u64 icmp_packets;
    __u64 syn_packets;
};

/* -------------------------------------------------------------------------
 * Maps — IP blocklist
 * Key: IPv4 address (u32), Value: block reason (u8)
 * Block reasons: 1=manual, 2=auto-ratelimit, 3=threat-intel, 4=geo-block
 * ------------------------------------------------------------------------- */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKLIST_ENTRIES);
    __type(key, __u32);         /* IPv4 address in network byte order */
    __type(value, __u8);        /* Block reason code */
} jzap_blocklist SEC(".maps");

/* -------------------------------------------------------------------------
 * Maps — Per-IP rate limit counters
 * ------------------------------------------------------------------------- */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RATELIMIT_ENTRIES);
    __type(key, __u32);                     /* IPv4 address */
    __type(value, struct rate_limit_entry);  /* Rate limit state */
} jzap_ratelimit SEC(".maps");

/* -------------------------------------------------------------------------
 * Maps — Configuration (tunable parameters from userspace)
 * Key: config parameter ID, Value: u64 config value
 * ------------------------------------------------------------------------- */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u64);
} jzap_config SEC(".maps");

/* -------------------------------------------------------------------------
 * Maps — Per-CPU metrics counters
 * ------------------------------------------------------------------------- */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} jzap_metrics SEC(".maps");

/* -------------------------------------------------------------------------
 * Maps — Geo filter (per-country actions)
 * Key: country code (u16), Value: geo_action
 * ------------------------------------------------------------------------- */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_GEO_ENTRIES);
    __type(key, __u16);
    __type(value, struct geo_action);
} jzap_geo_filter SEC(".maps");

/* -------------------------------------------------------------------------
 * Maps — SYN cookie tracking (per-IP handshake validation)
 * Key: source IPv4 (u32), Value: syn_cookie_state
 * ------------------------------------------------------------------------- */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SYN_COOKIE_ENTRIES);
    __type(key, __u32);
    __type(value, struct syn_cookie_state);
} jzap_syn_cookies SEC(".maps");

/* -------------------------------------------------------------------------
 * Maps — Amplification tracking (per-IP query/response ratio)
 * Key: source IPv4 (u32), Value: amplification_entry
 * ------------------------------------------------------------------------- */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_AMPLIFICATION_ENTRIES);
    __type(key, __u32);
    __type(value, struct amplification_entry);
} jzap_amplification SEC(".maps");

/* -------------------------------------------------------------------------
 * Maps — Traffic baseline (aggregate stats per window, index 0 = current)
 * Key: u32 index, Value: traffic_stats
 * ------------------------------------------------------------------------- */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, struct traffic_stats);
} jzap_traffic_baseline SEC(".maps");

/* -------------------------------------------------------------------------
 * Config parameter IDs
 * ------------------------------------------------------------------------- */
#define CFG_PPS_LIMIT               0
#define CFG_UDP_PPS_LIMIT           1
#define CFG_ICMP_PPS_LIMIT          2
#define CFG_SYN_PPS_LIMIT           3
#define CFG_ENABLE_GEO_FILTER       4
#define CFG_AMPLIFICATION_THRESHOLD 5
#define CFG_SYN_COOKIE_SECRET       6
#define CFG_BASELINE_WINDOW_SEC     7

/* -------------------------------------------------------------------------
 * Metrics IDs
 * ------------------------------------------------------------------------- */
#define METRIC_TOTAL_PACKETS          0
#define METRIC_DROPPED_BLOCKLIST      1
#define METRIC_DROPPED_RATELIMIT      2
#define METRIC_DROPPED_SYN            3
#define METRIC_DROPPED_UDP            4
#define METRIC_DROPPED_ICMP           5
#define METRIC_DROPPED_GEO            6
#define METRIC_PASSED                 7
#define METRIC_DROPPED_AMPLIFICATION  8
#define METRIC_SYN_COOKIES_ISSUED     9
#define METRIC_SYN_COOKIES_VALIDATED  10
#define METRIC_TOTAL_BYTES            11

/* -------------------------------------------------------------------------
 * Helper: Increment a per-CPU metric counter by 1
 * ------------------------------------------------------------------------- */
static __always_inline void metric_inc(__u32 metric_id)
{
    __u64 *val = bpf_map_lookup_elem(&jzap_metrics, &metric_id);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

/* -------------------------------------------------------------------------
 * Helper: Add a value to a per-CPU metric counter
 * ------------------------------------------------------------------------- */
static __always_inline void metric_add(__u32 metric_id, __u64 add_val)
{
    __u64 *val = bpf_map_lookup_elem(&jzap_metrics, &metric_id);
    if (val) {
        __sync_fetch_and_add(val, add_val);
    }
}

/* -------------------------------------------------------------------------
 * Helper: Get config value with default fallback
 * ------------------------------------------------------------------------- */
static __always_inline __u64 get_config(__u32 key, __u64 default_val)
{
    __u64 *val = bpf_map_lookup_elem(&jzap_config, &key);
    if (val) {
        return *val;
    }
    return default_val;
}

/* -------------------------------------------------------------------------
 * Helper: Simple SYN cookie hash using XOR and bit rotation
 * Produces a pseudo-random cookie from source IP + secret for SYN
 * validation. Not cryptographic — sufficient for XDP-level filtering.
 * ------------------------------------------------------------------------- */
static __always_inline __u32 simple_hash(__u32 ip, __u64 secret)
{
    __u32 h = ip ^ (__u32)secret ^ (__u32)(secret >> 32);
    /* Bit rotation mix */
    h = ((h << 13) | (h >> 19)) ^ (h * 0x5bd1e995);
    h ^= h >> 15;
    h = ((h << 7) | (h >> 25)) ^ (h * 0x1b873593);
    h ^= h >> 13;
    return h;
}

#endif /* JZAP_EBPF_COMMON_H */
