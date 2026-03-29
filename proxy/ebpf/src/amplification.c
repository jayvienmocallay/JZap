/* ===========================================================================
 * JZap (ShieldProxy) — XDP Reflection/Amplification Defense
 * FR-L3-04: Detect and drop amplification/reflection attack traffic
 *
 * Detects known amplification vectors:
 *   - DNS responses      (UDP port 53)
 *   - NTP monlist        (UDP port 123)
 *   - SSDP               (UDP port 1900)
 *   - Memcached          (UDP port 11211)
 *   - CHARGEN            (UDP port 19)
 *
 * For each vector, tracks per-source-IP query_count and response_bytes.
 * If the response_bytes / query_count ratio exceeds the configured
 * amplification threshold, the packet is dropped at XDP level.
 * =========================================================================== */

#include "common.h"

/* Well-known amplification source ports */
#define PORT_DNS       53
#define PORT_NTP       123
#define PORT_SSDP      1900
#define PORT_MEMCACHED 11211
#define PORT_CHARGEN   19

/* -------------------------------------------------------------------------
 * Helper: Check if a UDP source port is a known amplification vector.
 * Returns 1 if the port matches a known reflector, 0 otherwise.
 * ------------------------------------------------------------------------- */
static __always_inline int is_amplification_port(__u16 sport)
{
    switch (sport) {
    case PORT_DNS:
    case PORT_NTP:
    case PORT_SSDP:
    case PORT_MEMCACHED:
    case PORT_CHARGEN:
        return 1;
    default:
        return 0;
    }
}

SEC("xdp")
int jzap_amplification_prog(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    metric_inc(METRIC_TOTAL_PACKETS);

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

    /* Only inspect UDP packets for amplification vectors */
    if (iph->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    /* -----------------------------------------------------------------
     * Parse UDP header
     * ----------------------------------------------------------------- */
    struct udphdr *udph = (void *)iph + (iph->ihl * 4);
    if ((void *)(udph + 1) > data_end) {
        return XDP_PASS;
    }

    __u16 sport   = bpf_ntohs(udph->source);
    __u32 src_ip  = iph->saddr;
    __u16 udp_len = bpf_ntohs(udph->len);

    /* -----------------------------------------------------------------
     * Check if source port matches a known amplification vector.
     * Amplification attacks use spoofed source IPs, so the "source"
     * of the response is the reflector. We track by our packet's
     * source IP (the reflector / spoofed victim origin).
     * ----------------------------------------------------------------- */
    if (!is_amplification_port(sport)) {
        return XDP_PASS;
    }

    /* -----------------------------------------------------------------
     * Track per-source-IP amplification ratio
     * ----------------------------------------------------------------- */
    __u64 now = bpf_ktime_get_ns();
    __u64 threshold = get_config(CFG_AMPLIFICATION_THRESHOLD,
                                 DEFAULT_AMPLIFICATION_RATIO);

    struct amplification_entry *entry;
    entry = bpf_map_lookup_elem(&jzap_amplification, &src_ip);

    if (entry) {
        /* Check if we need to reset the window (1 second window) */
        if ((now - entry->window_start) >= RATE_LIMIT_WINDOW_NS) {
            entry->query_count   = 1;
            entry->response_bytes = udp_len;
            entry->window_start  = now;
            return XDP_PASS;
        }

        entry->query_count++;
        entry->response_bytes += udp_len;

        /* Calculate amplification ratio.
         * If average response size per query exceeds threshold * typical
         * small query size (~64 bytes), this is likely amplification. */
        if (entry->query_count > 0) {
            __u64 avg_response = entry->response_bytes / entry->query_count;
            if (avg_response > (threshold * 64)) {
                metric_inc(METRIC_DROPPED_AMPLIFICATION);
                return XDP_DROP;
            }
        }

        return XDP_PASS;
    }

    /* First packet from this source — create tracking entry */
    struct amplification_entry new_entry = {
        .query_count   = 1,
        .response_bytes = udp_len,
        .window_start  = now,
    };
    bpf_map_update_elem(&jzap_amplification, &src_ip, &new_entry, BPF_ANY);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
