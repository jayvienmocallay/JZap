/* ===========================================================================
 * JZap (ShieldProxy) — XDP IP Blocklist Program
 * FR-L3-05: Load and enforce IP blocklist at NIC driver level (XDP_DROP)
 * Drops packets from blocked IPs before they reach the kernel network stack.
 *
 * Supports:
 *   - IPv4 blocklist lookup (full 32-bit address)
 *   - IPv6 blocklist lookup (first 4 bytes of saddr as key — v1 simplification)
 *   - Per-blocked-IP hit counters for telemetry/dashboard
 *   - Packet length validation
 * =========================================================================== */

#include "common.h"

/* -------------------------------------------------------------------------
 * Per-blocked-IP hit counter map (per-CPU for lock-free updates)
 * Key: IPv4 address (u32), Value: hit count (u64)
 * ------------------------------------------------------------------------- */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_BLOCKLIST_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} jzap_blocklist_hits SEC(".maps");

/* -------------------------------------------------------------------------
 * Helper: Record a blocklist hit for telemetry
 * ------------------------------------------------------------------------- */
static __always_inline void record_blocklist_hit(__u32 ip)
{
    __u64 *count = bpf_map_lookup_elem(&jzap_blocklist_hits, &ip);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&jzap_blocklist_hits, &ip, &init, BPF_NOEXIST);
    }
}

SEC("xdp")
int jzap_blocklist_prog(struct xdp_md *ctx)
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

    __u16 eth_proto = eth->h_proto;
    __u32 src_ip    = 0;

    /* -----------------------------------------------------------------
     * Parse IPv4 header
     * ----------------------------------------------------------------- */
    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end) {
            return XDP_PASS;
        }

        /* Validate IP header length (IHL >= 5, i.e. 20 bytes minimum) */
        if (iph->ihl < 5) {
            return XDP_DROP;
        }

        /* Validate total packet length doesn't exceed captured data.
         * bpf_ntohs(iph->tot_len) is the IP-level total length;
         * ensure the Ethernet frame actually contains that many bytes. */
        if ((void *)iph + bpf_ntohs(iph->tot_len) > data_end) {
            return XDP_DROP;
        }

        src_ip = iph->saddr;

    /* -----------------------------------------------------------------
     * Parse IPv6 header
     * TODO: Full IPv6 support — currently uses first 4 bytes of saddr
     *       as the blocklist key. This is a v1 simplification; a proper
     *       implementation should use a 128-bit key or prefix-based LPM.
     * ----------------------------------------------------------------- */
    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end) {
            return XDP_PASS;
        }

        /* Use first 4 bytes of the 128-bit IPv6 source address as key.
         * This groups all addresses under the same /32 prefix together,
         * which is acceptable for v1 since most IPv6 DDoS traffic shares
         * a common high-order prefix. */
        src_ip = ip6h->saddr.in6_u.u6_addr32[0];

    } else {
        /* Not IPv4 or IPv6 — pass through */
        return XDP_PASS;
    }

    /* -----------------------------------------------------------------
     * Blocklist lookup — O(1) hash map lookup
     * ----------------------------------------------------------------- */
    __u8 *blocked = bpf_map_lookup_elem(&jzap_blocklist, &src_ip);
    if (blocked) {
        record_blocklist_hit(src_ip);
        metric_inc(METRIC_DROPPED_BLOCKLIST);
        return XDP_DROP;  /* Zero-copy drop at NIC level */
    }

    metric_inc(METRIC_PASSED);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
