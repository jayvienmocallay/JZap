package shieldproxy

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
)

// Name returns the plugin name for CoreDNS.
func (p *Plugin) Name() string {
	return "shieldproxy"
}

// ServeDNS handles incoming DNS requests with DDoS mitigation checks.
func (p *Plugin) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	start := time.Now()

	// Increment total query counter
	p.Metrics.QueriesTotal.Inc()

	// Extract source IP from the remote address
	sourceIP, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		sourceIP = w.RemoteAddr().String()
	}

	// --- Step 1: Response Rate Limiting (RRL) ---
	// Check if this source IP has exceeded the response rate limit.
	// RRL prevents DNS amplification attacks by limiting how many identical
	// responses are sent to the same source IP within a time window.
	rrlChecker := NewRRLChecker(p.RRL)
	allow, slip := rrlChecker.CheckRRL(sourceIP)

	if !allow {
		if slip {
			// Send a truncated response (TC bit set) to prompt legitimate clients
			// to retry over TCP, while rate-limiting amplification.
			p.Metrics.RRLSlipped.Inc()
			truncated := new(dns.Msg)
			truncated.SetReply(r)
			truncated.Truncated = true
			if writeErr := w.WriteMsg(truncated); writeErr != nil {
				return dns.RcodeServerFailure, writeErr
			}
			return dns.RcodeSuccess, nil
		}

		// Drop the query entirely — do not respond.
		p.Metrics.RRLDropped.Inc()
		return dns.RcodeSuccess, nil
	}

	// --- Step 2: NXDOMAIN Flood Detection ---
	// TODO (Phase 4): Implement NXDOMAIN flood detection.
	// Track per-source-IP NXDOMAIN response counts. If a source IP triggers
	// more than NXDomainThreshold NXDOMAIN responses within the window,
	// temporarily block that source from receiving NXDOMAIN answers.
	//
	// Implementation plan:
	//   1. After upstream resolution, check if rcode == NXDOMAIN
	//   2. Increment per-IP NXDOMAIN counter in Redis
	//   3. If counter > threshold, block or return REFUSED
	//   4. Use sliding window or fixed window in Redis with TTL

	// --- Step 3: Forward to next handler (upstream resolution) ---
	// TODO (Phase 4): Implement upstream forwarding.
	// For now, return SERVFAIL as a placeholder.
	//
	// In production, this would:
	//   1. Forward the query to the configured upstream DNS resolver
	//   2. Cache the response according to TTL
	//   3. Apply post-resolution checks (NXDOMAIN flood, response size limits)
	//   4. Return the response to the client

	if p.Next != nil {
		// Delegate to the next plugin in the chain
		rcode, nextErr := p.Next.ServeDNS(ctx, w, r)
		p.recordDuration(start)
		return rcode, nextErr
	}

	// No next handler — return SERVFAIL
	resp := new(dns.Msg)
	resp.SetRcode(r, dns.RcodeServerFailure)
	if writeErr := w.WriteMsg(resp); writeErr != nil {
		return dns.RcodeServerFailure, writeErr
	}

	// --- Step 4: Record query metrics ---
	p.recordDuration(start)

	// TODO (Phase 4): Log structured query metadata for analytics:
	//   - source IP, query name, query type, rcode, response size, latency
	//   - Push to traffic_events TimescaleDB table via async pipeline

	return dns.RcodeServerFailure, nil
}

// recordDuration observes the query processing duration in the histogram.
func (p *Plugin) recordDuration(start time.Time) {
	elapsed := time.Since(start).Seconds()
	p.Metrics.QueryDuration.Observe(elapsed)
}
