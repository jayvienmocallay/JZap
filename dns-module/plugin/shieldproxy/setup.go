package shieldproxy

import (
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
)

// RRLConfig holds Response Rate Limiting configuration.
type RRLConfig struct {
	// ResponsesPerSecond is the maximum number of identical responses per source IP per window.
	ResponsesPerSecond int

	// WindowSeconds is the time window in seconds for rate limiting.
	WindowSeconds int

	// SlipRatio controls truncated response ratio (1 in N responses are sent truncated instead of dropped).
	SlipRatio float64

	// NXDomainThreshold is the max NXDOMAIN responses per source IP before triggering flood detection.
	NXDomainThreshold int
}

// Metrics holds Prometheus metrics for the shieldproxy plugin.
type Metrics struct {
	QueriesTotal    prometheus.Counter
	BlockedTotal    prometheus.Counter
	RRLDropped      prometheus.Counter
	RRLSlipped      prometheus.Counter
	NXDomainFloods  prometheus.Counter
	QueryDuration   prometheus.Histogram
}

// Plugin is the main shieldproxy CoreDNS plugin struct.
type Plugin struct {
	// RedisClient is used for distributed rate limiting state.
	RedisClient *redis.Client

	// RRL holds the Response Rate Limiting configuration.
	RRL RRLConfig

	// Metrics holds Prometheus metrics collectors.
	Metrics *Metrics

	// Next is the next DNS handler in the CoreDNS plugin chain.
	Next dns.Handler
}

// init registers the shieldproxy plugin with CoreDNS.
// In a full CoreDNS plugin build, this would call:
//   caddy.RegisterPlugin("shieldproxy", caddy.Plugin{
//       ServerType: "dns",
//       Action:     setup,
//   })
// For now this is a stub — the plugin is registered when built as part of CoreDNS.
func init() {
	// TODO: CoreDNS plugin registration — requires CoreDNS build integration
}

// NewMetrics creates and registers Prometheus metrics for the plugin.
func NewMetrics() *Metrics {
	m := &Metrics{
		QueriesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "jzap",
			Subsystem: "dns",
			Name:      "queries_total",
			Help:      "Total number of DNS queries processed.",
		}),
		BlockedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "jzap",
			Subsystem: "dns",
			Name:      "blocked_total",
			Help:      "Total number of DNS queries blocked.",
		}),
		RRLDropped: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "jzap",
			Subsystem: "dns",
			Name:      "rrl_dropped_total",
			Help:      "Total number of responses dropped by RRL.",
		}),
		RRLSlipped: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "jzap",
			Subsystem: "dns",
			Name:      "rrl_slipped_total",
			Help:      "Total number of responses sent truncated (slipped) by RRL.",
		}),
		NXDomainFloods: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "jzap",
			Subsystem: "dns",
			Name:      "nxdomain_floods_total",
			Help:      "Total number of NXDOMAIN flood events detected.",
		}),
		QueryDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "jzap",
			Subsystem: "dns",
			Name:      "query_duration_seconds",
			Help:      "Histogram of DNS query processing duration.",
			Buckets:   prometheus.DefBuckets,
		}),
	}

	prometheus.MustRegister(m.QueriesTotal, m.BlockedTotal, m.RRLDropped,
		m.RRLSlipped, m.NXDomainFloods, m.QueryDuration)

	return m
}

// Setup reads the shieldproxy configuration block and returns a configured Plugin.
// In CoreDNS, this is called during server startup.
func Setup(redisAddr string, rrlConfig RRLConfig) (*Plugin, error) {
	// Initialize Redis client for distributed state
	rdb := redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})

	metrics := NewMetrics()

	p := &Plugin{
		RedisClient: rdb,
		RRL:         rrlConfig,
		Metrics:     metrics,
	}

	return p, nil
}
