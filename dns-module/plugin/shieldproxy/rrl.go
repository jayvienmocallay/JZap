package shieldproxy

import (
	"sync"
	"time"
)

// RRLChecker implements Response Rate Limiting for DNS.
// It tracks per-source-IP response counts within a sliding window and decides
// whether to allow, slip (truncate), or drop responses.
type RRLChecker struct {
	config  RRLConfig
	mu      sync.Mutex
	counts  map[string]*sourceCounter
	window  time.Time
}

// sourceCounter tracks response counts for a single source IP.
type sourceCounter struct {
	// Total responses sent to this source IP in the current window.
	responses int

	// NXDOMAIN responses sent to this source IP in the current window.
	nxdomains int

	// Number of times this source was slipped (sent truncated) in the current window.
	slips int
}

// NewRRLChecker creates a new RRL checker with the given configuration.
func NewRRLChecker(config RRLConfig) *RRLChecker {
	return &RRLChecker{
		config: config,
		counts: make(map[string]*sourceCounter),
		window: time.Now(),
	}
}

// CheckRRL determines whether a response to the given source IP should be allowed.
//
// Returns:
//   - allow: true if the response should be sent normally
//   - slip: true if the response should be sent truncated (TC bit set)
//
// If both allow and slip are false, the response should be dropped entirely.
//
// TODO (Phase 4): Full implementation with:
//   - Redis-backed distributed counters for multi-node deployments
//   - Per-query-type rate limiting (separate limits for ANY, NXDOMAIN, etc.)
//   - Configurable exemptions for known-good resolvers
//   - Exponential backoff for repeat offenders
func (r *RRLChecker) CheckRRL(sourceIP string) (allow bool, slip bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if the current window has expired and reset if needed
	elapsed := time.Since(r.window).Seconds()
	if elapsed >= float64(r.config.WindowSeconds) {
		r.resetCountersLocked()
	}

	// Get or create counter for this source IP
	counter, exists := r.counts[sourceIP]
	if !exists {
		counter = &sourceCounter{}
		r.counts[sourceIP] = counter
	}

	// Increment response count
	counter.responses++

	// If under the limit, allow normally
	if counter.responses <= r.config.ResponsesPerSecond {
		return true, false
	}

	// Over the limit — decide whether to slip or drop.
	// SlipRatio determines the fraction of over-limit responses that get
	// a truncated reply (TC bit) instead of being silently dropped.
	// A SlipRatio of 2.0 means 1 in 2 over-limit responses are slipped.
	if r.config.SlipRatio > 0 {
		counter.slips++
		if float64(counter.slips) <= float64(counter.responses-r.config.ResponsesPerSecond)/r.config.SlipRatio {
			return false, true // slip: send truncated
		}
	}

	// Drop the response entirely
	return false, false
}

// CheckNXDomainFlood checks if the source IP has exceeded the NXDOMAIN threshold.
//
// TODO (Phase 4): Implement with Redis-backed counters:
//   - INCR nxdomain:<sourceIP> with TTL = WindowSeconds
//   - Compare against NXDomainThreshold
//   - Return true if flood detected
func (r *RRLChecker) CheckNXDomainFlood(sourceIP string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	counter, exists := r.counts[sourceIP]
	if !exists {
		return false
	}

	return counter.nxdomains >= r.config.NXDomainThreshold
}

// IncrementNXDomain increments the NXDOMAIN counter for a source IP.
func (r *RRLChecker) IncrementNXDomain(sourceIP string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	counter, exists := r.counts[sourceIP]
	if !exists {
		counter = &sourceCounter{}
		r.counts[sourceIP] = counter
	}

	counter.nxdomains++
}

// ResetCounters clears all per-source-IP counters and resets the window.
// This is called when the rate limiting window expires.
func (r *RRLChecker) ResetCounters() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resetCountersLocked()
}

// resetCountersLocked resets counters while the lock is already held.
func (r *RRLChecker) resetCountersLocked() {
	r.counts = make(map[string]*sourceCounter)
	r.window = time.Now()
}
