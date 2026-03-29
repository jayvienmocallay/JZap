package telemetry

import (
	"context"
	"log"
	"time"
)

// TelemetryData represents a snapshot of local metrics to be sent to the
// control plane.
type TelemetryData struct {
	Timestamp        time.Time          `json:"timestamp"`
	ConnectionCounts map[string]uint64  `json:"connection_counts"`
	RequestRates     map[string]float64 `json:"request_rates"`
	DropCounts       map[string]uint64  `json:"drop_counts"`
}

// Reporter periodically collects local metrics and sends them to the control
// plane via gRPC.
type Reporter struct {
	controlPlaneURL string
	interval        time.Duration
}

// New creates a new telemetry Reporter.
func New(controlPlaneURL string, interval time.Duration) *Reporter {
	return &Reporter{
		controlPlaneURL: controlPlaneURL,
		interval:        interval,
	}
}

// Start runs the telemetry reporting loop. It blocks until the context is
// cancelled.
func (r *Reporter) Start(ctx context.Context) {
	log.Printf("telemetry: starting reporter (interval=%s, target=%s)", r.interval, r.controlPlaneURL)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("telemetry: stopping reporter")
			return
		case <-ticker.C:
			data := r.collectMetrics()
			if err := r.send(ctx, data); err != nil {
				log.Printf("telemetry: failed to send metrics: %v", err)
			}
		}
	}
}

// collectMetrics gathers per-IP connection counts, request rates, and drop
// counts from local sources (nftables counters, conntrack, etc.).
func (r *Reporter) collectMetrics() *TelemetryData {
	// TODO: read actual counters from nftables / conntrack / proc filesystem.
	// Returning stub data for now.
	data := &TelemetryData{
		Timestamp:        time.Now().UTC(),
		ConnectionCounts: make(map[string]uint64),
		RequestRates:     make(map[string]float64),
		DropCounts:       make(map[string]uint64),
	}

	log.Printf("telemetry: collected metrics at %s", data.Timestamp.Format(time.RFC3339))
	return data
}

// send transmits the telemetry data to the control plane via gRPC.
func (r *Reporter) send(ctx context.Context, data *TelemetryData) error {
	// TODO: establish a gRPC connection to the control plane and send the
	// TelemetryData using the JZap telemetry service proto.
	//
	// For now we just log the action as a stub.
	log.Printf("telemetry: would send %d connection counts, %d request rates, %d drop counts to %s",
		len(data.ConnectionCounts),
		len(data.RequestRates),
		len(data.DropCounts),
		r.controlPlaneURL,
	)
	return nil
}
