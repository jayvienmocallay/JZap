//! Structured traffic logging pipeline.
//!
//! Periodically logs traffic statistics (total packets, drops by reason, pass
//! rate) in structured JSON format to stdout. Also logs anomaly events when
//! they are received from the baseline monitoring system.

use std::sync::Arc;

use jzap_ebpf_loader::{EbpfManager, XdpProgram};
use jzap_shared::{AnomalyEvent, DroppedBreakdown, TrafficLogEntry, XdpMetricsSnapshot};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

/// Background task that periodically reads eBPF metrics and logs traffic
/// statistics as structured JSON.
pub async fn traffic_logging_loop(
    ebpf: Arc<EbpfManager>,
    interval_secs: u64,
    mut anomaly_rx: broadcast::Receiver<AnomalyEvent>,
) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
    let mut prev_snapshot = XdpMetricsSnapshot::default();

    info!(interval_secs, "starting traffic logging loop");

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let snapshot = match ebpf.read_metrics(XdpProgram::Blocklist) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(error = %e, "failed to read metrics for traffic log");
                        continue;
                    }
                };

                let entry = build_log_entry(&snapshot, &prev_snapshot);
                prev_snapshot = snapshot;

                // Emit as structured JSON log line.
                match serde_json::to_string(&entry) {
                    Ok(json) => {
                        info!(
                            target: "jzap::traffic",
                            traffic_log = %json,
                            "traffic stats"
                        );
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to serialize traffic log entry");
                    }
                }
            }

            event = anomaly_rx.recv() => {
                match event {
                    Ok(anomaly) => {
                        match serde_json::to_string(&anomaly) {
                            Ok(json) => {
                                info!(
                                    target: "jzap::anomaly",
                                    anomaly_event = %json,
                                    severity = ?anomaly.severity,
                                    "anomaly detected"
                                );
                            }
                            Err(e) => {
                                warn!(error = %e, "failed to serialize anomaly event");
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(skipped = n, "anomaly event receiver lagged");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        info!("anomaly event channel closed — logging anomalies stopped");
                        // Continue logging traffic stats without anomaly events.
                    }
                }
            }
        }
    }
}

/// Build a traffic log entry from the delta between two snapshots.
fn build_log_entry(
    current: &XdpMetricsSnapshot,
    prev: &XdpMetricsSnapshot,
) -> TrafficLogEntry {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let total_packets = current.total_packets.saturating_sub(prev.total_packets);
    let total_bytes = current.total_bytes.saturating_sub(prev.total_bytes);
    let passed = current.passed.saturating_sub(prev.passed);

    let breakdown = DroppedBreakdown {
        blocklist: current.dropped_blocklist.saturating_sub(prev.dropped_blocklist),
        ratelimit: current.dropped_ratelimit.saturating_sub(prev.dropped_ratelimit),
        syn_flood: current.dropped_syn.saturating_sub(prev.dropped_syn),
        udp_flood: current.dropped_udp.saturating_sub(prev.dropped_udp),
        icmp_flood: current.dropped_icmp.saturating_sub(prev.dropped_icmp),
        geo_filter: current.dropped_geo.saturating_sub(prev.dropped_geo),
        amplification: current.dropped_amplification.saturating_sub(prev.dropped_amplification),
    };

    let dropped_total = breakdown.blocklist
        + breakdown.ratelimit
        + breakdown.syn_flood
        + breakdown.udp_flood
        + breakdown.icmp_flood
        + breakdown.geo_filter
        + breakdown.amplification;

    TrafficLogEntry {
        timestamp: now,
        total_packets,
        total_bytes,
        dropped_total,
        passed,
        dropped_breakdown: breakdown,
    }
}
