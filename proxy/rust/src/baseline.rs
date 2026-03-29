//! Traffic baseline learning and N-sigma anomaly detection.
//!
//! Maintains a rolling window of traffic statistics read from eBPF maps,
//! computes mean and standard deviation, and emits anomaly events when
//! current traffic deviates by more than N standard deviations.

use std::collections::VecDeque;
use std::sync::Arc;

use anyhow::Result;
use jzap_ebpf_loader::EbpfManager;
use jzap_shared::{AnomalyEvent, AnomalySeverity, TrafficBaseline, XdpMetricsSnapshot};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

/// Maximum number of samples to retain for baseline computation.
const MAX_BASELINE_SAMPLES: usize = 120;

/// Maintains rolling traffic statistics and detects anomalies.
pub struct BaselineEngine {
    /// Rolling window of (timestamp, packets_per_interval, bytes_per_interval).
    samples: VecDeque<Sample>,

    /// N-sigma threshold for anomaly detection.
    sigma_threshold: f64,

    /// Critical threshold multiplier (e.g., 2x the sigma_threshold).
    critical_multiplier: f64,
}

#[derive(Debug, Clone)]
struct Sample {
    timestamp: u64,
    packets: u64,
    bytes: u64,
}

impl BaselineEngine {
    /// Create a new baseline engine.
    ///
    /// - `sigma_threshold`: number of standard deviations before warning
    /// - `critical_multiplier`: multiplied by sigma_threshold for critical severity
    pub fn new(sigma_threshold: f64, critical_multiplier: f64) -> Self {
        info!(
            sigma_threshold,
            critical_multiplier,
            "BaselineEngine created"
        );
        Self {
            samples: VecDeque::with_capacity(MAX_BASELINE_SAMPLES),
            sigma_threshold,
            critical_multiplier,
        }
    }

    /// Record a new traffic sample and check for anomalies.
    /// Returns a list of anomaly events (may be empty).
    pub fn record_and_check(
        &mut self,
        snapshot: &XdpMetricsSnapshot,
        prev_snapshot: &XdpMetricsSnapshot,
    ) -> Vec<AnomalyEvent> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Compute delta from previous snapshot (rate per interval).
        let delta_packets = snapshot.total_packets.saturating_sub(prev_snapshot.total_packets);
        let delta_bytes = snapshot.total_bytes.saturating_sub(prev_snapshot.total_bytes);

        let sample = Sample {
            timestamp: now,
            packets: delta_packets,
            bytes: delta_bytes,
        };

        self.samples.push_back(sample.clone());
        if self.samples.len() > MAX_BASELINE_SAMPLES {
            self.samples.pop_front();
        }

        // Need at least 10 samples to compute meaningful statistics.
        if self.samples.len() < 10 {
            debug!(
                samples = self.samples.len(),
                "insufficient samples for baseline (need 10)"
            );
            return Vec::new();
        }

        let baseline = self.compute_baseline();
        let mut events = Vec::new();

        // Check packets per interval.
        if baseline.stddev_pps > 0.0 {
            let sigma = (delta_packets as f64 - baseline.mean_pps) / baseline.stddev_pps;
            if sigma > self.sigma_threshold * self.critical_multiplier {
                events.push(AnomalyEvent {
                    timestamp: now,
                    metric_name: "packets_per_interval".into(),
                    current_value: delta_packets as f64,
                    baseline_mean: baseline.mean_pps,
                    baseline_stddev: baseline.stddev_pps,
                    sigma_deviation: sigma,
                    severity: AnomalySeverity::Critical,
                });
            } else if sigma > self.sigma_threshold {
                events.push(AnomalyEvent {
                    timestamp: now,
                    metric_name: "packets_per_interval".into(),
                    current_value: delta_packets as f64,
                    baseline_mean: baseline.mean_pps,
                    baseline_stddev: baseline.stddev_pps,
                    sigma_deviation: sigma,
                    severity: AnomalySeverity::Warning,
                });
            }
        }

        // Check bytes per interval.
        if baseline.stddev_bps > 0.0 {
            let sigma = (delta_bytes as f64 - baseline.mean_bps) / baseline.stddev_bps;
            if sigma > self.sigma_threshold * self.critical_multiplier {
                events.push(AnomalyEvent {
                    timestamp: now,
                    metric_name: "bytes_per_interval".into(),
                    current_value: delta_bytes as f64,
                    baseline_mean: baseline.mean_bps,
                    baseline_stddev: baseline.stddev_bps,
                    sigma_deviation: sigma,
                    severity: AnomalySeverity::Critical,
                });
            } else if sigma > self.sigma_threshold {
                events.push(AnomalyEvent {
                    timestamp: now,
                    metric_name: "bytes_per_interval".into(),
                    current_value: delta_bytes as f64,
                    baseline_mean: baseline.mean_bps,
                    baseline_stddev: baseline.stddev_bps,
                    sigma_deviation: sigma,
                    severity: AnomalySeverity::Warning,
                });
            }
        }

        events
    }

    /// Compute the current baseline (mean + stddev) from the sample window.
    pub fn compute_baseline(&self) -> TrafficBaseline {
        let n = self.samples.len() as f64;
        if n < 2.0 {
            return TrafficBaseline::default();
        }

        let sum_pps: f64 = self.samples.iter().map(|s| s.packets as f64).sum();
        let sum_bps: f64 = self.samples.iter().map(|s| s.bytes as f64).sum();

        let mean_pps = sum_pps / n;
        let mean_bps = sum_bps / n;

        let var_pps: f64 = self
            .samples
            .iter()
            .map(|s| (s.packets as f64 - mean_pps).powi(2))
            .sum::<f64>()
            / (n - 1.0);
        let var_bps: f64 = self
            .samples
            .iter()
            .map(|s| (s.bytes as f64 - mean_bps).powi(2))
            .sum::<f64>()
            / (n - 1.0);

        TrafficBaseline {
            mean_pps,
            stddev_pps: var_pps.sqrt(),
            mean_bps,
            stddev_bps: var_bps.sqrt(),
            sample_count: self.samples.len() as u64,
        }
    }

    /// Get the current number of samples in the window.
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }
}

/// Background task that periodically reads metrics, feeds them to the baseline
/// engine, and broadcasts anomaly events.
pub async fn baseline_monitoring_loop(
    ebpf: Arc<EbpfManager>,
    sigma_threshold: f64,
    interval_secs: u64,
    anomaly_tx: broadcast::Sender<AnomalyEvent>,
) {
    use jzap_ebpf_loader::XdpProgram;

    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
    let mut engine = BaselineEngine::new(sigma_threshold, 2.0);
    let mut prev_snapshot = XdpMetricsSnapshot::default();

    info!(
        sigma_threshold,
        interval_secs,
        "starting baseline monitoring loop"
    );

    loop {
        interval.tick().await;

        let snapshot = match ebpf.read_metrics(XdpProgram::Blocklist) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "failed to read metrics for baseline");
                continue;
            }
        };

        let events = engine.record_and_check(&snapshot, &prev_snapshot);

        for event in &events {
            match event.severity {
                AnomalySeverity::Warning => {
                    warn!(
                        metric = %event.metric_name,
                        current = event.current_value,
                        mean = event.baseline_mean,
                        sigma = event.sigma_deviation,
                        "traffic anomaly DETECTED (WARNING)"
                    );
                }
                AnomalySeverity::Critical => {
                    error!(
                        metric = %event.metric_name,
                        current = event.current_value,
                        mean = event.baseline_mean,
                        sigma = event.sigma_deviation,
                        "traffic anomaly DETECTED (CRITICAL)"
                    );
                }
            }

            // Broadcast to any listeners (e.g., traffic logger, future alert system).
            let _ = anomaly_tx.send(event.clone());
        }

        prev_snapshot = snapshot;
    }
}
