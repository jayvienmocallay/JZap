//! Prometheus metrics exporter for eBPF/XDP counters.
//!
//! Periodically reads per-CPU metrics from the eBPF maps (via EbpfManager),
//! updates Prometheus gauges, and serves `/metrics` over HTTP.

use std::sync::Arc;

use anyhow::Result;
use jzap_ebpf_loader::{EbpfManager, XdpProgram};
use jzap_shared::ebpf_metrics;
use prometheus::{Encoder, GaugeVec, Opts, Registry, TextEncoder};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Holds all Prometheus metric handles for the XDP layer.
pub struct XdpPrometheusMetrics {
    registry: Registry,
    xdp_counters: GaugeVec,
}

impl XdpPrometheusMetrics {
    /// Create a new metrics registry with XDP gauges pre-registered.
    pub fn new() -> Result<Self> {
        let registry = Registry::new();

        let xdp_counters = GaugeVec::new(
            Opts::new("jzap_xdp_packets", "XDP packet counters by action/reason"),
            &["metric"],
        )?;
        registry.register(Box::new(xdp_counters.clone()))?;

        Ok(Self {
            registry,
            xdp_counters,
        })
    }

    /// Update gauges from a fresh metrics read.
    pub fn update_from_snapshot(&self, snapshot: &jzap_shared::XdpMetricsSnapshot) {
        let values = [
            ("total_packets", snapshot.total_packets),
            ("dropped_blocklist", snapshot.dropped_blocklist),
            ("dropped_ratelimit", snapshot.dropped_ratelimit),
            ("dropped_syn_flood", snapshot.dropped_syn),
            ("dropped_udp_flood", snapshot.dropped_udp),
            ("dropped_icmp_flood", snapshot.dropped_icmp),
            ("dropped_geo_filter", snapshot.dropped_geo),
            ("passed", snapshot.passed),
            ("dropped_amplification", snapshot.dropped_amplification),
            ("syn_cookies_issued", snapshot.syn_cookies_issued),
            ("syn_cookies_validated", snapshot.syn_cookies_validated),
            ("total_bytes", snapshot.total_bytes),
        ];

        for (label, value) in &values {
            self.xdp_counters
                .with_label_values(&[label])
                .set(*value as f64);
        }
    }

    /// Render all metrics in Prometheus text format.
    pub fn render(&self) -> Result<String> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }
}

/// Background task that periodically reads eBPF metrics and updates Prometheus gauges.
pub async fn metrics_collection_loop(
    ebpf: Arc<EbpfManager>,
    prom: Arc<XdpPrometheusMetrics>,
    interval_secs: u64,
) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
    info!(interval_secs, "starting eBPF metrics collection loop");

    loop {
        interval.tick().await;

        // Read metrics from all loaded programs. The blocklist program has the
        // main metrics map; other programs share maps when using tail calls or
        // we can read from each independently.
        match ebpf.read_metrics(XdpProgram::Blocklist) {
            Ok(snapshot) => {
                prom.update_from_snapshot(&snapshot);
                debug!(
                    total = snapshot.total_packets,
                    passed = snapshot.passed,
                    "metrics snapshot updated"
                );
            }
            Err(e) => {
                warn!(error = %e, "failed to read eBPF metrics");
            }
        }
    }
}

/// Serve Prometheus metrics on the given port.
/// Handles GET /metrics requests and returns text/plain Prometheus format.
pub async fn serve_metrics_http(
    prom: Arc<XdpPrometheusMetrics>,
    port: u16,
) -> Result<()> {
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    info!(addr = %addr, "Prometheus metrics HTTP server listening");

    loop {
        let (stream, _peer) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let prom = prom.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                let prom = prom.clone();
                async move {
                    if req.uri().path() == "/metrics" {
                        match prom.render() {
                            Ok(body) => {
                                let resp = Response::builder()
                                    .status(StatusCode::OK)
                                    .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
                                    .body(Full::new(Bytes::from(body)))
                                    .unwrap();
                                Ok::<_, hyper::Error>(resp)
                            }
                            Err(_) => {
                                let resp = Response::builder()
                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                    .body(Full::new(Bytes::from("metrics error")))
                                    .unwrap();
                                Ok(resp)
                            }
                        }
                    } else if req.uri().path() == "/health" {
                        let resp = Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from("ok")))
                            .unwrap();
                        Ok(resp)
                    } else {
                        let resp = Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(Full::new(Bytes::from("not found")))
                            .unwrap();
                        Ok(resp)
                    }
                }
            });

            if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                hyper_util::rt::TokioExecutor::new(),
            )
            .serve_connection(io, service)
            .await
            {
                error!(error = %e, "HTTP connection error");
            }
        });
    }
}
