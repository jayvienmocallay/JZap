//! JZap Rust sidecar orchestrator.
//!
//! This binary initialises all Rust-side subsystems and runs them concurrently:
//!
//! 1. **eBPF Loader** — loads and attaches XDP programs (blocklist, ratelimit,
//!    amplification, geo_filter) to the configured network interface.
//! 2. **Metrics Exporter** — periodically reads per-CPU metrics from eBPF maps
//!    and serves them as Prometheus text format on `/metrics`.
//! 3. **Blocklist Sync** — polls the Control Plane API for blocklist and config
//!    updates, pushing them into eBPF maps.
//! 4. **Baseline Monitor** — computes rolling traffic statistics and emits
//!    anomaly events when traffic deviates by N-sigma.
//! 5. **Traffic Logger** — logs structured traffic stats and anomaly events.
//! 6. **Fingerprint Engine** — JA3 signature matching (loaded at startup).
//! 7. **Rate Limiter** — in-memory sliding-window rate limiter (L7).
//!
//! The sidecar also exposes a Unix-domain socket for IPC with OpenResty Lua
//! (TODO: Phase 2) and will eventually support gRPC for agent communication.

mod baseline;
mod blocklist_sync;
mod metrics;
mod traffic_log;

use std::sync::Arc;

use anyhow::Result;
use jzap_ebpf_loader::EbpfManager;
use jzap_fingerprint::FingerprintEngine;
use jzap_ratelimit_engine::RateLimiter;
use jzap_shared::{AnomalyEvent, JzapConfig, RateLimitConfig};
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crate::blocklist_sync::ControlPlaneClient;
use crate::metrics::XdpPrometheusMetrics;

#[tokio::main]
async fn main() -> Result<()> {
    // ------------------------------------------------------------------
    // Logging
    // ------------------------------------------------------------------
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("JZap Rust sidecar starting (Phase 1 — L3/4 Core)");

    // ------------------------------------------------------------------
    // Configuration
    // ------------------------------------------------------------------
    let config = JzapConfig {
        redis_host: env_or("JZAP_REDIS_HOST", "127.0.0.1"),
        redis_port: env_or("JZAP_REDIS_PORT", "6379")
            .parse()
            .unwrap_or(6379),
        redis_password: std::env::var("JZAP_REDIS_PASSWORD").ok(),
        control_plane_url: env_or("JZAP_CONTROL_PLANE_URL", "http://localhost:8080"),
        ebpf_programs_path: env_or("JZAP_EBPF_PATH", "/opt/jzap/ebpf"),
        socket_path: env_or("JZAP_SOCKET_PATH", "/var/run/jzap/jzap.sock"),
        xdp_interface: env_or("JZAP_XDP_INTERFACE", "eth0"),
        metrics_port: env_or("JZAP_METRICS_PORT", "9090")
            .parse()
            .unwrap_or(9090),
        blocklist_sync_interval_secs: env_or("JZAP_BLOCKLIST_SYNC_INTERVAL", "30")
            .parse()
            .unwrap_or(30),
        metrics_read_interval_secs: env_or("JZAP_METRICS_INTERVAL", "5")
            .parse()
            .unwrap_or(5),
        baseline_sigma_threshold: env_or("JZAP_BASELINE_SIGMA", "3.0")
            .parse()
            .unwrap_or(3.0),
        baseline_window_secs: env_or("JZAP_BASELINE_WINDOW", "60")
            .parse()
            .unwrap_or(60),
        traffic_logging_enabled: env_or("JZAP_TRAFFIC_LOG", "true")
            .parse()
            .unwrap_or(true),
    };

    info!(?config, "configuration loaded");

    // ------------------------------------------------------------------
    // eBPF Manager — load and attach XDP programs
    // ------------------------------------------------------------------
    let ebpf = Arc::new(EbpfManager::new(
        &config.ebpf_programs_path,
        &config.xdp_interface,
    ));

    if let Err(e) = ebpf.load_all() {
        error!(error = %e, "failed to load eBPF programs — continuing with stubs");
    }

    // ------------------------------------------------------------------
    // Fingerprint Engine (L3/L4 phase: loaded but not actively used yet)
    // ------------------------------------------------------------------
    let fingerprint = FingerprintEngine::new();
    // Try to load bot signatures if the file exists.
    let sig_path = format!("{}/ja3_signatures.json", config.ebpf_programs_path);
    if std::path::Path::new(&sig_path).exists() {
        if let Err(e) = fingerprint.load_signatures(&sig_path) {
            warn!(error = %e, "failed to load JA3 signatures");
        }
    }

    // ------------------------------------------------------------------
    // Rate Limiter (L7 — in-memory, Phase 2 will add Redis backing)
    // ------------------------------------------------------------------
    let rate_limit_config = RateLimitConfig {
        requests_per_second: 100,
        burst_size: 50,
        window_seconds: 60,
    };
    let _rate_limiter = RateLimiter::new(rate_limit_config);

    // ------------------------------------------------------------------
    // Prometheus Metrics
    // ------------------------------------------------------------------
    let prom = Arc::new(
        XdpPrometheusMetrics::new().expect("failed to create Prometheus metrics registry"),
    );

    // ------------------------------------------------------------------
    // Anomaly event broadcast channel
    // ------------------------------------------------------------------
    let (anomaly_tx, anomaly_rx) = broadcast::channel::<AnomalyEvent>(256);

    // ------------------------------------------------------------------
    // Control Plane Client
    // ------------------------------------------------------------------
    let cp_client = Arc::new(ControlPlaneClient::new(&config.control_plane_url));

    // ------------------------------------------------------------------
    // Spawn background tasks
    // ------------------------------------------------------------------

    // 1. Prometheus metrics HTTP server
    let prom_clone = prom.clone();
    let metrics_port = config.metrics_port;
    tokio::spawn(async move {
        if let Err(e) = metrics::serve_metrics_http(prom_clone, metrics_port).await {
            error!(error = %e, "Prometheus HTTP server failed");
        }
    });

    // 2. eBPF metrics collection → Prometheus gauges
    let ebpf_clone = ebpf.clone();
    let prom_clone = prom.clone();
    let metrics_interval = config.metrics_read_interval_secs;
    tokio::spawn(async move {
        metrics::metrics_collection_loop(ebpf_clone, prom_clone, metrics_interval).await;
    });

    // 3. Blocklist sync from Control Plane
    let ebpf_clone = ebpf.clone();
    let cp_clone = cp_client.clone();
    let blocklist_interval = config.blocklist_sync_interval_secs;
    tokio::spawn(async move {
        blocklist_sync::blocklist_sync_loop(ebpf_clone, cp_clone, blocklist_interval).await;
    });

    // 4. Config sync from Control Plane
    let ebpf_clone = ebpf.clone();
    let cp_clone = cp_client.clone();
    let config_interval = config.blocklist_sync_interval_secs;
    tokio::spawn(async move {
        blocklist_sync::config_sync_loop(ebpf_clone, cp_clone, config_interval).await;
    });

    // 5. Traffic baseline monitoring + anomaly detection
    let ebpf_clone = ebpf.clone();
    let sigma = config.baseline_sigma_threshold;
    let baseline_interval = config.metrics_read_interval_secs;
    let anomaly_tx_clone = anomaly_tx.clone();
    tokio::spawn(async move {
        baseline::baseline_monitoring_loop(ebpf_clone, sigma, baseline_interval, anomaly_tx_clone)
            .await;
    });

    // 6. Traffic logging
    if config.traffic_logging_enabled {
        let ebpf_clone = ebpf.clone();
        let log_interval = config.metrics_read_interval_secs;
        tokio::spawn(async move {
            traffic_log::traffic_logging_loop(ebpf_clone, log_interval, anomaly_rx).await;
        });
    }

    // ------------------------------------------------------------------
    // TODO(Phase 2): Start Unix socket server for IPC with OpenResty Lua
    // ------------------------------------------------------------------
    // The Lua FFI / cosocket layer in OpenResty will connect to this
    // socket to request fingerprint checks, rate-limit decisions, and
    // blocklist lookups.

    // ------------------------------------------------------------------
    // TODO(Phase 5): Start gRPC server for agent communication
    // ------------------------------------------------------------------
    // The JZap agent (Go binary running on the host) will push config
    // updates and pull metrics via gRPC.

    // ------------------------------------------------------------------
    // Graceful shutdown
    // ------------------------------------------------------------------
    info!("JZap sidecar ready — all background tasks running");
    info!(
        "  Prometheus metrics: http://0.0.0.0:{}",
        config.metrics_port
    );

    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl-c");

    info!("shutdown signal received");

    // Unload eBPF programs on shutdown.
    ebpf.unload_all();

    info!("JZap sidecar stopped");
    Ok(())
}

/// Read an env var or return a default.
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
