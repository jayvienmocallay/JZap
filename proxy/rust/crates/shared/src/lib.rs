//! Shared types, config structs, and error types for the JZap Rust components.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Unified error type for all JZap Rust components.
#[derive(Debug, thiserror::Error)]
pub enum JzapError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("redis error: {0}")]
    Redis(String),

    #[error("ebpf error: {0}")]
    Ebpf(String),

    #[error("fingerprint error: {0}")]
    Fingerprint(String),

    #[error("rate limit error: {0}")]
    RateLimit(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("http error: {0}")]
    Http(String),

    #[error("baseline anomaly: {0}")]
    BaselineAnomaly(String),
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Top-level configuration loaded from env / config file.
#[derive(Debug, Clone, Deserialize)]
pub struct JzapConfig {
    /// Hostname or IP of the Redis instance.
    pub redis_host: String,

    /// Port of the Redis instance.
    pub redis_port: u16,

    /// Optional password for Redis AUTH.
    pub redis_password: Option<String>,

    /// URL of the JZap control-plane API.
    pub control_plane_url: String,

    /// Filesystem path to pre-compiled eBPF object files.
    pub ebpf_programs_path: String,

    /// Unix-domain socket path used for IPC with OpenResty.
    pub socket_path: String,

    /// Network interface to attach XDP programs to (e.g., "eth0").
    pub xdp_interface: String,

    /// Port for Prometheus metrics HTTP server.
    pub metrics_port: u16,

    /// Interval (seconds) for polling the control plane for blocklist updates.
    pub blocklist_sync_interval_secs: u64,

    /// Interval (seconds) for reading eBPF metrics.
    pub metrics_read_interval_secs: u64,

    /// N-sigma threshold for traffic baseline anomaly detection.
    pub baseline_sigma_threshold: f64,

    /// Window size (seconds) for traffic baseline computation.
    pub baseline_window_secs: u64,

    /// Enable traffic logging to stdout.
    pub traffic_logging_enabled: bool,
}

impl Default for JzapConfig {
    fn default() -> Self {
        Self {
            redis_host: "127.0.0.1".into(),
            redis_port: 6379,
            redis_password: None,
            control_plane_url: "http://localhost:8080".into(),
            ebpf_programs_path: "/opt/jzap/ebpf".into(),
            socket_path: "/var/run/jzap/jzap.sock".into(),
            xdp_interface: "eth0".into(),
            metrics_port: 9090,
            blocklist_sync_interval_secs: 30,
            metrics_read_interval_secs: 5,
            baseline_sigma_threshold: 3.0,
            baseline_window_secs: 60,
            traffic_logging_enabled: true,
        }
    }
}

// ---------------------------------------------------------------------------
// eBPF Constants — mirror proxy/ebpf/src/common.h
// ---------------------------------------------------------------------------

/// Config parameter IDs (indices into jzap_config BPF_MAP_TYPE_ARRAY).
pub mod ebpf_config {
    pub const CFG_PPS_LIMIT: u32 = 0;
    pub const CFG_UDP_PPS_LIMIT: u32 = 1;
    pub const CFG_ICMP_PPS_LIMIT: u32 = 2;
    pub const CFG_SYN_PPS_LIMIT: u32 = 3;
    pub const CFG_ENABLE_GEO_FILTER: u32 = 4;
    pub const CFG_AMPLIFICATION_THRESHOLD: u32 = 5;
    pub const CFG_SYN_COOKIE_SECRET: u32 = 6;
    pub const CFG_BASELINE_WINDOW_SEC: u32 = 7;
}

/// Metrics IDs (indices into jzap_metrics BPF_MAP_TYPE_PERCPU_ARRAY).
pub mod ebpf_metrics {
    pub const METRIC_TOTAL_PACKETS: u32 = 0;
    pub const METRIC_DROPPED_BLOCKLIST: u32 = 1;
    pub const METRIC_DROPPED_RATELIMIT: u32 = 2;
    pub const METRIC_DROPPED_SYN: u32 = 3;
    pub const METRIC_DROPPED_UDP: u32 = 4;
    pub const METRIC_DROPPED_ICMP: u32 = 5;
    pub const METRIC_DROPPED_GEO: u32 = 6;
    pub const METRIC_PASSED: u32 = 7;
    pub const METRIC_DROPPED_AMPLIFICATION: u32 = 8;
    pub const METRIC_SYN_COOKIES_ISSUED: u32 = 9;
    pub const METRIC_SYN_COOKIES_VALIDATED: u32 = 10;
    pub const METRIC_TOTAL_BYTES: u32 = 11;

    /// Total number of metric slots.
    pub const METRIC_COUNT: u32 = 16;

    /// Human-readable labels for each metric ID (for Prometheus export).
    pub fn metric_label(id: u32) -> &'static str {
        match id {
            METRIC_TOTAL_PACKETS => "jzap_xdp_total_packets",
            METRIC_DROPPED_BLOCKLIST => "jzap_xdp_dropped_blocklist",
            METRIC_DROPPED_RATELIMIT => "jzap_xdp_dropped_ratelimit",
            METRIC_DROPPED_SYN => "jzap_xdp_dropped_syn_flood",
            METRIC_DROPPED_UDP => "jzap_xdp_dropped_udp_flood",
            METRIC_DROPPED_ICMP => "jzap_xdp_dropped_icmp_flood",
            METRIC_DROPPED_GEO => "jzap_xdp_dropped_geo_filter",
            METRIC_PASSED => "jzap_xdp_passed",
            METRIC_DROPPED_AMPLIFICATION => "jzap_xdp_dropped_amplification",
            METRIC_SYN_COOKIES_ISSUED => "jzap_xdp_syn_cookies_issued",
            METRIC_SYN_COOKIES_VALIDATED => "jzap_xdp_syn_cookies_validated",
            METRIC_TOTAL_BYTES => "jzap_xdp_total_bytes",
            _ => "jzap_xdp_unknown",
        }
    }
}

/// Map names as they appear in the eBPF ELF object files.
pub mod ebpf_maps {
    pub const MAP_BLOCKLIST: &str = "jzap_blocklist";
    pub const MAP_RATELIMIT: &str = "jzap_ratelimit";
    pub const MAP_CONFIG: &str = "jzap_config";
    pub const MAP_METRICS: &str = "jzap_metrics";
    pub const MAP_GEO_FILTER: &str = "jzap_geo_filter";
    pub const MAP_SYN_COOKIES: &str = "jzap_syn_cookies";
    pub const MAP_AMPLIFICATION: &str = "jzap_amplification";
    pub const MAP_TRAFFIC_BASELINE: &str = "jzap_traffic_baseline";
}

/// eBPF program names (ELF section names).
pub mod ebpf_programs {
    pub const PROG_BLOCKLIST: &str = "xdp/blocklist";
    pub const PROG_RATELIMIT: &str = "xdp/ratelimit";
    pub const PROG_AMPLIFICATION: &str = "xdp/amplification";
    pub const PROG_GEO_FILTER: &str = "xdp/geo_filter";
}

// ---------------------------------------------------------------------------
// Blocklist
// ---------------------------------------------------------------------------

/// Why an IP was added to the blocklist.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockReason {
    Manual = 1,
    AutoRateLimit = 2,
    ThreatIntel = 3,
    GeoBlock = 4,
}

impl BlockReason {
    /// Convert from the u8 value stored in the eBPF map.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Manual),
            2 => Some(Self::AutoRateLimit),
            3 => Some(Self::ThreatIntel),
            4 => Some(Self::GeoBlock),
            _ => None,
        }
    }

    /// Convert to the u8 value for storage in the eBPF map.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A single entry in the IP blocklist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistEntry {
    /// The blocked IP address (v4 or v6).
    pub ip: String,

    /// Reason the IP was blocked.
    pub reason: BlockReason,

    /// Unix timestamp (seconds) when the entry was created.
    pub added_at: u64,

    /// Optional expiry Unix timestamp; `None` means permanent.
    pub expires_at: Option<u64>,
}

// ---------------------------------------------------------------------------
// Geo filtering
// ---------------------------------------------------------------------------

/// Action to take for a given country.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum GeoAction {
    Allow = 0,
    Drop = 1,
    RateLimit = 2,
}

/// A geo-filter rule for a specific country code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoFilterRule {
    /// ISO 3166-1 numeric country code.
    pub country_code: u16,

    /// Action to take.
    pub action: GeoAction,

    /// PPS limit when action is RateLimit.
    pub rate_limit_pps: u32,
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

/// Configuration knobs for the sliding-window rate limiter.
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum sustained requests per second.
    pub requests_per_second: u64,

    /// Burst allowance above the sustained rate.
    pub burst_size: u64,

    /// Duration (seconds) of the sliding window.
    pub window_seconds: u64,
}

// ---------------------------------------------------------------------------
// TLS fingerprinting
// ---------------------------------------------------------------------------

/// Result of a JA3 fingerprint computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintResult {
    /// The MD5 hash of the JA3 string.
    pub ja3_hash: String,

    /// The full JA3 string before hashing.
    pub ja3_full: String,

    /// Whether this fingerprint matches a known bot signature.
    pub is_known_bot: bool,

    /// Name of the matched bot, if any.
    pub bot_name: Option<String>,
}

// ---------------------------------------------------------------------------
// Traffic baseline / anomaly detection
// ---------------------------------------------------------------------------

/// Aggregate traffic statistics for one time window (mirrors eBPF traffic_stats).
#[derive(Debug, Clone, Default, Serialize)]
pub struct TrafficStats {
    pub window_start: u64,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub icmp_packets: u64,
    pub syn_packets: u64,
}

/// Rolling baseline statistics with mean and standard deviation.
#[derive(Debug, Clone, Default)]
pub struct TrafficBaseline {
    pub mean_pps: f64,
    pub stddev_pps: f64,
    pub mean_bps: f64,
    pub stddev_bps: f64,
    pub sample_count: u64,
}

/// An anomaly event detected by the baseline engine.
#[derive(Debug, Clone, Serialize)]
pub struct AnomalyEvent {
    pub timestamp: u64,
    pub metric_name: String,
    pub current_value: f64,
    pub baseline_mean: f64,
    pub baseline_stddev: f64,
    pub sigma_deviation: f64,
    pub severity: AnomalySeverity,
}

/// Severity level of a traffic anomaly.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum AnomalySeverity {
    Warning,
    Critical,
}

// ---------------------------------------------------------------------------
// XDP metrics snapshot — aggregated from per-CPU maps
// ---------------------------------------------------------------------------

/// A point-in-time snapshot of all eBPF/XDP metrics.
#[derive(Debug, Clone, Default, Serialize)]
pub struct XdpMetricsSnapshot {
    pub total_packets: u64,
    pub dropped_blocklist: u64,
    pub dropped_ratelimit: u64,
    pub dropped_syn: u64,
    pub dropped_udp: u64,
    pub dropped_icmp: u64,
    pub dropped_geo: u64,
    pub passed: u64,
    pub dropped_amplification: u64,
    pub syn_cookies_issued: u64,
    pub syn_cookies_validated: u64,
    pub total_bytes: u64,
}

impl XdpMetricsSnapshot {
    /// Build a snapshot from an array of summed per-CPU values indexed by metric ID.
    pub fn from_raw(values: &[u64]) -> Self {
        use ebpf_metrics::*;
        Self {
            total_packets: values
                .get(METRIC_TOTAL_PACKETS as usize)
                .copied()
                .unwrap_or(0),
            dropped_blocklist: values
                .get(METRIC_DROPPED_BLOCKLIST as usize)
                .copied()
                .unwrap_or(0),
            dropped_ratelimit: values
                .get(METRIC_DROPPED_RATELIMIT as usize)
                .copied()
                .unwrap_or(0),
            dropped_syn: values
                .get(METRIC_DROPPED_SYN as usize)
                .copied()
                .unwrap_or(0),
            dropped_udp: values
                .get(METRIC_DROPPED_UDP as usize)
                .copied()
                .unwrap_or(0),
            dropped_icmp: values
                .get(METRIC_DROPPED_ICMP as usize)
                .copied()
                .unwrap_or(0),
            dropped_geo: values
                .get(METRIC_DROPPED_GEO as usize)
                .copied()
                .unwrap_or(0),
            passed: values.get(METRIC_PASSED as usize).copied().unwrap_or(0),
            dropped_amplification: values
                .get(METRIC_DROPPED_AMPLIFICATION as usize)
                .copied()
                .unwrap_or(0),
            syn_cookies_issued: values
                .get(METRIC_SYN_COOKIES_ISSUED as usize)
                .copied()
                .unwrap_or(0),
            syn_cookies_validated: values
                .get(METRIC_SYN_COOKIES_VALIDATED as usize)
                .copied()
                .unwrap_or(0),
            total_bytes: values
                .get(METRIC_TOTAL_BYTES as usize)
                .copied()
                .unwrap_or(0),
        }
    }
}

// ---------------------------------------------------------------------------
// Control Plane API response types (for blocklist sync)
// ---------------------------------------------------------------------------

/// Response from the control plane's blocklist endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct BlocklistResponse {
    pub entries: Vec<BlocklistEntry>,
    pub version: u64,
}

/// Response from the control plane's config endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct ConfigResponse {
    pub pps_limit: Option<u64>,
    pub udp_pps_limit: Option<u64>,
    pub icmp_pps_limit: Option<u64>,
    pub syn_pps_limit: Option<u64>,
    pub enable_geo_filter: Option<bool>,
    pub amplification_threshold: Option<u64>,
    pub geo_rules: Option<Vec<GeoFilterRule>>,
}

// ---------------------------------------------------------------------------
// Traffic log entry
// ---------------------------------------------------------------------------

/// A structured traffic log entry emitted by the sidecar.
#[derive(Debug, Clone, Serialize)]
pub struct TrafficLogEntry {
    pub timestamp: u64,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub dropped_total: u64,
    pub passed: u64,
    pub dropped_breakdown: DroppedBreakdown,
}

/// Breakdown of dropped packets by reason.
#[derive(Debug, Clone, Serialize)]
pub struct DroppedBreakdown {
    pub blocklist: u64,
    pub ratelimit: u64,
    pub syn_flood: u64,
    pub udp_flood: u64,
    pub icmp_flood: u64,
    pub geo_filter: u64,
    pub amplification: u64,
}
