//! Blocklist synchronization with the JZap Control Plane API.
//!
//! Periodically polls the control plane for the current blocklist and config,
//! then pushes updates into the eBPF maps via EbpfManager.

use std::sync::Arc;

use anyhow::{Context, Result};
use jzap_ebpf_loader::{EbpfManager, XdpProgram};
use jzap_shared::{
    ebpf_config, BlocklistResponse, ConfigResponse,
};
use reqwest::Client;
use tracing::{debug, error, info, warn};

/// Client for communicating with the JZap Control Plane REST API.
pub struct ControlPlaneClient {
    http: Client,
    base_url: String,
}

impl ControlPlaneClient {
    /// Create a new control plane client.
    pub fn new(base_url: &str) -> Self {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client");

        info!(base_url = %base_url, "ControlPlaneClient created");
        Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Fetch the current blocklist from the control plane.
    pub async fn fetch_blocklist(&self) -> Result<BlocklistResponse> {
        let url = format!("{}/api/v1/blocklist", self.base_url);
        debug!(url = %url, "fetching blocklist");

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .context("failed to fetch blocklist from control plane")?;

        if !resp.status().is_success() {
            anyhow::bail!(
                "control plane returned {} for blocklist fetch",
                resp.status()
            );
        }

        let body = resp
            .json::<BlocklistResponse>()
            .await
            .context("failed to parse blocklist response")?;

        Ok(body)
    }

    /// Fetch the current XDP configuration from the control plane.
    pub async fn fetch_config(&self) -> Result<ConfigResponse> {
        let url = format!("{}/api/v1/config/xdp", self.base_url);
        debug!(url = %url, "fetching XDP config");

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .context("failed to fetch config from control plane")?;

        if !resp.status().is_success() {
            anyhow::bail!(
                "control plane returned {} for config fetch",
                resp.status()
            );
        }

        let body = resp
            .json::<ConfigResponse>()
            .await
            .context("failed to parse config response")?;

        Ok(body)
    }
}

/// Background task that periodically syncs the blocklist from the control plane
/// into the eBPF blocklist map.
pub async fn blocklist_sync_loop(
    ebpf: Arc<EbpfManager>,
    cp_client: Arc<ControlPlaneClient>,
    interval_secs: u64,
) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
    let mut last_version: u64 = 0;

    info!(
        interval_secs,
        "starting blocklist sync loop"
    );

    loop {
        interval.tick().await;

        match cp_client.fetch_blocklist().await {
            Ok(response) => {
                if response.version == last_version {
                    debug!(version = last_version, "blocklist unchanged, skipping update");
                    continue;
                }

                info!(
                    version = response.version,
                    entries = response.entries.len(),
                    "received blocklist update from control plane"
                );

                // Filter out expired entries.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                let active_entries: Vec<_> = response
                    .entries
                    .into_iter()
                    .filter(|e| e.expires_at.map_or(true, |exp| exp > now))
                    .collect();

                if let Err(e) = ebpf.update_blocklist(&active_entries) {
                    error!(error = %e, "failed to push blocklist to eBPF map");
                    continue;
                }

                last_version = response.version;
                info!(
                    version = last_version,
                    active_count = active_entries.len(),
                    "blocklist sync complete"
                );
            }
            Err(e) => {
                warn!(error = %e, "blocklist sync failed — will retry next interval");
            }
        }
    }
}

/// Background task that periodically syncs XDP config from the control plane.
pub async fn config_sync_loop(
    ebpf: Arc<EbpfManager>,
    cp_client: Arc<ControlPlaneClient>,
    interval_secs: u64,
) {
    // Config syncs less frequently than blocklist (2x the interval).
    let sync_interval = interval_secs * 2;
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(sync_interval));

    info!(
        sync_interval,
        "starting config sync loop"
    );

    loop {
        interval.tick().await;

        match cp_client.fetch_config().await {
            Ok(config) => {
                let mut configs = Vec::new();

                if let Some(v) = config.pps_limit {
                    configs.push((ebpf_config::CFG_PPS_LIMIT, v));
                }
                if let Some(v) = config.udp_pps_limit {
                    configs.push((ebpf_config::CFG_UDP_PPS_LIMIT, v));
                }
                if let Some(v) = config.icmp_pps_limit {
                    configs.push((ebpf_config::CFG_ICMP_PPS_LIMIT, v));
                }
                if let Some(v) = config.syn_pps_limit {
                    configs.push((ebpf_config::CFG_SYN_PPS_LIMIT, v));
                }
                if let Some(v) = config.enable_geo_filter {
                    configs.push((ebpf_config::CFG_ENABLE_GEO_FILTER, if v { 1 } else { 0 }));
                }
                if let Some(v) = config.amplification_threshold {
                    configs.push((ebpf_config::CFG_AMPLIFICATION_THRESHOLD, v));
                }

                if !configs.is_empty() {
                    // Apply config to all loaded programs that share the config map.
                    for program in [
                        XdpProgram::Blocklist,
                        XdpProgram::Ratelimit,
                        XdpProgram::Amplification,
                        XdpProgram::GeoFilter,
                    ] {
                        if let Err(e) = ebpf.apply_config(program, &configs) {
                            debug!(program = ?program, error = %e, "config apply skipped for program");
                        }
                    }
                    info!(count = configs.len(), "XDP config updated from control plane");
                }

                // Update geo filter rules if present.
                if let Some(geo_rules) = config.geo_rules {
                    if let Err(e) = ebpf.update_geo_filter(&geo_rules) {
                        error!(error = %e, "failed to update geo filter map");
                    } else {
                        info!(count = geo_rules.len(), "geo filter rules updated");
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "config sync failed — will retry next interval");
            }
        }
    }
}
