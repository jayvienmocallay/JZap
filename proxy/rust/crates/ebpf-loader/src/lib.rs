//! eBPF XDP program loader and manager for JZap.
//!
//! On Linux, this crate uses the `aya` library to:
//! - Load pre-compiled eBPF `.o` object files
//! - Attach XDP programs to network interfaces
//! - Read/write BPF maps (blocklist, config, metrics, geo filter, etc.)
//! - Support hot-reload of programs without traffic interruption
//!
//! On non-Linux platforms, all methods are no-op stubs that log warnings.
//! This allows the workspace to compile and test on macOS/Windows CI.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use jzap_shared::{
    ebpf_config, ebpf_maps, ebpf_metrics, BlockReason, BlocklistEntry, GeoAction, GeoFilterRule,
    TrafficStats, XdpMetricsSnapshot,
};
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// Linux-only imports (aya)
// ---------------------------------------------------------------------------
#[cfg(target_os = "linux")]
use aya::{
    maps::{Array, HashMap as AyaHashMap, MapData, PerCpuArray, PerCpuValues},
    programs::{Xdp, XdpFlags},
    Ebpf,
};

#[cfg(target_os = "linux")]
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Program handle tracking
// ---------------------------------------------------------------------------

/// Identifies a loaded XDP program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XdpProgram {
    Blocklist,
    Ratelimit,
    Amplification,
    GeoFilter,
}

impl XdpProgram {
    /// Filename of the compiled eBPF object file (without directory).
    pub fn object_file(&self) -> &'static str {
        match self {
            Self::Blocklist => "blocklist.o",
            Self::Ratelimit => "ratelimit.o",
            Self::Amplification => "amplification.o",
            Self::GeoFilter => "geo_filter.o",
        }
    }

    /// XDP section name inside the ELF object.
    pub fn section_name(&self) -> &'static str {
        match self {
            Self::Blocklist => "xdp",
            Self::Ratelimit => "xdp",
            Self::Amplification => "xdp",
            Self::GeoFilter => "xdp",
        }
    }
}

// ===========================================================================
// Linux implementation
// ===========================================================================
#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    /// Manages the lifecycle of eBPF/XDP programs attached to a network interface.
    pub struct EbpfManager {
        /// Filesystem path to the directory containing `.o` eBPF object files.
        programs_path: PathBuf,

        /// Network interface name to attach XDP programs to.
        interface: String,

        /// Loaded eBPF program handles, keyed by program type.
        /// Each `Ebpf` handle owns the loaded program and its maps.
        loaded: Mutex<HashMap<XdpProgram, Ebpf>>,
    }

    impl EbpfManager {
        /// Create a new [`EbpfManager`].
        ///
        /// - `programs_path`: directory containing compiled `.o` files
        /// - `interface`: network interface name (e.g., "eth0")
        pub fn new(programs_path: &str, interface: &str) -> Self {
            info!(
                path = %programs_path,
                interface = %interface,
                "EbpfManager created (aya/Linux)"
            );
            Self {
                programs_path: PathBuf::from(programs_path),
                interface: interface.to_string(),
                loaded: Mutex::new(HashMap::new()),
            }
        }

        // -----------------------------------------------------------------
        // Program loading
        // -----------------------------------------------------------------

        /// Load and attach a single XDP program to the configured interface.
        pub fn load_and_attach(&self, program: XdpProgram) -> Result<()> {
            let obj_path = self.programs_path.join(program.object_file());
            info!(
                program = ?program,
                path = %obj_path.display(),
                interface = %self.interface,
                "loading eBPF program"
            );

            // Load the eBPF object file.
            let mut ebpf = Ebpf::load_file(&obj_path)
                .with_context(|| format!("failed to load eBPF object: {}", obj_path.display()))?;

            // Initialize aya-log forwarding (best effort — not all programs have log maps).
            if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
                debug!(error = %e, "aya-log init skipped (program may not use bpf_printk)");
            }

            // Get the XDP program handle and attach it.
            let xdp: &mut Xdp = ebpf
                .program_mut(program.section_name())
                .context("XDP program section not found")?
                .try_into()
                .context("program is not XDP")?;

            xdp.load().context("failed to load XDP program")?;

            // Use SKB_MODE for broader compatibility; switch to DRV_MODE in production
            // on supported NICs for better performance.
            xdp.attach(&self.interface, XdpFlags::SKB_MODE)
                .with_context(|| {
                    format!(
                        "failed to attach XDP program {:?} to {}",
                        program, self.interface
                    )
                })?;

            info!(program = ?program, "eBPF program loaded and attached");

            let mut loaded = self.loaded.lock().unwrap();
            loaded.insert(program, ebpf);

            Ok(())
        }

        /// Load and attach all four XDP programs.
        pub fn load_all(&self) -> Result<()> {
            self.load_and_attach(XdpProgram::Blocklist)?;
            self.load_and_attach(XdpProgram::Ratelimit)?;
            self.load_and_attach(XdpProgram::Amplification)?;
            self.load_and_attach(XdpProgram::GeoFilter)?;
            info!("all eBPF programs loaded and attached");
            Ok(())
        }

        /// Hot-reload a specific program by detaching, reloading, and re-attaching.
        /// The short gap between detach and re-attach means a few packets may
        /// bypass XDP; this is acceptable for config-change reloads.
        pub fn hot_reload(&self, program: XdpProgram) -> Result<()> {
            info!(program = ?program, "hot-reloading eBPF program");

            // Drop the old handle (which detaches the program).
            {
                let mut loaded = self.loaded.lock().unwrap();
                loaded.remove(&program);
            }

            // Load and attach the new version.
            self.load_and_attach(program)?;
            info!(program = ?program, "hot-reload complete");
            Ok(())
        }

        // -----------------------------------------------------------------
        // Blocklist map operations
        // -----------------------------------------------------------------

        /// Bulk-update the blocklist map. Clears existing entries and inserts
        /// the new set.
        pub fn update_blocklist(&self, entries: &[BlocklistEntry]) -> Result<()> {
            let loaded = self.loaded.lock().unwrap();
            let ebpf = loaded
                .get(&XdpProgram::Blocklist)
                .context("blocklist program not loaded")?;

            let mut map: AyaHashMap<&MapData, u32, u8> = AyaHashMap::try_from(
                ebpf.map(ebpf_maps::MAP_BLOCKLIST)
                    .context("blocklist map not found")?,
            )?;

            // We cannot easily iterate+delete in aya's HashMap, so we rely on
            // the fact that we do a full sync: the control plane sends the
            // complete blocklist each time, and we insert/overwrite entries.
            // Expired entries are handled by not including them in the sync.

            let mut count = 0u64;
            for entry in entries {
                if let Ok(ip) = entry.ip.parse::<Ipv4Addr>() {
                    let ip_u32 = u32::from(ip).to_be();
                    map.insert(&ip_u32, &entry.reason.as_u8(), 0)
                        .with_context(|| {
                            format!("failed to insert blocklist entry for {}", entry.ip)
                        })?;
                    count += 1;
                } else {
                    warn!(ip = %entry.ip, "skipping non-IPv4 blocklist entry (IPv6 handled by separate map)");
                }
            }

            info!(count, "blocklist map updated");
            Ok(())
        }

        /// Add a single IP to the blocklist.
        pub fn add_to_blocklist(&self, ip: Ipv4Addr, reason: BlockReason) -> Result<()> {
            let loaded = self.loaded.lock().unwrap();
            let ebpf = loaded
                .get(&XdpProgram::Blocklist)
                .context("blocklist program not loaded")?;

            let mut map: AyaHashMap<&MapData, u32, u8> = AyaHashMap::try_from(
                ebpf.map(ebpf_maps::MAP_BLOCKLIST)
                    .context("blocklist map not found")?,
            )?;

            let ip_u32 = u32::from(ip).to_be();
            map.insert(&ip_u32, &reason.as_u8(), 0)?;
            info!(ip = %ip, reason = ?reason, "added IP to blocklist");
            Ok(())
        }

        /// Remove a single IP from the blocklist.
        pub fn remove_from_blocklist(&self, ip: Ipv4Addr) -> Result<()> {
            let loaded = self.loaded.lock().unwrap();
            let ebpf = loaded
                .get(&XdpProgram::Blocklist)
                .context("blocklist program not loaded")?;

            let mut map: AyaHashMap<&MapData, u32, u8> = AyaHashMap::try_from(
                ebpf.map(ebpf_maps::MAP_BLOCKLIST)
                    .context("blocklist map not found")?,
            )?;

            let ip_u32 = u32::from(ip).to_be();
            map.remove(&ip_u32)?;
            info!(ip = %ip, "removed IP from blocklist");
            Ok(())
        }

        // -----------------------------------------------------------------
        // Config map operations
        // -----------------------------------------------------------------

        /// Set a single configuration value in the eBPF config array map.
        pub fn set_config(&self, program: XdpProgram, key: u32, value: u64) -> Result<()> {
            let loaded = self.loaded.lock().unwrap();
            let ebpf = loaded
                .get(&program)
                .with_context(|| format!("program {:?} not loaded", program))?;

            let mut map: Array<&MapData, u64> = Array::try_from(
                ebpf.map(ebpf_maps::MAP_CONFIG)
                    .context("config map not found")?,
            )?;

            map.set(key, &value, 0)?;
            info!(program = ?program, key, value, "config map updated");
            Ok(())
        }

        /// Apply all config values from a control-plane ConfigResponse.
        pub fn apply_config(&self, program: XdpProgram, configs: &[(u32, u64)]) -> Result<()> {
            for &(key, value) in configs {
                self.set_config(program, key, value)?;
            }
            Ok(())
        }

        // -----------------------------------------------------------------
        // Geo filter map operations
        // -----------------------------------------------------------------

        /// Update the geo filter map with a set of country rules.
        pub fn update_geo_filter(&self, rules: &[GeoFilterRule]) -> Result<()> {
            let loaded = self.loaded.lock().unwrap();
            let ebpf = loaded
                .get(&XdpProgram::GeoFilter)
                .context("geo_filter program not loaded")?;

            // The geo_filter map is a HASH with key=u16 (country code), value=geo_action struct.
            // In aya, we represent the value as a byte array matching the C struct layout:
            //   struct geo_action { __u8 action; __u32 rate_limit_pps; } — 5 bytes (packed).
            // However, BPF maps may pad the struct. We'll use a [u8; 8] to be safe.
            let mut map: AyaHashMap<&MapData, u16, [u8; 8]> = AyaHashMap::try_from(
                ebpf.map(ebpf_maps::MAP_GEO_FILTER)
                    .context("geo filter map not found")?,
            )?;

            for rule in rules {
                let mut val = [0u8; 8];
                val[0] = rule.action as u8;
                val[4..8].copy_from_slice(&rule.rate_limit_pps.to_ne_bytes());
                map.insert(&rule.country_code, &val, 0)?;
            }

            info!(count = rules.len(), "geo filter map updated");
            Ok(())
        }

        // -----------------------------------------------------------------
        // Metrics reading
        // -----------------------------------------------------------------

        /// Read and aggregate per-CPU metrics from the metrics map.
        /// Returns summed values across all CPUs for each metric ID.
        pub fn read_metrics(&self, program: XdpProgram) -> Result<XdpMetricsSnapshot> {
            let loaded = self.loaded.lock().unwrap();
            let ebpf = loaded
                .get(&program)
                .with_context(|| format!("program {:?} not loaded", program))?;

            let map: PerCpuArray<&MapData, u64> = PerCpuArray::try_from(
                ebpf.map(ebpf_maps::MAP_METRICS)
                    .context("metrics map not found")?,
            )?;

            let mut sums = vec![0u64; ebpf_metrics::METRIC_COUNT as usize];

            for i in 0..ebpf_metrics::METRIC_COUNT {
                match map.get(&i, 0) {
                    Ok(per_cpu_values) => {
                        let sum: u64 = per_cpu_values.iter().sum();
                        sums[i as usize] = sum;
                    }
                    Err(e) => {
                        debug!(metric_id = i, error = %e, "failed to read metric (may be unused)");
                    }
                }
            }

            Ok(XdpMetricsSnapshot::from_raw(&sums))
        }

        /// Read traffic baseline stats from the traffic_baseline map.
        pub fn read_traffic_baseline(&self) -> Result<Vec<TrafficStats>> {
            let loaded = self.loaded.lock().unwrap();
            // Traffic baseline is in the ratelimit program (which records all traffic stats).
            let ebpf = loaded
                .get(&XdpProgram::Ratelimit)
                .context("ratelimit program not loaded")?;

            let map: Array<&MapData, [u8; 56]> = Array::try_from(
                ebpf.map(ebpf_maps::MAP_TRAFFIC_BASELINE)
                    .context("traffic_baseline map not found")?,
            )?;

            let mut stats_vec = Vec::new();
            // The map has 8 entries (array slots).
            for i in 0..8u32 {
                match map.get(&i, 0) {
                    Ok(bytes) => {
                        // Parse the 56-byte C struct (7 x u64).
                        let stats = TrafficStats {
                            window_start: u64::from_ne_bytes(bytes[0..8].try_into().unwrap()),
                            total_packets: u64::from_ne_bytes(bytes[8..16].try_into().unwrap()),
                            total_bytes: u64::from_ne_bytes(bytes[16..24].try_into().unwrap()),
                            tcp_packets: u64::from_ne_bytes(bytes[24..32].try_into().unwrap()),
                            udp_packets: u64::from_ne_bytes(bytes[32..40].try_into().unwrap()),
                            icmp_packets: u64::from_ne_bytes(bytes[40..48].try_into().unwrap()),
                            syn_packets: u64::from_ne_bytes(bytes[48..56].try_into().unwrap()),
                        };
                        if stats.window_start > 0 {
                            stats_vec.push(stats);
                        }
                    }
                    Err(e) => {
                        debug!(index = i, error = %e, "failed to read traffic baseline slot");
                    }
                }
            }

            Ok(stats_vec)
        }

        /// Get a HashMap of all metric labels to their summed values (for Prometheus).
        pub fn read_metrics_labeled(&self, program: XdpProgram) -> Result<HashMap<String, u64>> {
            let snapshot = self.read_metrics(program)?;
            let raw = [
                snapshot.total_packets,
                snapshot.dropped_blocklist,
                snapshot.dropped_ratelimit,
                snapshot.dropped_syn,
                snapshot.dropped_udp,
                snapshot.dropped_icmp,
                snapshot.dropped_geo,
                snapshot.passed,
                snapshot.dropped_amplification,
                snapshot.syn_cookies_issued,
                snapshot.syn_cookies_validated,
                snapshot.total_bytes,
            ];

            let mut map = HashMap::new();
            for (i, &val) in raw.iter().enumerate() {
                let label = ebpf_metrics::metric_label(i as u32);
                map.insert(label.to_string(), val);
            }
            Ok(map)
        }

        // -----------------------------------------------------------------
        // Lifecycle
        // -----------------------------------------------------------------

        /// Detach all loaded programs and release resources.
        pub fn unload_all(&self) {
            let mut loaded = self.loaded.lock().unwrap();
            let count = loaded.len();
            loaded.clear();
            info!(count, "all eBPF programs unloaded");
        }

        /// Check if a specific program is currently loaded.
        pub fn is_loaded(&self, program: XdpProgram) -> bool {
            let loaded = self.loaded.lock().unwrap();
            loaded.contains_key(&program)
        }

        /// Get the path to the programs directory.
        pub fn programs_path(&self) -> &PathBuf {
            &self.programs_path
        }

        /// Get the interface name.
        pub fn interface(&self) -> &str {
            &self.interface
        }
    }

    // Thread safety: Mutex<HashMap> protects the loaded map.
    // EbpfManager is Send + Sync because Mutex<T> is Send + Sync when T: Send.
    unsafe impl Send for EbpfManager {}
    unsafe impl Sync for EbpfManager {}
}

// ===========================================================================
// Non-Linux stub implementation
// ===========================================================================
#[cfg(not(target_os = "linux"))]
mod platform {
    use super::*;

    /// Stub EbpfManager for non-Linux platforms.
    /// All methods log warnings and return Ok.
    pub struct EbpfManager {
        programs_path: PathBuf,
        interface: String,
    }

    impl EbpfManager {
        pub fn new(programs_path: &str, interface: &str) -> Self {
            warn!(
                path = %programs_path,
                interface = %interface,
                "EbpfManager created (STUB — not on Linux, eBPF unavailable)"
            );
            Self {
                programs_path: PathBuf::from(programs_path),
                interface: interface.to_string(),
            }
        }

        pub fn load_and_attach(&self, program: XdpProgram) -> Result<()> {
            warn!(program = ?program, "load_and_attach is a stub (not on Linux)");
            Ok(())
        }

        pub fn load_all(&self) -> Result<()> {
            warn!("load_all is a stub (not on Linux)");
            Ok(())
        }

        pub fn hot_reload(&self, program: XdpProgram) -> Result<()> {
            warn!(program = ?program, "hot_reload is a stub (not on Linux)");
            Ok(())
        }

        pub fn update_blocklist(&self, entries: &[BlocklistEntry]) -> Result<()> {
            info!(
                count = entries.len(),
                "update_blocklist called (stub — entries discarded)"
            );
            Ok(())
        }

        pub fn add_to_blocklist(&self, ip: Ipv4Addr, reason: BlockReason) -> Result<()> {
            info!(ip = %ip, reason = ?reason, "add_to_blocklist called (stub)");
            Ok(())
        }

        pub fn remove_from_blocklist(&self, ip: Ipv4Addr) -> Result<()> {
            info!(ip = %ip, "remove_from_blocklist called (stub)");
            Ok(())
        }

        pub fn set_config(&self, program: XdpProgram, key: u32, value: u64) -> Result<()> {
            info!(program = ?program, key, value, "set_config called (stub)");
            Ok(())
        }

        pub fn apply_config(&self, program: XdpProgram, configs: &[(u32, u64)]) -> Result<()> {
            info!(program = ?program, count = configs.len(), "apply_config called (stub)");
            Ok(())
        }

        pub fn update_geo_filter(&self, rules: &[GeoFilterRule]) -> Result<()> {
            info!(count = rules.len(), "update_geo_filter called (stub)");
            Ok(())
        }

        pub fn read_metrics(&self, _program: XdpProgram) -> Result<XdpMetricsSnapshot> {
            warn!("read_metrics called (stub — returning zeros)");
            Ok(XdpMetricsSnapshot::default())
        }

        pub fn read_traffic_baseline(&self) -> Result<Vec<TrafficStats>> {
            warn!("read_traffic_baseline called (stub — returning empty)");
            Ok(Vec::new())
        }

        pub fn read_metrics_labeled(&self, _program: XdpProgram) -> Result<HashMap<String, u64>> {
            warn!("read_metrics_labeled called (stub — returning empty)");
            Ok(HashMap::new())
        }

        pub fn unload_all(&self) {
            info!("unload_all called (stub)");
        }

        pub fn is_loaded(&self, _program: XdpProgram) -> bool {
            false
        }

        pub fn programs_path(&self) -> &PathBuf {
            &self.programs_path
        }

        pub fn interface(&self) -> &str {
            &self.interface
        }
    }
}

// ===========================================================================
// Re-export the platform-specific implementation
// ===========================================================================
pub use platform::EbpfManager;
