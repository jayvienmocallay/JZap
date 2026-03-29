//! TLS / JA3 fingerprint extraction and known-bot signature matching.
//!
//! TODO(phase-3): Implement full ClientHello parsing (TLS extensions,
//!                cipher suites, elliptic curves) to produce accurate JA3
//!                strings. The current implementation is a placeholder.

use std::fs;

use dashmap::DashMap;
use jzap_shared::FingerprintResult;
use serde::Deserialize;
use tracing::{info, warn};

/// A single entry in the bot-signature database loaded from JSON.
#[derive(Debug, Clone, Deserialize)]
struct BotSignature {
    ja3_hash: String,
    bot_name: String,
}

/// Engine for computing JA3 fingerprints and matching them against a
/// database of known bot / scanner signatures.
pub struct FingerprintEngine {
    /// JA3 hash → bot name.
    signatures: DashMap<String, String>,
}

impl FingerprintEngine {
    /// Create a new engine with an empty signature database.
    pub fn new() -> Self {
        info!("FingerprintEngine created with empty signature DB");
        Self {
            signatures: DashMap::new(),
        }
    }

    /// Load known bot JA3 signatures from a JSON file.
    ///
    /// The file should contain an array of objects, each with `ja3_hash` and
    /// `bot_name` fields.
    ///
    /// TODO(phase-3): Support hot-reload via file watcher or control-plane push.
    pub fn load_signatures(&self, path: &str) -> Result<(), jzap_shared::JzapError> {
        let data = fs::read_to_string(path).map_err(jzap_shared::JzapError::Io)?;

        let entries: Vec<BotSignature> = serde_json::from_str(&data).map_err(|e| {
            jzap_shared::JzapError::Fingerprint(format!("failed to parse signatures: {e}"))
        })?;

        for entry in &entries {
            self.signatures
                .insert(entry.ja3_hash.clone(), entry.bot_name.clone());
        }

        info!(count = entries.len(), path, "loaded bot signatures");
        Ok(())
    }

    /// Compute a JA3 fingerprint from a raw TLS ClientHello message.
    ///
    /// TODO(phase-3): Parse the ClientHello bytes to extract:
    ///   - TLS version
    ///   - Cipher suites
    ///   - Extensions
    ///   - Elliptic curves
    ///   - EC point formats
    /// Then build the canonical JA3 string, MD5-hash it, and check the
    /// signature database.
    pub fn compute_ja3(
        &self,
        _client_hello: &[u8],
    ) -> Result<FingerprintResult, jzap_shared::JzapError> {
        warn!("compute_ja3 is a stub — returning placeholder fingerprint");

        // Placeholder: hash the raw bytes directly (NOT a real JA3).
        let digest = md5::compute(_client_hello);
        let hash = hex::encode(digest.0);

        let bot_match = self.check_known_bot(&hash);

        Ok(FingerprintResult {
            ja3_hash: hash,
            ja3_full: String::from("stub-ja3-string"),
            is_known_bot: bot_match.is_some(),
            bot_name: bot_match,
        })
    }

    /// Look up a JA3 hash in the known-bot signature database.
    ///
    /// Returns `Some(bot_name)` if the hash is recognised, `None` otherwise.
    pub fn check_known_bot(&self, ja3_hash: &str) -> Option<String> {
        self.signatures.get(ja3_hash).map(|v| v.value().clone())
    }
}

impl Default for FingerprintEngine {
    fn default() -> Self {
        Self::new()
    }
}
