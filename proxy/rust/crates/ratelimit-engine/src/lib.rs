//! Sliding-window rate limiter with local in-memory counters and optional
//! Redis-backed distributed state.
//!
//! TODO(phase-2): Implement Redis-backed distributed sliding window using
//!                sorted sets or Lua scripts so rate limits are enforced
//!                consistently across multiple proxy instances.

use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use jzap_shared::{JzapError, RateLimitConfig};
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Decision enum
// ---------------------------------------------------------------------------

/// The outcome of a rate-limit check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitDecision {
    /// Request is within limits — let it through.
    Allow,
    /// Request exceeds the sustained rate — block or return 429.
    RateLimit,
    /// Request is borderline — issue a JS/CAPTCHA challenge instead of
    /// hard-blocking.
    Challenge,
}

// ---------------------------------------------------------------------------
// Internal counter
// ---------------------------------------------------------------------------

/// Per-key sliding-window state.
#[derive(Debug, Clone)]
struct WindowCounter {
    /// Accumulated count in the current window.
    count: u64,
    /// Start of the current window (unix seconds).
    window_start: u64,
}

// ---------------------------------------------------------------------------
// RateLimiter
// ---------------------------------------------------------------------------

/// Core rate-limiter combining a fast local [`DashMap`] with an optional
/// Redis connection for cross-instance synchronisation.
pub struct RateLimiter {
    config: RateLimitConfig,
    /// Per-key in-memory sliding-window counters.
    counters: DashMap<String, WindowCounter>,
    /// Optional Redis connection manager.
    ///
    /// TODO(phase-2): Replace with `redis::aio::ConnectionManager` once
    ///                the Redis integration is wired up.
    _redis: Option<()>,
}

impl RateLimiter {
    /// Create a purely in-memory rate limiter.
    pub fn new(config: RateLimitConfig) -> Self {
        info!(
            rps = config.requests_per_second,
            burst = config.burst_size,
            window = config.window_seconds,
            "RateLimiter created (in-memory only)"
        );
        Self {
            config,
            counters: DashMap::new(),
            _redis: None,
        }
    }

    /// Create a rate limiter that also synchronises with Redis.
    ///
    /// TODO(phase-2): Actually establish a Redis connection here using
    ///                `redis::Client::open` + `get_tokio_connection_manager`.
    pub async fn with_redis(config: RateLimitConfig, _redis_url: &str) -> Result<Self, JzapError> {
        warn!("with_redis is a stub — falling back to in-memory only");
        Ok(Self {
            config,
            counters: DashMap::new(),
            _redis: None,
        })
    }

    /// Check whether `key` (typically a client IP) should be allowed,
    /// rate-limited, or challenged.
    pub fn check_rate_limit(&self, key: &str) -> Result<RateLimitDecision, JzapError> {
        let now = Self::now_secs();
        let limit = self.config.requests_per_second * self.config.window_seconds;
        let burst_limit = limit + self.config.burst_size;

        let count = self
            .counters
            .get(key)
            .map(|c| {
                let c = c.value();
                if now - c.window_start >= self.config.window_seconds {
                    0 // window expired — effectively zero
                } else {
                    c.count
                }
            })
            .unwrap_or(0);

        let decision = if count < limit {
            RateLimitDecision::Allow
        } else if count < burst_limit {
            RateLimitDecision::Challenge
        } else {
            RateLimitDecision::RateLimit
        };

        Ok(decision)
    }

    /// Increment the counter for `key` and return the new count within the
    /// current window.
    pub fn increment(&self, key: &str) -> Result<u64, JzapError> {
        let now = Self::now_secs();

        let mut entry = self
            .counters
            .entry(key.to_string())
            .or_insert(WindowCounter {
                count: 0,
                window_start: now,
            });

        let counter = entry.value_mut();

        // Reset the window if it has expired.
        if now - counter.window_start >= self.config.window_seconds {
            counter.count = 0;
            counter.window_start = now;
        }

        counter.count += 1;
        Ok(counter.count)
    }

    /// Return the current request count for `key` in the active window.
    pub fn get_count(&self, key: &str) -> Result<u64, JzapError> {
        let now = Self::now_secs();

        let count = self
            .counters
            .get(key)
            .map(|c| {
                let c = c.value();
                if now - c.window_start >= self.config.window_seconds {
                    0
                } else {
                    c.count
                }
            })
            .unwrap_or(0);

        Ok(count)
    }

    // -- helpers ----------------------------------------------------------

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs()
    }
}
