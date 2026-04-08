//! Rate limiting for destination announcements.
//!
//! This module provides rate limiting for destination announcements to prevent
//! network flooding and abuse. Each destination is tracked separately with
//! configurable limits.
//!
//! # Overview
//!
//! AnnounceLimits implements a rate limiting system that:
//! - Tracks announcements from each destination
//! - Allows a grace period for initial announcements
//! - Applies penalties for repeated violations
//! - Blocks destinations that exceed their limits
//!
//! # Usage
//!
//! This is used internally by the Transport to limit announcement rates
//! from remote destinations.

use alloc::collections::BTreeMap;

use crate::async_backend::time::{Duration, Instant};

use crate::hash::AddressHash;

/// Configuration for announce rate limiting.
pub struct AnnounceRateLimit {
    /// The target interval between announcements.
    pub target: Duration,
    /// Number of grace period violations before blocking.
    pub grace: u32,
    /// Optional penalty duration to add to block time.
    pub penalty: Option<Duration>,
}

impl Default for AnnounceRateLimit {
    fn default() -> Self {
        Self {
            target: Duration::from_secs(3600),
            grace: 10,
            penalty: Some(Duration::from_secs(7200)),
        }
    }
}

/// Internal entry tracking rate limit state for a single destination.
struct AnnounceLimitEntry {
    /// The rate limit configuration.
    rate_limit: Option<AnnounceRateLimit>,
    /// Number of violations within the grace period.
    violations: u32,
    /// Timestamp of the last announcement.
    last_announce: Instant,
    /// Timestamp until which the destination is blocked.
    blocked_until: Instant,
}

impl AnnounceLimitEntry {
    /// Creates a new entry with the given rate limit configuration.
    pub fn new(rate_limit: Option<AnnounceRateLimit>) -> Self {
        Self {
            rate_limit,
            violations: 0,
            last_announce: Instant::now(),
            blocked_until: Instant::now(),
        }
    }

    /// Handles an incoming announcement and checks if rate limited.
    ///
    /// Returns Some(Duration) if blocked, None if allowed.
    pub fn handle_announce(&mut self) -> Option<Duration> {
        let mut is_blocked = false;
        let now = Instant::now();

        if let Some(ref rate_limit) = self.rate_limit {
            // Check if currently blocked
            if now < self.blocked_until {
                self.blocked_until = now + rate_limit.target;
                if let Some(penalty) = rate_limit.penalty {
                    self.blocked_until += penalty;
                }
                is_blocked = true;
            } else {
                // Check if announcement is too soon
                let next_allowed = self.last_announce + rate_limit.target;
                if now < next_allowed {
                    self.violations += 1;
                    if self.violations >= rate_limit.grace {
                        // Exceeded grace period - block the destination
                        self.violations = 0;
                        self.blocked_until = now + rate_limit.target;
                        is_blocked = true;
                    }
                }
            }
        }

        self.last_announce = now;

        if is_blocked {
            Some(self.blocked_until - now)
        } else {
            None
        }
    }
}

/// Manages rate limits for multiple destination announcements.
pub struct AnnounceLimits {
    /// Map of destination addresses to their rate limit entries.
    limits: BTreeMap<AddressHash, AnnounceLimitEntry>,
}

impl AnnounceLimits {
    /// Creates a new AnnounceLimits manager.
    pub fn new() -> Self {
        Self {
            limits: BTreeMap::new(),
        }
    }

    /// Checks if an announcement from the given destination should be allowed.
    ///
    /// # Arguments
    ///
    /// * `destination` - The destination address to check
    ///
    /// # Returns
    ///
    /// * `Some(Duration)` - If the destination is blocked, returns how long
    /// * `None` - If the announcement is allowed
    pub fn check(&mut self, destination: &AddressHash) -> Option<Duration> {
        if let Some(entry) = self.limits.get_mut(destination) {
            return entry.handle_announce();
        }

        // Create new entry with default limits
        self.limits.insert(
            destination.clone(),
            AnnounceLimitEntry::new(Default::default()),
        );

        None
    }
}
