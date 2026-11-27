//! Ban record type used across the crate.

use crate::ban_target::BanTarget;

use serde::{Deserialize, Serialize};

/// A single ban record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BanRecord {
    /// The banned IP address.
    pub ip: BanTarget,
    /// Which jail triggered the ban.
    pub jail_id: String,
    /// When the ban was applied (unix timestamp).
    pub banned_at: i64,
    /// When the ban expires (`None` = permanent).
    pub expires_at: Option<i64>,
}
