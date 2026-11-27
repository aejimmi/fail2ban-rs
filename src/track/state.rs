//! Ban record type used across the crate.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// A single ban record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BanRecord {
    /// The banned IP address.
    pub ip: IpAddr,
    /// Which jail triggered the ban.
    pub jail_id: String,
    /// When the ban was applied (unix timestamp).
    pub banned_at: i64,
    /// When the ban expires (`None` = permanent).
    pub expires_at: Option<i64>,
}

/// One matched log line retained as evidence for an automatic ban.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BanLogLine {
    /// Matching input, limited to the first 4 KiB of UTF-8.
    pub text: String,
    /// Whether the captured line exceeded the byte limit.
    pub truncated: bool,
}

impl BanLogLine {
    pub(crate) fn capture(line: &str) -> Self {
        const MAX_BYTES: usize = 4 * 1024;
        let end = line.floor_char_boundary(MAX_BYTES);
        Self {
            text: line.get(..end).unwrap_or(line).to_owned(),
            truncated: end < line.len(),
        }
    }
}
