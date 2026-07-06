//! Tracking — failure counting, ban/unban decisions, and state persistence.
//!
//! Owns all mutable state: failure counts (ring buffers), active bans,
//! and runtime statistics. Receives Failure events from watchers and
//! TrackerCmd queries from the server. Sends FirewallCmd to enforce.

/// Escalating ban time calculator.
pub mod ban_calc;
/// Fixed-capacity ring buffer for failure timestamps.
pub mod circular;
/// MaxMind GeoIP enrichment.
#[cfg(feature = "maxmind")]
pub mod maxmind;
/// WAL-backed ban state persistence.
pub mod persist;
/// Serializable ban record.
pub mod state;

mod commands;
mod execute;
mod failure;
mod run;
mod sweep;
mod tracker_state;

pub use run::run;

use std::collections::HashMap;
use std::net::IpAddr;

use serde::Serialize;
use tokio::sync::oneshot;

use crate::config::JailConfig;
use crate::track::state::BanRecord;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Commands from the server to the tracker (query/mutate state).
pub enum TrackerCmd {
    /// Return all active bans.
    QueryBans {
        respond: oneshot::Sender<Vec<BanRecord>>,
    },
    /// Manually ban an IP.
    ManualBan {
        ip: IpAddr,
        jail_id: String,
        ban_time: i64,
        respond: oneshot::Sender<crate::error::Result<()>>,
    },
    /// Manually unban an IP.
    ManualUnban {
        ip: IpAddr,
        jail_id: String,
        respond: oneshot::Sender<crate::error::Result<()>>,
    },
    /// The executor failed to apply an automatic ban; roll back tracker state.
    ///
    /// Sent by the executor (not the server). The tracker removes the ban
    /// record and index entry and adjusts counters, leaving the failure buffer
    /// cleared so the IP re-accumulates failures and retries.
    BanApplyFailed { ip: IpAddr, jail_id: String },
    /// Return runtime statistics.
    GetStats { respond: oneshot::Sender<Stats> },
    /// Hot-reload global and jail configurations.
    UpdateConfig {
        global: crate::config::GlobalConfig,
        jails: HashMap<String, JailConfig>,
    },
}

/// Runtime statistics snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct Stats {
    /// Seconds since the tracker started.
    pub uptime_secs: i64,
    /// Number of currently-active bans.
    pub active_bans: usize,
    /// Total bans applied since startup.
    pub total_bans: u64,
    /// Total unbans applied since startup.
    pub total_unbans: u64,
    /// Total failures observed since startup.
    pub total_failures: u64,
    /// Per-jail statistics.
    pub jails: HashMap<String, JailStats>,
}

/// Per-jail statistics.
#[derive(Debug, Clone, Default, Serialize)]
pub struct JailStats {
    /// Number of currently-active bans for this jail.
    pub active_bans: usize,
    /// Total bans applied for this jail since startup.
    pub total_bans: u64,
    /// Total failures observed for this jail since startup.
    pub total_failures: u64,
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
mod test_support;

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
mod commands_test;
#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
mod failure_test;
#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
mod regression_test;
#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
mod run_test;
#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
mod sweep_test;
