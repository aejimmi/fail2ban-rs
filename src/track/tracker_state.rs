//! Shared tracker state.
//!
//! Groups all mutable tracker state into cohesive sub-structs (failure buffers,
//! the in-memory ban index, and aggregate counters) alongside the persistent
//! store and IO handles, keeping per-function argument counts low.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;

use etchdb::{Store, WalBackend};

use tokio::sync::mpsc;

use crate::enforce::FirewallCmd;
use crate::logging::Logger;
use crate::track::ban_calc::JailParams;
use crate::track::circular::CircularTimestamps;
use crate::track::manual::ManualBanOutcome;
#[cfg(feature = "maxmind")]
use crate::track::maxmind::MaxmindState;
use crate::track::persist::BanState;
use crate::track::unban::UnbanOutcome;

/// Key identifying a failure/ban stream: the offending IP and the jail id.
pub(super) type FailKey = (IpAddr, String);

/// Per-key failure timestamp buffer.
pub(super) struct FailState {
    /// Ring buffer of recent failure timestamps for this (ip, jail).
    pub(super) timestamps: CircularTimestamps,
}

/// Aggregate ban/unban/failure counters, both global and per-jail.
#[derive(Default)]
pub(super) struct Counters {
    /// Total bans applied since startup.
    pub(super) total_bans: u64,
    /// Total unbans applied since startup.
    pub(super) total_unbans: u64,
    /// Total failures observed since startup.
    pub(super) total_failures: u64,
    /// Per-jail ban totals.
    pub(super) jail_bans: HashMap<String, u64>,
    /// Per-jail failure totals.
    pub(super) jail_failures: HashMap<String, u64>,
}

/// In-memory mirror of the persisted ban set plus the soonest-expiry hint.
#[derive(Default)]
pub(super) struct BanIndex {
    /// Currently-banned (ip, jail) keys. Mirrors the store's `bans` collection
    /// so the failure hot path avoids taking a store lock.
    pub(super) banned_keys: HashSet<FailKey>,
    /// Soonest known ban expiry (unix ts); drives the sweep wakeup without a
    /// per-iteration store read. Always `<=` the true soonest expiry (early is
    /// safe — a spurious wakeup just re-sweeps and recomputes).
    pub(super) next_expiry: Option<i64>,
}

/// Manual bans whose firewall acknowledgement is still outstanding.
#[derive(Default)]
pub(super) struct PendingManualBans {
    /// Outstanding manual bans keyed by (ip, jail), mapped to the id of the
    /// ack waiter that owns them. A resolution whose id no longer matches (the
    /// ban was unbanned, expired, or rolled back meanwhile) must not touch state.
    pub(super) by_key: HashMap<FailKey, u64>,
    /// Next waiter id to hand out.
    pub(super) next_id: u64,
}

impl PendingManualBans {
    /// Register a pending manual ban and return its waiter id.
    pub(super) fn insert(&mut self, key: FailKey) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.by_key.insert(key, id);
        id
    }

    /// Remove the pending entry for `key` if it is still owned by `id`;
    /// returns whether it was.
    pub(super) fn resolve(&mut self, key: &FailKey, id: u64) -> bool {
        if self.by_key.get(key) != Some(&id) {
            return false;
        }
        self.by_key.remove(key);
        true
    }
}

/// All mutable tracker state, grouped to reduce function argument counts.
pub(super) struct TrackerState {
    /// Compiled per-jail parameters, keyed by jail id.
    pub(super) jail_params: HashMap<String, JailParams>,
    /// Active failure buffers, keyed by (ip, jail).
    pub(super) failures: HashMap<FailKey, FailState>,
    /// WAL-backed persistent ban state.
    pub(super) store: Arc<Store<BanState, WalBackend<BanState>>>,
    /// In-memory ban index and next-expiry hint.
    pub(super) index: BanIndex,
    /// Runtime counters.
    pub(super) counters: Counters,
    /// Startup timestamp (unix ts), for uptime reporting.
    pub(super) started_at: i64,
    /// Escalation-count decay window (seconds); `<= 0` disables decay. Counts
    /// whose most recent ban is older than this are reset by the sweep.
    pub(super) ban_count_decay: i64,
    /// Channel to the firewall executor.
    pub(super) executor_tx: mpsc::Sender<FirewallCmd>,
    /// Channel for spawned manual-ban ack waiters to report back on.
    pub(super) resolve_tx: mpsc::Sender<ManualBanOutcome>,
    /// Manual bans awaiting their firewall acknowledgement.
    pub(super) pending_manual: PendingManualBans,
    pub(super) pending_unbans: HashSet<FailKey>,
    pub(super) unban_retry_after: HashMap<FailKey, i64>,
    pub(super) unban_outcome_tx: mpsc::Sender<UnbanOutcome>,
    /// Whether reconcile requests are sent to the executor. They travel on
    /// `executor_tx`, ordered with this tracker's bans and unbans.
    pub(super) reconcile_enabled: bool,
    /// Rotating queue of ban keys still to be reconciled in the current pass,
    /// so capped reconcile batches eventually cover every active ban.
    pub(super) reconcile_queue: VecDeque<FailKey>,
    /// Optional structured event logger.
    pub(super) logger: Option<Logger>,
    /// GeoIP enrichment state.
    #[cfg(feature = "maxmind")]
    pub(super) maxmind: MaxmindState,
}

impl TrackerState {
    /// Log and webhook-notify a ban.
    pub(super) fn notify_ban(&self, ip: IpAddr, jail_id: &str, ban_time: i64, manual: bool) {
        if let Some(ref t) = self.logger {
            t.log_ban(ip, jail_id, ban_time, manual);
        }
        if let Some(params) = self.jail_params.get(jail_id)
            && let Some(ref url) = params.webhook
        {
            crate::webhook::notify_ban(url, ip, jail_id, ban_time);
        }
    }

    /// Log and webhook-notify an unban.
    pub(super) fn notify_unban(&self, ip: IpAddr, jail_id: &str, manual: bool) {
        if let Some(ref t) = self.logger {
            t.log_unban(ip, jail_id, manual);
        }
        if let Some(params) = self.jail_params.get(jail_id)
            && let Some(ref url) = params.webhook
        {
            crate::webhook::notify_unban(url, ip, jail_id);
        }
    }
}
