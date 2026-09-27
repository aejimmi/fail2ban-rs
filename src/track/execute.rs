//! Shared ban/unban execution primitives.
//!
//! These mutate [`TrackerState`], persist to the store, and drive the firewall
//! executor. They are shared by the failure hot path (automatic bans), command
//! handling (manual ban/unban), and the sweep (expiry unbans).

use std::net::IpAddr;

use tokio::sync::oneshot;
use tracing::warn;

use crate::enforce::FirewallCmd;
use crate::error::{Error, Result};
use crate::track::persist::BanCount;
use crate::track::state::BanRecord;
use crate::track::tracker_state::{FailKey, TrackerState};

/// Why a recorded ban was rolled back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RollbackReason {
    /// The executor channel was closed; the ban command was never delivered.
    ChannelClosed,
    /// The firewall backend reported an error applying the ban.
    FirewallBanFailed,
    /// The firewall did not acknowledge the ban in time.
    Timeout,
}

impl RollbackReason {
    /// Stable label for structured logs.
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::ChannelClosed => "channel_closed",
            Self::FirewallBanFailed => "firewall_ban_failed",
            Self::Timeout => "firewall_ban_timeout",
        }
    }
}

/// Automatic ban: record the ban, send the fire-and-forget firewall command,
/// and notify. If the executor is gone the ban is rolled back and no
/// notification fires (the firewall never saw it).
///
/// `new_ban_count` carries the escalation counter so the count increment and
/// the ban record land in one atomic store write.
pub(super) async fn execute_ban(
    ip: IpAddr,
    jail_id: &str,
    ban_time: i64,
    new_ban_count: Option<u32>,
    s: &mut TrackerState,
) {
    let ban = match record_ban(ip, jail_id, ban_time, new_ban_count, s) {
        Ok(ban) => ban,
        Err(e) => {
            warn!(%ip, jail = %jail_id, error = %e, "ban not applied because persistence failed");
            return;
        }
    };
    if s.executor_tx.send(ban_cmd(&ban, None)).await.is_err() {
        warn!(%ip, jail = %jail_id, "executor channel closed");
        rollback_ban(ip, jail_id, RollbackReason::ChannelClosed, s);
        return;
    }
    s.notify_ban(ip, jail_id, ban_time, false);
}

/// Persist a ban record (and any updated ban count) in a single transaction,
/// index it, clear stale failures, and bump counters. Returns the record.
pub(super) fn record_ban(
    ip: IpAddr,
    jail_id: &str,
    ban_time: i64,
    new_ban_count: Option<u32>,
    s: &mut TrackerState,
) -> Result<BanRecord> {
    let now = chrono::Utc::now().timestamp();
    let expires_at = (ban_time >= 0).then(|| now.saturating_add(ban_time));
    let key: FailKey = (ip, jail_id.to_string());
    let ban = BanRecord {
        ip,
        jail_id: jail_id.to_string(),
        banned_at: now,
        expires_at,
    };
    persist_then_apply(
        s,
        |state| persist_ban(state, &key, &ban, new_ban_count),
        |state| {
            // A failed write leaves the failure buffer and index intact.
            state.failures.remove(&key);
            state.index.banned_keys.insert(key.clone());
            if let Some(exp) = expires_at {
                state.index.next_expiry =
                    Some(state.index.next_expiry.map_or(exp, |cur| cur.min(exp)));
            }
            state.counters.total_bans += 1;
            *state
                .counters
                .jail_bans
                .entry(jail_id.to_string())
                .or_insert(0) += 1;
            ban.clone()
        },
    )
}

/// Run in-memory changes only after the persistent write succeeds.
fn persist_then_apply<S, T>(
    state: &mut S,
    persist: impl FnOnce(&S) -> Result<()>,
    apply: impl FnOnce(&mut S) -> T,
) -> Result<T> {
    persist(state)?;
    Ok(apply(state))
}

/// Build the firewall `Ban` command for a record.
pub(super) fn ban_cmd(ban: &BanRecord, done: Option<oneshot::Sender<Result<()>>>) -> FirewallCmd {
    FirewallCmd::Ban {
        ip: ban.ip,
        jail_id: ban.jail_id.clone(),
        banned_at: ban.banned_at,
        expires_at: ban.expires_at,
        done,
    }
}

/// Persist the ban record and any updated escalation count in one transaction.
fn persist_ban(
    s: &TrackerState,
    key: &FailKey,
    ban: &BanRecord,
    new_ban_count: Option<u32>,
) -> Result<()> {
    s.store
        .write(|tx| {
            tx.bans.put(key.clone(), ban.clone())?;
            if let Some(count) = new_ban_count {
                // Stamp the ban timestamp so the sweep can decay stale counters.
                tx.ban_counts.put(
                    ban.ip,
                    BanCount {
                        count,
                        last_ban: ban.banned_at,
                    },
                )?;
            }
            Ok(())
        })
        .map_err(|e| Error::persistence(format!("recording ban: {e}")))
}

/// Shared unban execution: drop the ban index entry, update counters, send
/// firewall command, notify. The store record is deleted by the caller.
pub(super) async fn execute_unban(ip: IpAddr, jail_id: &str, manual: bool, s: &mut TrackerState) {
    let key = (ip, jail_id.to_string());
    s.index.banned_keys.remove(&key);
    s.pending_manual.by_key.remove(&key);
    s.counters.total_unbans += 1;
    let cmd = FirewallCmd::Unban {
        ip,
        jail_id: jail_id.to_string(),
    };
    if s.executor_tx.send(cmd).await.is_err() {
        warn!("executor channel closed");
    }
    s.notify_unban(ip, jail_id, manual);
}

/// Roll back a ban the firewall never applied.
///
/// Deletes the persisted ban record, drops the index entry, and decrements the
/// counters `record_ban` bumped. Idempotent via `banned_keys`: a ban already
/// unbanned (or rolled back) is left untouched. No firewall `Unban` is issued —
/// the kernel never had the ban. The failure buffer was cleared by
/// `record_ban` and stays cleared, so the IP re-accumulates and retries.
pub(super) fn rollback_ban(
    ip: IpAddr,
    jail_id: &str,
    reason: RollbackReason,
    s: &mut TrackerState,
) {
    let key: FailKey = (ip, jail_id.to_string());
    s.pending_manual.by_key.remove(&key);
    if !s.index.banned_keys.remove(&key) {
        return;
    }
    if let Err(e) = s.store.write(|tx| {
        tx.bans.delete(&key);
        Ok(())
    }) {
        warn!(error = %e, "rollback persist failed: {e}");
    }
    s.counters.total_bans = s.counters.total_bans.saturating_sub(1);
    if let Some(v) = s.counters.jail_bans.get_mut(jail_id) {
        *v = v.saturating_sub(1);
    }
    warn!(%ip, jail = %jail_id, reason = reason.as_str(), "ban rolled back");
}

#[cfg(test)]
mod persistence_failure_test {
    use super::*;

    #[test]
    fn failed_write_prevents_following_state_mutation() {
        let mut indexed_and_counted = false;
        let result = persist_then_apply(
            &mut indexed_and_counted,
            |_| Err(Error::persistence("injected WAL failure")),
            |state| *state = true,
        );
        assert!(matches!(result, Err(Error::Persistence { .. })));
        assert!(!indexed_and_counted);
    }
}
