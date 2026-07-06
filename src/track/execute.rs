//! Shared ban/unban execution primitives.
//!
//! These mutate [`TrackerState`], persist to the store, and drive the firewall
//! executor. They are shared by the failure hot path (automatic bans), command
//! handling (manual ban/unban), and the sweep (expiry unbans).

use std::net::IpAddr;

use tracing::warn;

use crate::enforce::FirewallCmd;
use crate::track::persist::BanCount;
use crate::track::state::BanRecord;
use crate::track::tracker_state::{FailKey, TrackerState};

/// Shared ban execution: persist record (and any updated ban count) in a single
/// transaction, index the ban, clear stale failures, send firewall command, notify.
///
/// `new_ban_count` carries the escalation counter for automatic bans so the
/// count increment and the ban record land in one atomic store write (a crash
/// between two separate writes would desync escalation state). Manual bans pass
/// `None`.
pub(super) async fn execute_ban(
    ip: IpAddr,
    jail_id: &str,
    ban_time: i64,
    manual: bool,
    new_ban_count: Option<u32>,
    s: &mut TrackerState,
) {
    let now = chrono::Utc::now().timestamp();
    let expires_at = if ban_time < 0 {
        None
    } else {
        Some(now.saturating_add(ban_time))
    };
    let key: FailKey = (ip, jail_id.to_string());
    let ban = BanRecord {
        ip,
        jail_id: jail_id.to_string(),
        banned_at: now,
        expires_at,
    };

    persist_ban(s, &key, &ban, ip, new_ban_count);

    // Clear the failure buffer so that after any future unban the IP must reach
    // the full threshold again rather than being re-banned by stale failures.
    s.failures.remove(&key);
    s.index.banned_keys.insert(key);
    if let Some(exp) = expires_at {
        s.index.next_expiry = Some(s.index.next_expiry.map_or(exp, |cur| cur.min(exp)));
    }
    s.counters.total_bans += 1;
    *s.counters.jail_bans.entry(jail_id.to_string()).or_insert(0) += 1;

    let cmd = FirewallCmd::Ban {
        ip,
        jail_id: jail_id.to_string(),
        banned_at: now,
        expires_at,
        done: None,
    };
    if s.executor_tx.send(cmd).await.is_err() {
        warn!("executor channel closed");
    }

    s.notify_ban(ip, jail_id, ban_time, manual);
}

/// Persist the ban record and any updated escalation count in one transaction.
fn persist_ban(
    s: &TrackerState,
    key: &FailKey,
    ban: &BanRecord,
    ip: IpAddr,
    new_ban_count: Option<u32>,
) {
    if let Err(e) = s.store.write(|tx| {
        tx.bans.put(key.clone(), ban.clone());
        if let Some(count) = new_ban_count {
            // Stamp the ban timestamp so the sweep can decay stale counters.
            tx.ban_counts.put(
                ip,
                BanCount {
                    count,
                    last_ban: ban.banned_at,
                },
            );
        }
        Ok(())
    }) {
        warn!(error = %e, "state persist failed: {e}");
    }
}

/// Shared unban execution: drop the ban index entry, update counters, send
/// firewall command, notify. The store record is deleted by the caller.
pub(super) async fn execute_unban(ip: IpAddr, jail_id: &str, manual: bool, s: &mut TrackerState) {
    s.index.banned_keys.remove(&(ip, jail_id.to_string()));
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

/// Roll back an automatic ban the firewall failed to apply.
///
/// Deletes the persisted ban record, drops the index entry, and decrements the
/// counters `execute_ban` bumped. Idempotent via `banned_keys`: a ban already
/// unbanned (or rolled back) is left untouched. No firewall `Unban` is issued —
/// the kernel never had the ban. The failure buffer was cleared by
/// `execute_ban` and stays cleared, so the IP re-accumulates and retries.
pub(super) fn rollback_ban(ip: IpAddr, jail_id: &str, s: &mut TrackerState) {
    let key: FailKey = (ip, jail_id.to_string());
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
    warn!(
        %ip,
        jail = %jail_id,
        reason = "firewall_ban_failed",
        "ban rolled back"
    );
}
