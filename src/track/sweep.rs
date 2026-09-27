//! Periodic sweep — expiry unbans, stale-failure pruning, escalation-count
//! decay, and reconcile requests.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;

use etchdb::{Store, WalBackend};
use tracing::{debug, info, warn};

use crate::enforce::FirewallCmd;
use crate::track::ban_calc::JailParams;
use crate::track::persist::BanState;
use crate::track::state::BanRecord;
use crate::track::tracker_state::{FailKey, FailState, TrackerState};
use crate::track::unban::start_unban;

/// Cap on the number of bans verified per reconcile tick, bounding the
/// executor's per-tick shell-outs. The rotating queue covers the remainder on
/// later ticks.
const RECONCILE_MAX_BANS: usize = 1000;

/// Periodic sweep: unban every store record whose expiry has passed, prune stale
/// failure buffers, then recompute the soonest-expiry hint.
///
/// Scanning the ban map (rather than draining a timer heap) means unbans are
/// always driven by the current, authoritative ban record — a manually unbanned
/// and re-banned IP can never be prematurely unbanned by an obsolete timer.
pub(super) async fn process_unbans(s: &mut TrackerState) {
    let now = chrono::Utc::now().timestamp();
    let expired: Vec<FailKey> = s
        .store
        .read()
        .bans
        .iter()
        .filter_map(|(key, ban)| match ban.expires_at {
            Some(exp)
                if exp <= now
                    && !s.pending_unbans.contains(key)
                    && s.unban_retry_after
                        .get(key)
                        .is_none_or(|retry| *retry <= now) =>
            {
                Some(key.clone())
            }
            _ => None,
        })
        .collect();

    for key in expired {
        unban_expired(key, s).await;
    }

    prune_stale_failures(&mut s.failures, &s.jail_params, now);
    prune_decayed_ban_counts(&s.store, s.ban_count_decay, now);
    s.index.next_expiry = s
        .store
        .read()
        .bans
        .iter()
        .filter_map(|(key, b)| {
            b.expires_at.map(|exp| {
                if s.pending_unbans.contains(key) {
                    i64::MAX
                } else {
                    s.unban_retry_after
                        .get(key)
                        .copied()
                        .map_or(exp, |retry| exp.max(retry))
                }
            })
        })
        .min();
}

/// Whether an escalation count has decayed: its most recent ban is older than
/// the decay window. A `decay <= 0` disables decay (counts never go stale),
/// mirroring fail2ban's bantime-decay concept — escalation restarts from zero
/// only after a fully quiet `decay` window.
pub(super) fn ban_count_decayed(last_ban: i64, decay: i64, now: i64) -> bool {
    decay > 0 && last_ban < now - decay
}

/// Drop escalation counters whose most recent ban predates the decay window,
/// bounding the memory the `ban_counts` map can consume over the daemon's life.
///
/// A full reset (rather than a decrement) is deliberate: after a quiet period a
/// returning offender is treated as a first-time offender again.
pub(super) fn prune_decayed_ban_counts(
    store: &Arc<Store<BanState, WalBackend<BanState>>>,
    decay: i64,
    now: i64,
) {
    if decay <= 0 {
        return;
    }
    let stale: Vec<IpAddr> = store
        .read()
        .ban_counts
        .iter()
        .filter(|(_, bc)| ban_count_decayed(bc.last_ban, decay, now))
        .map(|(ip, _)| *ip)
        .collect();
    if stale.is_empty() {
        return;
    }
    let dropped = stale.len();
    if let Err(e) = store.write(|tx| {
        for ip in &stale {
            tx.ban_counts.delete(ip);
        }
        Ok(())
    }) {
        warn!(error = %e, "escalation-count decay persist failed: {e}");
        return;
    }
    info!(dropped, decay, "escalation counts decayed");
}

/// Delete an expired ban from the store and run shared unban handling.
async fn unban_expired(key: FailKey, s: &mut TrackerState) {
    let (ip, ref jail_id) = key;
    start_unban(ip, jail_id.clone(), false, None, s).await;
}

/// Drop failure buffers whose newest timestamp already falls outside the jail's
/// find_time window (or whose jail no longer exists), bounding memory use.
pub(super) fn prune_stale_failures(
    failures: &mut HashMap<FailKey, FailState>,
    jail_params: &HashMap<String, JailParams>,
    now: i64,
) {
    failures.retain(|key, fs| match jail_params.get(&key.1) {
        Some(params) => fs
            .timestamps
            .newest()
            .is_none_or(|newest| newest >= now - params.find_time),
        None => false,
    });
}

/// Ask the executor to reconcile the next batch of active bans.
///
/// Batches are drawn from a rotating key queue (see [`next_reconcile_batch`])
/// so successive ticks walk the whole ban set instead of re-checking the same
/// subset forever. Sent on the executor command channel (ordered with bans
/// and unbans) with `try_send` so the tracker's event loop never blocks — if
/// the channel is full (executor still busy) or closed the batch is dropped
/// and its bans are revisited on the next pass.
pub(super) fn request_reconcile(s: &mut TrackerState) {
    if !s.reconcile_enabled {
        return;
    }
    let store_state = s.store.read();
    let bans = next_reconcile_batch(
        &mut s.reconcile_queue,
        &store_state.bans,
        RECONCILE_MAX_BANS,
    )
    .into_iter()
    .filter(|b| !s.pending_unbans.contains(&(b.ip, b.jail_id.clone())))
    .collect::<Vec<_>>();
    drop(store_state);
    if bans.is_empty() {
        return;
    }
    debug!(
        batch = bans.len(),
        remaining = s.reconcile_queue.len(),
        "reconcile batch requested"
    );
    if s.executor_tx
        .try_send(FirewallCmd::Reconcile { bans })
        .is_err()
    {
        warn!("reconcile request dropped (executor busy or gone)");
    }
}

/// Pop up to `max` still-active bans off the rotating reconcile queue.
///
/// When the queue is empty it is refilled with every current ban key, starting
/// a new pass. Keys whose ban has since been removed are skipped. With `N`
/// stable bans every ban is visited within `ceil(N / max)` calls.
pub(super) fn next_reconcile_batch(
    queue: &mut VecDeque<FailKey>,
    bans: &HashMap<FailKey, BanRecord>,
    max: usize,
) -> Vec<BanRecord> {
    if queue.is_empty() {
        queue.extend(bans.keys().cloned());
    }
    let mut batch = Vec::with_capacity(max.min(queue.len()));
    while batch.len() < max {
        let Some(key) = queue.pop_front() else {
            break;
        };
        if let Some(ban) = bans.get(&key) {
            batch.push(ban.clone());
        }
    }
    batch
}

/// Reconcile every active ban of one jail immediately (post-reload healing).
///
/// Sent in [`RECONCILE_MAX_BANS`]-sized chunks with `try_send`; a chunk that
/// cannot be queued is left to the periodic rotation.
pub(super) fn request_jail_reconcile(jail_id: &str, s: &TrackerState) {
    if !s.reconcile_enabled {
        return;
    }
    let bans: Vec<BanRecord> = s
        .store
        .read()
        .bans
        .values()
        .filter(|b| b.jail_id == jail_id)
        .filter(|b| !s.pending_unbans.contains(&(b.ip, b.jail_id.clone())))
        .cloned()
        .collect();
    info!(jail = %jail_id, bans = bans.len(), "jail reconcile requested");
    for chunk in bans.chunks(RECONCILE_MAX_BANS) {
        let req = FirewallCmd::Reconcile {
            bans: chunk.to_vec(),
        };
        if s.executor_tx.try_send(req).is_err() {
            warn!(jail = %jail_id, "jail reconcile request dropped; periodic reconcile will cover it");
            return;
        }
    }
}
