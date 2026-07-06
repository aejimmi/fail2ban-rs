//! Periodic sweep — expiry unbans, stale-failure pruning, escalation-count
//! decay, and reconcile requests.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use etchdb::{Store, WalBackend};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::enforce::ReconcileRequest;
use crate::track::ban_calc::JailParams;
use crate::track::execute::execute_unban;
use crate::track::persist::BanState;
use crate::track::state::BanRecord;
use crate::track::tracker_state::{FailKey, FailState, TrackerState};

/// Cap on the number of bans verified per reconcile tick, bounding the
/// executor's per-tick shell-outs. Any remainder is covered by later ticks.
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
            Some(exp) if exp <= now => Some(key.clone()),
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
        .values()
        .filter_map(|b| b.expires_at)
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
    if let Err(e) = s.store.write(|tx| {
        tx.bans.delete(&key);
        Ok(())
    }) {
        warn!(error = %e, "state persist failed: {e}");
    }
    info!(%ip, jail = %jail_id, reason = "expired", "unbanned");
    execute_unban(ip, jail_id, false, s).await;
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

/// Ask the executor to reconcile active bans against the firewall.
///
/// Snapshots up to [`RECONCILE_MAX_BANS`] active bans and hands them to the
/// executor, which does the per-IP `is_banned` shell-outs. Uses `try_send` so
/// the tracker's event loop never blocks here — if the reconcile channel is
/// full (executor still busy) or closed the request is dropped and retried on
/// the next tick.
pub(super) fn request_reconcile(
    reconcile_tx: Option<&mpsc::Sender<ReconcileRequest>>,
    s: &TrackerState,
) {
    let Some(tx) = reconcile_tx else {
        return;
    };
    let store_state = s.store.read();
    let total = store_state.bans.len();
    let bans: Vec<BanRecord> = store_state
        .bans
        .values()
        .take(RECONCILE_MAX_BANS)
        .cloned()
        .collect();
    drop(store_state);
    if bans.is_empty() {
        return;
    }
    if total > RECONCILE_MAX_BANS {
        warn!(
            total,
            capped = RECONCILE_MAX_BANS,
            "reconcile batch capped; remainder deferred to next tick"
        );
    }
    if tx.try_send(ReconcileRequest { bans }).is_err() {
        warn!("reconcile request dropped (executor busy or gone)");
    }
}
