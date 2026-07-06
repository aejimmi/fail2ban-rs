//! Failure handling — count failures and ban on threshold.

use std::collections::HashMap;

#[cfg(not(feature = "maxmind"))]
use tracing::info;
use tracing::{debug, warn};

use crate::detect::watcher::Failure;
use crate::track::ban_calc::calc_ban_time;
use crate::track::circular::CircularTimestamps;
use crate::track::execute::execute_ban;
use crate::track::tracker_state::{FailKey, FailState, TrackerState};

/// Record a failure and, if the jail's threshold is reached, trigger a ban.
pub(super) async fn handle_failure(failure: Failure, s: &mut TrackerState) {
    s.counters.total_failures += 1;
    incr_jail_counter(&mut s.counters.jail_failures, &failure.jail_id);

    // Build the (ip, jail) key once and reuse it for the membership check and
    // the failures-map entry. The common case (not banned, below threshold)
    // takes no store lock — `banned_keys` mirrors the persisted ban set.
    let key: FailKey = (failure.ip, failure.jail_id.clone());
    if s.index.banned_keys.contains(&key) {
        debug!(
            ip = %failure.ip,
            jail = %failure.jail_id,
            reason = "already_banned",
            "failure ignored"
        );
        return;
    }

    let Some(params) = s.jail_params.get(&failure.jail_id) else {
        warn!(
            jail = %failure.jail_id,
            reason = "unknown_jail",
            "failure ignored"
        );
        return;
    };
    let max_retry = params.max_retry;
    let find_time = params.find_time;

    let fail_state = s.failures.entry(key).or_insert_with(|| FailState {
        timestamps: CircularTimestamps::new(max_retry as usize),
    });
    fail_state.timestamps.push(failure.timestamp);

    if fail_state.timestamps.threshold_reached(find_time) {
        ban_on_threshold(failure, s).await;
    }
}

/// Execute a threshold-triggered ban: read and increment the escalation count,
/// compute the effective ban time, log (with optional GeoIP enrichment), and ban.
async fn ban_on_threshold(failure: Failure, s: &mut TrackerState) {
    let Some(params) = s.jail_params.get(&failure.jail_id) else {
        return;
    };
    let base_ban_time = params.ban_time;
    let count = s
        .store
        .read()
        .ban_counts
        .get(&failure.ip)
        .map_or(0, |bc| bc.count);
    let effective_ban_time = calc_ban_time(base_ban_time, count, params);

    #[cfg(feature = "maxmind")]
    {
        let enrichment = s.maxmind.enrich(failure.ip, &failure.jail_id);
        crate::track::maxmind::log_ban_event(&failure, effective_ban_time, count + 1, &enrichment);
    }
    #[cfg(not(feature = "maxmind"))]
    info!(
        ip = %failure.ip,
        jail = %failure.jail_id,
        ban_time = effective_ban_time,
        ban_count = count + 1,
        reason = "threshold",
        "banned"
    );

    execute_ban(
        failure.ip,
        &failure.jail_id,
        effective_ban_time,
        false,
        Some(count + 1),
        s,
    )
    .await;
}

/// Increment a per-jail counter without cloning the key on the common (hit) path.
fn incr_jail_counter(map: &mut HashMap<String, u64>, jail_id: &str) {
    if let Some(v) = map.get_mut(jail_id) {
        *v += 1;
    } else {
        map.insert(jail_id.to_string(), 1);
    }
}
