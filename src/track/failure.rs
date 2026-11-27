//! Failure handling — count failures and ban on threshold.

use std::collections::{HashMap, VecDeque};

#[cfg(not(feature = "maxmind"))]
use tracing::info;
use tracing::{debug, warn};

use crate::detect::watcher::Failure;
use crate::track::ban_calc::calc_ban_time;
use crate::track::circular::CircularTimestamps;
use crate::track::execute::execute_ban;
use crate::track::tracker_state::{FailKey, FailState, TrackerState};

/// Record a failure and, if the jail's threshold is reached, trigger a ban.
pub(super) async fn handle_failure(mut failure: Failure, s: &mut TrackerState) {
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

    if record_failure(&mut failure, key, s) {
        ban_on_threshold(failure, s).await;
    }
}

/// Push the failure into its (ip, jail) window; returns whether the jail's
/// threshold is now reached. Unknown jails are logged and ignored.
fn record_failure(failure: &mut Failure, key: FailKey, s: &mut TrackerState) -> bool {
    const MAX_LOG_LINES: usize = 16;
    let Some(params) = s.jail_params.get(&failure.jail_id) else {
        warn!(
            jail = %failure.jail_id,
            reason = "unknown_jail",
            "failure ignored"
        );
        return false;
    };
    let (max_retry, find_time) = (params.max_retry, params.find_time);
    let fail_state = s.failures.entry(key).or_insert_with(|| FailState {
        timestamps: CircularTimestamps::new(max_retry as usize),
        log_lines: VecDeque::new(),
    });
    fail_state.timestamps.push(failure.timestamp);
    if params.save_ban_logs && (failure.log_line.is_some() || !fail_state.log_lines.is_empty()) {
        let limit = fail_state.timestamps.capacity().min(MAX_LOG_LINES);
        if fail_state.log_lines.len() == limit {
            fail_state.log_lines.pop_front();
        }
        fail_state.log_lines.push_back(failure.log_line.take());
    }
    fail_state.timestamps.threshold_reached(find_time)
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

    log_threshold_ban(&failure, effective_ban_time, count + 1, s);
    execute_ban(
        failure.ip,
        &failure.jail_id,
        effective_ban_time,
        Some(count + 1),
        s,
    )
    .await;
}

/// Log a threshold ban, GeoIP-enriched when the `maxmind` feature is on.
#[cfg_attr(not(feature = "maxmind"), allow(unused_variables))]
fn log_threshold_ban(failure: &Failure, ban_time: i64, ban_count: u32, s: &TrackerState) {
    #[cfg(feature = "maxmind")]
    {
        let enrichment = s.maxmind.enrich(failure.ip, &failure.jail_id);
        crate::track::maxmind::log_ban_event(failure, ban_time, ban_count, &enrichment);
    }
    #[cfg(not(feature = "maxmind"))]
    info!(
        ip = %failure.ip,
        jail = %failure.jail_id,
        ban_time,
        ban_count,
        reason = "threshold",
        "banned"
    );
}

/// Increment a per-jail counter without cloning the key on the common (hit) path.
fn incr_jail_counter(map: &mut HashMap<String, u64>, jail_id: &str) {
    if let Some(v) = map.get_mut(jail_id) {
        *v += 1;
    } else {
        map.insert(jail_id.to_string(), 1);
    }
}
