//! Tracker task — single-owner failure counting and ban/unban logic.
//!
//! Owns all mutable state: failure counts (ring buffers), active bans,
//! and runtime statistics. Receives Failure events from watchers and
//! TrackerCmd queries from the server. Sends FirewallCmd to executor.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::net::IpAddr;

use serde::Serialize;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::ban_calc::{build_jail_params, calc_ban_time, JailParams};
use crate::circular::CircularTimestamps;
use crate::config::JailConfig;
use crate::executor::FirewallCmd;
use crate::logging::Logger;
use crate::state::{BanRecord, StateSnapshot};
use crate::watcher::Failure;

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
    /// Return runtime statistics.
    GetStats { respond: oneshot::Sender<Stats> },
    /// Hot-reload jail configurations.
    UpdateJails { jails: HashMap<String, JailConfig> },
}

/// Runtime statistics snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct Stats {
    pub uptime_secs: i64,
    pub active_bans: usize,
    pub total_bans: u64,
    pub total_unbans: u64,
    pub total_failures: u64,
    pub jails: HashMap<String, JailStats>,
}

/// Per-jail statistics.
#[derive(Debug, Clone, Default, Serialize)]
pub struct JailStats {
    pub active_bans: usize,
    pub total_bans: u64,
    pub total_failures: u64,
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

#[derive(Debug, Eq, PartialEq)]
struct UnbanTimer {
    expires_at: i64,
    ip: IpAddr,
    jail_id: String,
}

impl Ord for UnbanTimer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.expires_at.cmp(&other.expires_at)
    }
}

impl PartialOrd for UnbanTimer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

type FailKey = (IpAddr, String);

struct FailState {
    timestamps: CircularTimestamps,
}

/// All mutable tracker state, grouped to reduce function argument counts.
struct TrackerState {
    jail_params: HashMap<String, JailParams>,
    failures: HashMap<FailKey, FailState>,
    bans: HashMap<(IpAddr, String), BanRecord>,
    ban_counts: HashMap<IpAddr, u32>,
    unban_queue: BinaryHeap<Reverse<UnbanTimer>>,
    total_bans: u64,
    total_unbans: u64,
    total_failures: u64,
    jail_bans: HashMap<String, u64>,
    jail_failures: HashMap<String, u64>,
    started_at: i64,
    executor_tx: mpsc::Sender<FirewallCmd>,
    logger: Option<Logger>,
}

impl TrackerState {
    fn notify_ban(&self, ip: IpAddr, jail_id: &str, ban_time: i64, manual: bool) {
        if let Some(ref t) = self.logger {
            t.log_ban(ip, jail_id, ban_time, manual);
        }
        if let Some(params) = self.jail_params.get(jail_id)
            && let Some(ref url) = params.webhook
        {
            crate::webhook::notify_ban(url, ip, jail_id, ban_time);
        }
    }

    fn notify_unban(&self, ip: IpAddr, jail_id: &str, manual: bool) {
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

// ---------------------------------------------------------------------------
// Main run loop
// ---------------------------------------------------------------------------

/// Run the tracker task.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    jail_configs: HashMap<String, JailConfig>,
    mut failure_rx: mpsc::Receiver<Failure>,
    mut cmd_rx: mpsc::Receiver<TrackerCmd>,
    executor_tx: mpsc::Sender<FirewallCmd>,
    restored_bans: Vec<BanRecord>,
    restored_ban_counts: HashMap<IpAddr, u32>,
    logger: Option<Logger>,
    cancel: CancellationToken,
) {
    info!("tracker started");

    let mut state = TrackerState {
        jail_params: build_jail_params(&jail_configs),
        failures: HashMap::new(),
        bans: HashMap::new(),
        ban_counts: restored_ban_counts,
        unban_queue: BinaryHeap::new(),
        total_bans: 0,
        total_unbans: 0,
        total_failures: 0,
        jail_bans: HashMap::new(),
        jail_failures: HashMap::new(),
        started_at: chrono::Utc::now().timestamp(),
        executor_tx,
        logger,
    };

    // Restore bans from persisted state.
    for ban in restored_bans {
        if let Some(expires) = ban.expires_at {
            state.unban_queue.push(Reverse(UnbanTimer {
                expires_at: expires,
                ip: ban.ip,
                jail_id: ban.jail_id.clone(),
            }));
        }
        let ban_key = (ban.ip, ban.jail_id.clone());
        state.bans.insert(ban_key, ban);
    }

    let save_interval = tokio::time::Duration::from_secs(60);
    let mut save_timer = tokio::time::interval(save_interval);
    save_timer.tick().await; // consume immediate first tick

    loop {
        let next_unban_sleep = next_unban_duration(&state.unban_queue);

        tokio::select! {
            _ = cancel.cancelled() => {
                info!("tracker shutting down");
                let snapshot = build_snapshot(&state.bans, &state.ban_counts);
                let _ = state.executor_tx.send(FirewallCmd::SaveState { snapshot }).await;
                break;
            }

            failure = failure_rx.recv() => {
                match failure {
                    Some(f) => handle_failure(f, &mut state).await,
                    None => {
                        info!("failure channel closed");
                        break;
                    }
                }
            }

            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(c) => handle_cmd(c, &mut state).await,
                    None => debug!("tracker cmd channel closed"),
                }
            }

            _ = tokio::time::sleep(next_unban_sleep) => {
                process_unbans(&mut state).await;
            }

            _ = save_timer.tick() => {
                let snapshot = build_snapshot(&state.bans, &state.ban_counts);
                if state.executor_tx.send(FirewallCmd::SaveState { snapshot }).await.is_err() {
                    warn!("executor channel closed during state save");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Command handling
// ---------------------------------------------------------------------------

async fn handle_cmd(cmd: TrackerCmd, s: &mut TrackerState) {
    match cmd {
        TrackerCmd::QueryBans { respond } => {
            let list: Vec<BanRecord> = s.bans.values().cloned().collect();
            let _ = respond.send(list);
        }

        TrackerCmd::ManualBan {
            ip,
            jail_id,
            ban_time,
            respond,
        } => {
            let result = do_manual_ban(ip, &jail_id, ban_time, s).await;
            let _ = respond.send(result);
        }

        TrackerCmd::ManualUnban {
            ip,
            jail_id,
            respond,
        } => {
            let result = do_manual_unban(ip, &jail_id, s).await;
            let _ = respond.send(result);
        }

        TrackerCmd::GetStats { respond } => {
            let now = chrono::Utc::now().timestamp();
            let mut jail_stats: HashMap<String, JailStats> = HashMap::new();
            for jail_id in s.jail_params.keys() {
                let active = s.bans.values().filter(|b| b.jail_id == *jail_id).count();
                jail_stats.insert(
                    jail_id.clone(),
                    JailStats {
                        active_bans: active,
                        total_bans: *s.jail_bans.get(jail_id).unwrap_or(&0),
                        total_failures: *s.jail_failures.get(jail_id).unwrap_or(&0),
                    },
                );
            }
            let stats = Stats {
                uptime_secs: now - s.started_at,
                active_bans: s.bans.len(),
                total_bans: s.total_bans,
                total_unbans: s.total_unbans,
                total_failures: s.total_failures,
                jails: jail_stats,
            };
            let _ = respond.send(stats);
        }

        TrackerCmd::UpdateJails { jails } => {
            info!(jails = jails.len(), "updating jail configurations");
            let new_params = build_jail_params(&jails);
            s.failures
                .retain(|(_, jail_id), _| new_params.contains_key(jail_id));
            s.jail_params = new_params;
        }
    }
}

// ---------------------------------------------------------------------------
// Manual ban/unban
// ---------------------------------------------------------------------------

/// Shared ban execution: create record, enqueue unban, send firewall command, notify.
async fn execute_ban(ip: IpAddr, jail_id: &str, ban_time: i64, manual: bool, s: &mut TrackerState) {
    let now = chrono::Utc::now().timestamp();
    let expires_at = if ban_time < 0 { None } else { Some(now + ban_time) };

    let ban = BanRecord {
        ip,
        jail_id: jail_id.to_string(),
        banned_at: now,
        expires_at,
    };

    if let Some(exp) = expires_at {
        s.unban_queue.push(Reverse(UnbanTimer {
            expires_at: exp,
            ip,
            jail_id: jail_id.to_string(),
        }));
    }

    s.bans.insert((ip, jail_id.to_string()), ban);
    s.total_bans += 1;
    *s.jail_bans.entry(jail_id.to_string()).or_insert(0) += 1;

    let cmd = FirewallCmd::Ban {
        ip,
        jail_id: jail_id.to_string(),
        banned_at: now,
        expires_at,
    };
    if s.executor_tx.send(cmd).await.is_err() {
        warn!("executor channel closed");
    }

    s.notify_ban(ip, jail_id, ban_time, manual);
}

async fn do_manual_ban(
    ip: IpAddr,
    jail_id: &str,
    ban_time: i64,
    s: &mut TrackerState,
) -> crate::error::Result<()> {
    if s.bans.contains_key(&(ip, jail_id.to_string())) {
        return Err(crate::error::Error::AlreadyBanned {
            ip,
            jail: jail_id.to_string(),
        });
    }
    info!(%ip, jail = %jail_id, ban_time, "manual ban");
    execute_ban(ip, jail_id, ban_time, true, s).await;
    Ok(())
}

async fn do_manual_unban(
    ip: IpAddr,
    jail_id: &str,
    s: &mut TrackerState,
) -> crate::error::Result<()> {
    if s.bans.remove(&(ip, jail_id.to_string())).is_none() {
        return Err(crate::error::Error::NotBanned {
            ip,
            jail: jail_id.to_string(),
        });
    }
    info!(%ip, jail = %jail_id, "manual unban");
    execute_unban(ip, jail_id, true, s).await;
    Ok(())
}

/// Shared unban execution: update counters, send firewall command, notify.
async fn execute_unban(ip: IpAddr, jail_id: &str, manual: bool, s: &mut TrackerState) {
    s.total_unbans += 1;
    let cmd = FirewallCmd::Unban {
        ip,
        jail_id: jail_id.to_string(),
    };
    if s.executor_tx.send(cmd).await.is_err() {
        warn!("executor channel closed");
    }
    s.notify_unban(ip, jail_id, manual);
}

// ---------------------------------------------------------------------------
// Failure handling
// ---------------------------------------------------------------------------

async fn handle_failure(failure: Failure, s: &mut TrackerState) {
    s.total_failures += 1;
    *s.jail_failures.entry(failure.jail_id.clone()).or_insert(0) += 1;

    let ban_key = (failure.ip, failure.jail_id.clone());
    if s.bans.contains_key(&ban_key) {
        debug!(ip = %failure.ip, jail = %failure.jail_id, "already banned, ignoring failure");
        return;
    }

    let params = match s.jail_params.get(&failure.jail_id) {
        Some(p) => p,
        None => {
            warn!(jail = %failure.jail_id, "unknown jail in failure event");
            return;
        }
    };

    let max_retry = params.max_retry;
    let find_time = params.find_time;
    let ban_time = params.ban_time;

    let key = (failure.ip, failure.jail_id.clone());
    let fail_state = s.failures.entry(key).or_insert_with(|| FailState {
        timestamps: CircularTimestamps::new(max_retry as usize),
    });

    fail_state.timestamps.push(failure.timestamp);

    if fail_state.timestamps.threshold_reached(find_time) {
        let count = *s.ban_counts.get(&failure.ip).unwrap_or(&0);
        let effective_ban_time = calc_ban_time(ban_time, count, params);
        *s.ban_counts.entry(failure.ip).or_insert(0) += 1;

        info!(
            ip = %failure.ip,
            jail = %failure.jail_id,
            ban_time = effective_ban_time,
            ban_count = count + 1,
            "threshold reached, banning"
        );

        execute_ban(failure.ip, &failure.jail_id, effective_ban_time, false, s).await;
    }
}

// ---------------------------------------------------------------------------
// Unban processing
// ---------------------------------------------------------------------------

async fn process_unbans(s: &mut TrackerState) {
    let now = chrono::Utc::now().timestamp();
    while let Some(Reverse(timer)) = s.unban_queue.peek() {
        if timer.expires_at > now {
            break;
        }
        let Reverse(timer) = s.unban_queue.pop().expect("peeked");
        let ban_key = (timer.ip, timer.jail_id.clone());
        if s.bans.remove(&ban_key).is_some() {
            info!(ip = %timer.ip, jail = %timer.jail_id, "unban timer expired");
            execute_unban(timer.ip, &timer.jail_id, false, s).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn next_unban_duration(queue: &BinaryHeap<Reverse<UnbanTimer>>) -> tokio::time::Duration {
    match queue.peek() {
        Some(Reverse(timer)) => {
            let now = chrono::Utc::now().timestamp();
            let secs = (timer.expires_at - now).max(0) as u64;
            tokio::time::Duration::from_secs(secs.min(60))
        }
        None => tokio::time::Duration::from_secs(60),
    }
}

fn build_snapshot(
    bans: &HashMap<(IpAddr, String), BanRecord>,
    ban_counts: &HashMap<IpAddr, u32>,
) -> StateSnapshot {
    StateSnapshot {
        bans: bans.values().cloned().collect(),
        ban_counts: ban_counts.iter().map(|(ip, c)| (*ip, *c)).collect(),
        snapshot_time: chrono::Utc::now().timestamp(),
    }
}
