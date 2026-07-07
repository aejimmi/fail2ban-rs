//! Tracker event loop — startup seeding and the main `select!` loop.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use etchdb::{Store, WalBackend};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::config::JailConfig;
use crate::detect::watcher::Failure;
use crate::enforce::{FirewallCmd, ReconcileRequest};
use crate::logging::Logger;
use crate::track::TrackerCmd;
use crate::track::ban_calc::build_jail_params;
use crate::track::commands::handle_cmd;
use crate::track::failure::handle_failure;
#[cfg(feature = "maxmind")]
use crate::track::maxmind::MaxmindState;
use crate::track::persist::{BanCount, BanState};
use crate::track::state::BanRecord;
use crate::track::sweep::{process_unbans, request_reconcile};
use crate::track::tracker_state::{BanIndex, Counters, TrackerState};

/// How often the tracker asks the executor to reconcile active bans against the
/// firewall (seconds). Deliberately low-frequency: `is_banned` shells out per IP.
const RECONCILE_INTERVAL_SECS: u64 = 300;

/// Run the tracker task.
#[allow(clippy::too_many_arguments, clippy::implicit_hasher)]
pub async fn run(
    global_config: crate::config::GlobalConfig,
    jail_configs: HashMap<String, JailConfig>,
    mut failure_rx: mpsc::Receiver<Failure>,
    mut cmd_rx: mpsc::Receiver<TrackerCmd>,
    executor_tx: mpsc::Sender<FirewallCmd>,
    reconcile_tx: Option<mpsc::Sender<ReconcileRequest>>,
    restored_bans: Vec<BanRecord>,
    restored_ban_counts: HashMap<IpAddr, BanCount>,
    store: Arc<Store<BanState, WalBackend<BanState>>>,
    logger: Option<Logger>,
    cancel: CancellationToken,
) {
    info!(phase = "startup", "failure tracker started");
    warn_maxmind_disabled(&global_config);

    let mut state = init_state(&global_config, &jail_configs, executor_tx, store, logger);
    seed_restored(&mut state, &restored_bans, &restored_ban_counts);
    rebuild_index(&mut state);

    let mut reconcile_interval =
        tokio::time::interval(tokio::time::Duration::from_secs(RECONCILE_INTERVAL_SECS));
    reconcile_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        let next_unban_sleep = next_sweep_duration(state.index.next_expiry);

        tokio::select! {
            () = cancel.cancelled() => {
                info!(phase = "shutdown", "failure tracker stopping");
                if let Err(e) = state.store.flush() {
                    warn!(phase = "shutdown", error = %e, "state flush failed");
                }
                break;
            }

            failure = failure_rx.recv() => {
                let Some(f) = failure else {
                    error!(
                        channel = "failure",
                        phase = "shutdown",
                        "input channel closed (all failure senders dropped); tracker stopping"
                    );
                    break;
                };
                handle_failure(f, &mut state).await;
            }

            cmd = cmd_rx.recv() => {
                let Some(c) = cmd else {
                    error!(
                        channel = "command",
                        phase = "shutdown",
                        "input channel closed (all command senders dropped); tracker stopping"
                    );
                    break;
                };
                handle_cmd(c, &mut state).await;
            }

            () = tokio::time::sleep(next_unban_sleep) => {
                process_unbans(&mut state).await;
            }

            _ = reconcile_interval.tick() => {
                request_reconcile(reconcile_tx.as_ref(), &state);
            }
        }
    }
}

/// Warn if maxmind config is present but the feature was not compiled in.
#[cfg_attr(feature = "maxmind", allow(unused_variables))]
fn warn_maxmind_disabled(global_config: &crate::config::GlobalConfig) {
    #[cfg(not(feature = "maxmind"))]
    if global_config.maxmind_asn.is_some()
        || global_config.maxmind_country.is_some()
        || global_config.maxmind_city.is_some()
    {
        warn!(
            phase = "startup",
            reason = "feature_not_compiled",
            "maxmind config ignored"
        );
    }
}

/// Build the initial tracker state from configuration and IO handles.
#[cfg_attr(not(feature = "maxmind"), allow(unused_variables))]
fn init_state(
    global_config: &crate::config::GlobalConfig,
    jail_configs: &HashMap<String, JailConfig>,
    executor_tx: mpsc::Sender<FirewallCmd>,
    store: Arc<Store<BanState, WalBackend<BanState>>>,
    logger: Option<Logger>,
) -> TrackerState {
    TrackerState {
        jail_params: build_jail_params(jail_configs),
        failures: HashMap::new(),
        store,
        index: BanIndex::default(),
        counters: Counters::default(),
        started_at: chrono::Utc::now().timestamp(),
        ban_count_decay: global_config.ban_count_decay,
        executor_tx,
        logger,
        #[cfg(feature = "maxmind")]
        maxmind: MaxmindState::load(global_config, jail_configs),
    }
}

/// Seed the store with restored bans (from firewall restore filtering).
///
/// On first boot with etch, the store already has these from WAL replay. On
/// migration from the old format, `server.rs` passes the filtered active bans.
fn seed_restored(
    state: &mut TrackerState,
    restored_bans: &[BanRecord],
    restored_ban_counts: &HashMap<IpAddr, BanCount>,
) {
    let store_state = state.store.read();
    let should_seed = store_state.bans.is_empty() && !restored_bans.is_empty();
    drop(store_state);
    if !should_seed {
        return;
    }
    if let Err(e) = state.store.write(|tx| {
        for ban in restored_bans {
            tx.bans.put((ban.ip, ban.jail_id.clone()), ban.clone())?;
        }
        for (ip, count) in restored_ban_counts {
            tx.ban_counts.put(*ip, *count)?;
        }
        Ok(())
    }) {
        warn!(phase = "startup", error = %e, "restore seeding failed");
    }
}

/// Build the in-memory ban index and the soonest-expiry hint from the store.
fn rebuild_index(state: &mut TrackerState) {
    let store_state = state.store.read();
    state.index.banned_keys = store_state.bans.keys().cloned().collect();
    state.index.next_expiry = store_state.bans.values().filter_map(|b| b.expires_at).min();
}

/// Time until the next sweep: soon enough to unban the earliest-expiring ban,
/// capped at 60s so an idle tracker still wakes periodically. Reads only the
/// in-memory `next_expiry` hint, keeping the per-iteration cost off the store.
fn next_sweep_duration(next_expiry: Option<i64>) -> tokio::time::Duration {
    match next_expiry {
        Some(exp) => {
            let now = chrono::Utc::now().timestamp();
            let secs = (exp - now).max(0) as u64;
            tokio::time::Duration::from_secs(secs.min(60))
        }
        None => tokio::time::Duration::from_secs(60),
    }
}
