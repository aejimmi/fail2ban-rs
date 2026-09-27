//! Tracker event loop — startup seeding and the main `select!` loop.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;

use etchdb::{Store, WalBackend};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::config::JailConfig;
use crate::detect::watcher::Failure;
use crate::enforce::FirewallCmd;
use crate::logging::Logger;
use crate::track::TrackerCmd;
use crate::track::ban_calc::build_jail_params;
use crate::track::commands::handle_cmd;
use crate::track::failure::handle_failure;
use crate::track::manual::{ManualBanOutcome, handle_manual_ban_outcome};
#[cfg(feature = "maxmind")]
use crate::track::maxmind::MaxmindState;
use crate::track::persist::{BanCount, BanState};
use crate::track::state::BanRecord;
use crate::track::sweep::{process_unbans, request_reconcile};
use crate::track::tracker_state::{BanIndex, Counters, PendingManualBans, TrackerState};
use crate::track::unban::{UnbanOutcome, handle_unban_outcome};

/// How often the tracker asks the executor to reconcile active bans against the
/// firewall (seconds). Deliberately low-frequency: `is_banned` shells out per IP.
const RECONCILE_INTERVAL_SECS: u64 = 300;

/// Capacity of the internal channel on which manual-ban ack waiters report.
const RESOLVE_CHANNEL_SIZE: usize = 64;

/// Run the tracker task.
///
/// With `reconcile` enabled the tracker periodically (and after reloads) asks
/// the executor to re-verify active bans, via `FirewallCmd::Reconcile` on
/// `executor_tx` so the requests are ordered with its bans and unbans.
#[allow(clippy::too_many_arguments, clippy::implicit_hasher)]
pub async fn run(
    global_config: crate::config::GlobalConfig,
    jail_configs: HashMap<String, JailConfig>,
    failure_rx: mpsc::Receiver<Failure>,
    cmd_rx: mpsc::Receiver<TrackerCmd>,
    executor_tx: mpsc::Sender<FirewallCmd>,
    reconcile: bool,
    restored_bans: Vec<BanRecord>,
    restored_ban_counts: HashMap<IpAddr, BanCount>,
    store: Arc<Store<BanState, WalBackend<BanState>>>,
    logger: Option<Logger>,
    cancel: CancellationToken,
) {
    info!(phase = "startup", "failure tracker started");
    warn_maxmind_disabled(&global_config);

    let (resolve_tx, resolve_rx) = mpsc::channel(RESOLVE_CHANNEL_SIZE);
    let (unban_outcome_tx, unban_outcome_rx) = mpsc::channel(RESOLVE_CHANNEL_SIZE);
    let io = StateIo {
        executor_tx,
        reconcile,
        resolve_tx,
        unban_outcome_tx,
        store,
        logger,
    };
    let mut state = init_state(&global_config, &jail_configs, io);
    seed_restored(&mut state, &restored_bans, &restored_ban_counts);
    rebuild_index(&mut state);

    let rx = TrackerRx {
        failure: failure_rx,
        cmd: cmd_rx,
        resolve: resolve_rx,
        unban: unban_outcome_rx,
    };
    event_loop(state, rx, cancel).await;
}

/// Receivers the tracker event loop selects over.
struct TrackerRx {
    failure: mpsc::Receiver<Failure>,
    cmd: mpsc::Receiver<TrackerCmd>,
    resolve: mpsc::Receiver<ManualBanOutcome>,
    unban: mpsc::Receiver<UnbanOutcome>,
}

/// One event observed by the tracker loop.
enum Event {
    Cancelled,
    Failure(Option<Failure>),
    Cmd(Option<TrackerCmd>),
    Outcome(Option<ManualBanOutcome>),
    UnbanOutcome(Option<UnbanOutcome>),
    Sweep,
    Reconcile,
}

/// Wait for events and handle them until cancelled or an input closes.
async fn event_loop(mut state: TrackerState, mut rx: TrackerRx, cancel: CancellationToken) {
    let mut reconcile_interval =
        tokio::time::interval(tokio::time::Duration::from_secs(RECONCILE_INTERVAL_SECS));
    reconcile_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let next_unban_sleep = next_sweep_duration(state.index.next_expiry);
        let event = tokio::select! {
            () = cancel.cancelled() => Event::Cancelled,
            f = rx.failure.recv() => Event::Failure(f),
            c = rx.cmd.recv() => Event::Cmd(c),
            o = rx.resolve.recv() => Event::Outcome(o),
            o = rx.unban.recv() => Event::UnbanOutcome(o),
            () = tokio::time::sleep(next_unban_sleep) => Event::Sweep,
            _ = reconcile_interval.tick() => Event::Reconcile,
        };
        if !handle_event(event, &mut state).await {
            break;
        }
    }
}

/// Handle one event; returns `false` when the tracker must stop.
async fn handle_event(event: Event, s: &mut TrackerState) -> bool {
    match event {
        Event::Cancelled => {
            info!(phase = "shutdown", "failure tracker stopping");
            if let Err(e) = s.store.flush() {
                warn!(phase = "shutdown", error = %e, "state flush failed");
            }
            return false;
        }
        Event::Failure(None) => return input_closed("failure"),
        Event::Cmd(None) => return input_closed("command"),
        Event::Failure(Some(f)) => handle_failure(f, s).await,
        Event::Cmd(Some(c)) => handle_cmd(c, s).await,
        // The state holds a sender, so this channel never closes.
        Event::Outcome(o) => {
            if let Some(o) = o {
                handle_manual_ban_outcome(o, s).await;
            }
        }
        Event::UnbanOutcome(o) => {
            if let Some(o) = o {
                handle_unban_outcome(o, s);
            }
        }
        Event::Sweep => process_unbans(s).await,
        Event::Reconcile => request_reconcile(s),
    }
    true
}

/// Log that an input channel closed (all its senders dropped); always `false`.
fn input_closed(channel: &'static str) -> bool {
    error!(
        channel,
        phase = "shutdown",
        "input channel closed (all {channel} senders dropped); tracker stopping"
    );
    false
}

/// Channels and handles moved into the tracker state at startup.
struct StateIo {
    executor_tx: mpsc::Sender<FirewallCmd>,
    reconcile: bool,
    resolve_tx: mpsc::Sender<ManualBanOutcome>,
    unban_outcome_tx: mpsc::Sender<UnbanOutcome>,
    store: Arc<Store<BanState, WalBackend<BanState>>>,
    logger: Option<Logger>,
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
    io: StateIo,
) -> TrackerState {
    TrackerState {
        jail_params: build_jail_params(jail_configs),
        failures: HashMap::new(),
        store: io.store,
        index: BanIndex::default(),
        counters: Counters::default(),
        started_at: chrono::Utc::now().timestamp(),
        ban_count_decay: global_config.ban_count_decay,
        executor_tx: io.executor_tx,
        resolve_tx: io.resolve_tx,
        unban_outcome_tx: io.unban_outcome_tx,
        pending_manual: PendingManualBans::default(),
        pending_unbans: std::collections::HashSet::new(),
        unban_retry_after: HashMap::new(),
        reconcile_enabled: io.reconcile,
        reconcile_queue: VecDeque::new(),
        logger: io.logger,
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
