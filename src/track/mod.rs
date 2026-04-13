//! Tracking — failure counting, ban/unban decisions, and state persistence.
//!
//! Owns all mutable state: failure counts (ring buffers), active bans,
//! and runtime statistics. Receives Failure events from watchers and
//! TrackerCmd queries from the server. Sends FirewallCmd to enforce.

/// Escalating ban time calculator.
pub mod ban_calc;
/// Fixed-capacity ring buffer for failure timestamps.
pub mod circular;
/// MaxMind GeoIP enrichment.
#[cfg(feature = "maxmind")]
pub mod maxmind;
/// WAL-backed ban state persistence.
pub mod persist;
/// Serializable ban record.
pub mod state;

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::net::IpAddr;
use std::sync::Arc;

use etchdb::{Store, WalBackend};
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::JailConfig;
use crate::detect::watcher::Failure;
use crate::enforce::FirewallCmd;
use crate::logging::Logger;
use crate::track::ban_calc::{JailParams, build_jail_params, calc_ban_time};
use crate::track::circular::CircularTimestamps;
#[cfg(feature = "maxmind")]
use crate::track::maxmind::MaxmindState;
use crate::track::persist::BanState;
use crate::track::state::BanRecord;

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
    /// Hot-reload global and jail configurations.
    UpdateConfig {
        global: crate::config::GlobalConfig,
        jails: HashMap<String, JailConfig>,
    },
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
    store: Arc<Store<BanState, WalBackend<BanState>>>,
    unban_queue: BinaryHeap<Reverse<UnbanTimer>>,
    total_bans: u64,
    total_unbans: u64,
    total_failures: u64,
    jail_bans: HashMap<String, u64>,
    jail_failures: HashMap<String, u64>,
    started_at: i64,
    executor_tx: mpsc::Sender<FirewallCmd>,
    logger: Option<Logger>,
    #[cfg(feature = "maxmind")]
    maxmind: MaxmindState,
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
#[allow(clippy::too_many_arguments, clippy::implicit_hasher)]
pub async fn run(
    global_config: crate::config::GlobalConfig,
    jail_configs: HashMap<String, JailConfig>,
    mut failure_rx: mpsc::Receiver<Failure>,
    mut cmd_rx: mpsc::Receiver<TrackerCmd>,
    executor_tx: mpsc::Sender<FirewallCmd>,
    restored_bans: Vec<BanRecord>,
    restored_ban_counts: HashMap<IpAddr, u32>,
    store: Arc<Store<BanState, WalBackend<BanState>>>,
    logger: Option<Logger>,
    cancel: CancellationToken,
) {
    info!("tracker started");

    #[cfg(not(feature = "maxmind"))]
    if global_config.maxmind_asn.is_some()
        || global_config.maxmind_country.is_some()
        || global_config.maxmind_city.is_some()
    {
        warn!("maxmind paths configured but maxmind feature not compiled — ignoring");
    }

    let mut state = TrackerState {
        jail_params: build_jail_params(&jail_configs),
        failures: HashMap::new(),
        store,
        unban_queue: BinaryHeap::new(),
        total_bans: 0,
        total_unbans: 0,
        total_failures: 0,
        jail_bans: HashMap::new(),
        jail_failures: HashMap::new(),
        started_at: chrono::Utc::now().timestamp(),
        executor_tx,
        logger,
        #[cfg(feature = "maxmind")]
        maxmind: MaxmindState::load(&global_config, &jail_configs),
    };

    // Restore unban timers from persisted state.
    for ban in &restored_bans {
        if let Some(expires) = ban.expires_at {
            state.unban_queue.push(Reverse(UnbanTimer {
                expires_at: expires,
                ip: ban.ip,
                jail_id: ban.jail_id.clone(),
            }));
        }
    }

    // Seed the store with restored bans (from firewall restore filtering).
    // On first boot with etch, the store already has these from WAL replay.
    // On migration from old format, server.rs passes the filtered active_bans.
    {
        let store_state = state.store.read();
        if store_state.bans.is_empty() && !restored_bans.is_empty() {
            drop(store_state);
            let _ = state.store.write(|tx| {
                for ban in &restored_bans {
                    tx.bans.put((ban.ip, ban.jail_id.clone()), ban.clone());
                }
                for (ip, count) in &restored_ban_counts {
                    tx.ban_counts.put(*ip, *count);
                }
                Ok(())
            });
        }
    }

    loop {
        let next_unban_sleep = next_unban_duration(&state.unban_queue);

        tokio::select! {
            () = cancel.cancelled() => {
                info!("tracker shutting down");
                if let Err(e) = state.store.flush() {
                    warn!("final flush failed: {e}");
                }
                break;
            }

            failure = failure_rx.recv() => {
                if let Some(f) = failure {
                    handle_failure(f, &mut state).await;
                } else {
                    info!("failure channel closed");
                    break;
                }
            }

            cmd = cmd_rx.recv() => {
                if let Some(c) = cmd {
                    handle_cmd(c, &mut state).await;
                } else {
                    debug!("tracker cmd channel closed");
                }
            }

            () = tokio::time::sleep(next_unban_sleep) => {
                process_unbans(&mut state).await;
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
            let list: Vec<BanRecord> = s.store.read().bans.values().cloned().collect();
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
            let store_state = s.store.read();
            let mut jail_stats: HashMap<String, JailStats> = HashMap::new();
            for jail_id in s.jail_params.keys() {
                let active = store_state
                    .bans
                    .values()
                    .filter(|b| b.jail_id == *jail_id)
                    .count();
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
                uptime_secs: (now - s.started_at).max(0),
                active_bans: store_state.bans.len(),
                total_bans: s.total_bans,
                total_unbans: s.total_unbans,
                total_failures: s.total_failures,
                jails: jail_stats,
            };
            drop(store_state);
            let _ = respond.send(stats);
        }

        TrackerCmd::UpdateConfig { global, jails } => {
            info!(
                jails = jails.len(),
                "updating jail and global configurations"
            );
            let new_params = build_jail_params(&jails);
            s.failures
                .retain(|(_, jail_id), _| new_params.contains_key(jail_id));
            s.jail_params = new_params;
            #[cfg(feature = "maxmind")]
            s.maxmind.reload(&global, &jails);
            let _ = &global; // suppress unused warning when maxmind disabled
        }
    }
}

// ---------------------------------------------------------------------------
// Manual ban/unban
// ---------------------------------------------------------------------------

/// Shared ban execution: create record, enqueue unban, send firewall command, notify.
async fn execute_ban(ip: IpAddr, jail_id: &str, ban_time: i64, manual: bool, s: &mut TrackerState) {
    let now = chrono::Utc::now().timestamp();
    let expires_at = if ban_time < 0 {
        None
    } else {
        Some(now.saturating_add(ban_time))
    };

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

    let ban_clone = ban.clone();
    let jail_owned = jail_id.to_string();
    if let Err(e) = s.store.write(|tx| {
        tx.bans.put((ip, jail_owned.clone()), ban_clone.clone());
        Ok(())
    }) {
        warn!("etch write failed: {e}");
    }
    s.total_bans += 1;
    *s.jail_bans.entry(jail_id.to_string()).or_insert(0) += 1;

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

async fn do_manual_ban(
    ip: IpAddr,
    jail_id: &str,
    ban_time: i64,
    s: &mut TrackerState,
) -> crate::error::Result<()> {
    if !s.jail_params.contains_key(jail_id) {
        return Err(crate::error::Error::config(format!(
            "unknown jail: {jail_id}"
        )));
    }
    if s.store.read().bans.contains_key(&(ip, jail_id.to_string())) {
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
    if !s.jail_params.contains_key(jail_id) {
        return Err(crate::error::Error::config(format!(
            "unknown jail: {jail_id}"
        )));
    }
    let key = (ip, jail_id.to_string());
    if !s.store.read().bans.contains_key(&key) {
        return Err(crate::error::Error::NotBanned {
            ip,
            jail: jail_id.to_string(),
        });
    }
    if let Err(e) = s.store.write(|tx| {
        tx.bans.delete(&key);
        Ok(())
    }) {
        warn!("etch write failed: {e}");
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
    if s.store.read().bans.contains_key(&ban_key) {
        debug!(ip = %failure.ip, jail = %failure.jail_id, "already banned, ignoring failure");
        return;
    }

    let Some(params) = s.jail_params.get(&failure.jail_id) else {
        warn!(jail = %failure.jail_id, "unknown jail in failure event");
        return;
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
        let count = s
            .store
            .read()
            .ban_counts
            .get(&failure.ip)
            .copied()
            .unwrap_or(0);
        let effective_ban_time = calc_ban_time(ban_time, count, params);
        let ip = failure.ip;
        if let Err(e) = s.store.write(|tx| {
            tx.ban_counts.put(ip, count + 1);
            Ok(())
        }) {
            warn!("etch write failed: {e}");
        }

        #[cfg(feature = "maxmind")]
        {
            let enrichment = s.maxmind.enrich(failure.ip, &failure.jail_id);
            crate::track::maxmind::log_ban_event(
                &failure,
                effective_ban_time,
                count + 1,
                &enrichment,
            );
        }
        #[cfg(not(feature = "maxmind"))]
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
        let Some(Reverse(timer)) = s.unban_queue.pop() else {
            break;
        };
        let ban_key = (timer.ip, timer.jail_id.clone());
        if s.store.read().bans.contains_key(&ban_key) {
            if let Err(e) = s.store.write(|tx| {
                tx.bans.delete(&ban_key);
                Ok(())
            }) {
                warn!("etch write failed: {e}");
            }
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

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use etchdb::Store;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use crate::config::JailConfig;
    use crate::detect::watcher::Failure;
    use crate::enforce::FirewallCmd;
    use crate::track::TrackerCmd;
    use crate::track::persist::BanState;

    fn test_jail_config() -> JailConfig {
        JailConfig {
            enabled: true,
            log_path: "/tmp/test.log".into(),
            date_format: crate::detect::date::DateFormat::Syslog,
            filter: vec!["from <HOST>".to_string()],
            max_retry: 3,
            find_time: 600,
            ban_time: 60,
            ignoreself: false,
            maxmind: vec![
                crate::config::MaxmindField::Asn,
                crate::config::MaxmindField::Country,
                crate::config::MaxmindField::City,
            ],
            ..JailConfig::default()
        }
    }

    fn test_store() -> Arc<Store<BanState, etchdb::WalBackend<BanState>>> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        std::mem::forget(dir); // keep the tempdir alive
        let store = Store::<BanState, etchdb::WalBackend<BanState>>::open_wal(path).unwrap();
        Arc::new(store)
    }

    fn test_global_config() -> crate::config::GlobalConfig {
        crate::config::GlobalConfig {
            state_dir: std::path::PathBuf::from("/tmp/state"),
            socket_path: std::path::PathBuf::from("/tmp/sock"),
            log_level: "info".to_string(),
            channel_size: 1024,
            maxmind_asn: Some(
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/GeoLite2-ASN-Test.mmdb"),
            ),
            maxmind_country: Some(
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/GeoLite2-Country-Test.mmdb"),
            ),
            maxmind_city: Some(
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/GeoLite2-City-Test.mmdb"),
            ),
        }
    }

    #[tokio::test]
    async fn bans_after_threshold() {
        let mut jails = HashMap::new();
        jails.insert("sshd".to_string(), test_jail_config());

        let (failure_tx, failure_rx) = mpsc::channel(16);
        let (executor_tx, mut executor_rx) = mpsc::channel(16);
        let (_cmd_tx, cmd_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            crate::track::run(
                test_global_config(),
                jails,
                failure_rx,
                cmd_rx,
                executor_tx,
                vec![],
                std::collections::HashMap::new(),
                test_store(),
                None,
                cancel_clone,
            )
            .await;
        });

        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let now = chrono::Utc::now().timestamp();

        // Send 3 failures (= max_retry).
        for i in 0..3 {
            failure_tx
                .send(Failure {
                    ip,
                    jail_id: "sshd".to_string(),
                    timestamp: now + i,
                })
                .await
                .unwrap();
        }

        // Should receive a Ban command.
        let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), executor_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        match cmd {
            FirewallCmd::Ban {
                ip: ban_ip,
                jail_id,
                ..
            } => {
                assert_eq!(ban_ip, ip);
                assert_eq!(jail_id, "sshd");
            }
            other => panic!("expected Ban, got: {other:?}"),
        }

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn reban_on_restart_false_still_bans_new_offenders() {
        let mut jail = test_jail_config();
        jail.reban_on_restart = false;

        let mut jails = HashMap::new();
        jails.insert("sshd".to_string(), jail);

        let (failure_tx, failure_rx) = mpsc::channel(16);
        let (executor_tx, mut executor_rx) = mpsc::channel(16);
        let (_cmd_tx, cmd_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            crate::track::run(
                test_global_config(),
                jails,
                failure_rx,
                cmd_rx,
                executor_tx,
                vec![],
                std::collections::HashMap::new(),
                test_store(),
                None,
                cancel_clone,
            )
            .await;
        });

        let ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
        let now = chrono::Utc::now().timestamp();

        // Send 3 failures (= max_retry) — should still ban despite reban_on_restart=false.
        for i in 0..3 {
            failure_tx
                .send(Failure {
                    ip,
                    jail_id: "sshd".to_string(),
                    timestamp: now + i,
                })
                .await
                .unwrap();
        }

        let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), executor_rx.recv())
            .await
            .expect("timeout — ban should still fire with reban_on_restart=false")
            .expect("channel closed");

        match cmd {
            FirewallCmd::Ban {
                ip: ban_ip,
                jail_id,
                ..
            } => {
                assert_eq!(ban_ip, ip);
                assert_eq!(jail_id, "sshd");
            }
            other => panic!("expected Ban, got: {other:?}"),
        }

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn no_ban_below_threshold() {
        let mut jails = HashMap::new();
        jails.insert("sshd".to_string(), test_jail_config());

        let (failure_tx, failure_rx) = mpsc::channel(16);
        let (executor_tx, mut executor_rx) = mpsc::channel(16);
        let (_cmd_tx, cmd_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            crate::track::run(
                test_global_config(),
                jails,
                failure_rx,
                cmd_rx,
                executor_tx,
                vec![],
                std::collections::HashMap::new(),
                test_store(),
                None,
                cancel_clone,
            )
            .await;
        });

        let ip = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        let now = chrono::Utc::now().timestamp();

        // Only 2 failures (< max_retry of 3).
        for i in 0..2 {
            failure_tx
                .send(Failure {
                    ip,
                    jail_id: "sshd".to_string(),
                    timestamp: now + i,
                })
                .await
                .unwrap();
        }

        // Give tracker time to process.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Should not receive a Ban.
        let result =
            tokio::time::timeout(std::time::Duration::from_millis(200), executor_rx.recv()).await;
        assert!(result.is_err(), "should not have received a command");

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn no_ban_outside_find_time() {
        let mut jail = test_jail_config();
        jail.find_time = 10; // 10 second window
        let mut jails = HashMap::new();
        jails.insert("sshd".to_string(), jail);

        let (failure_tx, failure_rx) = mpsc::channel(16);
        let (executor_tx, mut executor_rx) = mpsc::channel(16);
        let (_cmd_tx, cmd_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            crate::track::run(
                test_global_config(),
                jails,
                failure_rx,
                cmd_rx,
                executor_tx,
                vec![],
                std::collections::HashMap::new(),
                test_store(),
                None,
                cancel_clone,
            )
            .await;
        });

        let ip = IpAddr::V4(Ipv4Addr::new(9, 10, 11, 12));
        let now = chrono::Utc::now().timestamp();

        // 3 failures spread over 100 seconds (> find_time of 10).
        for i in 0..3 {
            failure_tx
                .send(Failure {
                    ip,
                    jail_id: "sshd".to_string(),
                    timestamp: now + (i * 50),
                })
                .await
                .unwrap();
        }

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let result =
            tokio::time::timeout(std::time::Duration::from_millis(200), executor_rx.recv()).await;
        assert!(result.is_err(), "should not ban outside find_time");

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn already_banned_ip_ignored() {
        let mut jails = HashMap::new();
        jails.insert("sshd".to_string(), test_jail_config());

        let (failure_tx, failure_rx) = mpsc::channel(64);
        let (executor_tx, mut executor_rx) = mpsc::channel(64);
        let (_cmd_tx, cmd_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            crate::track::run(
                test_global_config(),
                jails,
                failure_rx,
                cmd_rx,
                executor_tx,
                vec![],
                std::collections::HashMap::new(),
                test_store(),
                None,
                cancel_clone,
            )
            .await;
        });

        let ip = IpAddr::V4(Ipv4Addr::new(20, 20, 20, 20));
        let now = chrono::Utc::now().timestamp();

        // Trigger first ban (3 failures).
        for i in 0..3 {
            failure_tx
                .send(Failure {
                    ip,
                    jail_id: "sshd".to_string(),
                    timestamp: now + i,
                })
                .await
                .unwrap();
        }

        // Receive the ban command.
        let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), executor_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert!(matches!(cmd, FirewallCmd::Ban { .. }));

        // Send more failures for the same IP — should be silently ignored.
        for i in 0..3 {
            failure_tx
                .send(Failure {
                    ip,
                    jail_id: "sshd".to_string(),
                    timestamp: now + 10 + i,
                })
                .await
                .unwrap();
        }

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Should NOT receive a second Ban command.
        let result =
            tokio::time::timeout(std::time::Duration::from_millis(200), executor_rx.recv()).await;
        // Either timeout (no message) — but not another Ban.
        match result {
            Err(_) => {} // timeout, good
            Ok(other) => panic!("expected no second Ban, got: {other:?}"),
        }

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn unknown_jail_failure_ignored() {
        let mut jails = HashMap::new();
        jails.insert("sshd".to_string(), test_jail_config());

        let (failure_tx, failure_rx) = mpsc::channel(16);
        let (executor_tx, mut executor_rx) = mpsc::channel(16);
        let (_cmd_tx, cmd_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            crate::track::run(
                test_global_config(),
                jails,
                failure_rx,
                cmd_rx,
                executor_tx,
                vec![],
                std::collections::HashMap::new(),
                test_store(),
                None,
                cancel_clone,
            )
            .await;
        });

        // Send failure for a jail that doesn't exist.
        failure_tx
            .send(Failure {
                ip: IpAddr::V4(Ipv4Addr::new(30, 30, 30, 30)),
                jail_id: "nonexistent".to_string(),
                timestamp: chrono::Utc::now().timestamp(),
            })
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let result =
            tokio::time::timeout(std::time::Duration::from_millis(200), executor_rx.recv()).await;
        assert!(result.is_err(), "unknown jail should not produce commands");

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn unban_timer_fires() {
        let mut jail = test_jail_config();
        jail.ban_time = 1; // 1 second ban
        let mut jails = HashMap::new();
        jails.insert("sshd".to_string(), jail);

        let (failure_tx, failure_rx) = mpsc::channel(64);
        let (executor_tx, mut executor_rx) = mpsc::channel(64);
        let (_cmd_tx, cmd_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            crate::track::run(
                test_global_config(),
                jails,
                failure_rx,
                cmd_rx,
                executor_tx,
                vec![],
                std::collections::HashMap::new(),
                test_store(),
                None,
                cancel_clone,
            )
            .await;
        });

        let ip = IpAddr::V4(Ipv4Addr::new(40, 40, 40, 40));
        let now = chrono::Utc::now().timestamp();

        // Trigger ban.
        for i in 0..3 {
            failure_tx
                .send(Failure {
                    ip,
                    jail_id: "sshd".to_string(),
                    timestamp: now + i,
                })
                .await
                .unwrap();
        }

        // Receive Ban.
        let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), executor_rx.recv())
            .await
            .expect("timeout waiting for ban")
            .expect("channel closed");
        assert!(matches!(cmd, FirewallCmd::Ban { .. }));

        // Wait for unban timer (1 second ban + some buffer).
        let mut got_unban = false;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(std::time::Duration::from_millis(500), executor_rx.recv())
                .await
            {
                Ok(Some(FirewallCmd::Unban {
                    ip: unban_ip,
                    jail_id,
                })) => {
                    assert_eq!(unban_ip, ip);
                    assert_eq!(jail_id, "sshd");
                    got_unban = true;
                    break;
                }
                Ok(Some(other)) => panic!("unexpected command: {other:?}"),
                Ok(None) => break,
                Err(_) => {} // timeout, try again
            }
        }
        assert!(
            got_unban,
            "should have received Unban after ban_time expired"
        );

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn restored_bans_populate_unban_queue() {
        let mut jails = HashMap::new();
        jails.insert("sshd".to_string(), test_jail_config());

        let now = chrono::Utc::now().timestamp();
        let restored = vec![crate::track::state::BanRecord {
            ip: IpAddr::V4(Ipv4Addr::new(50, 50, 50, 50)),
            jail_id: "sshd".to_string(),
            banned_at: now - 10,
            expires_at: Some(now + 1), // expires in 1 second
        }];

        let (_failure_tx, failure_rx) = mpsc::channel(16);
        let (executor_tx, mut executor_rx) = mpsc::channel(64);
        let (_cmd_tx, cmd_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            crate::track::run(
                test_global_config(),
                jails,
                failure_rx,
                cmd_rx,
                executor_tx,
                restored,
                std::collections::HashMap::new(),
                test_store(),
                None,
                cancel_clone,
            )
            .await;
        });

        // The restored ban should expire after ~1 second.
        let mut got_unban = false;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(4);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(std::time::Duration::from_millis(500), executor_rx.recv())
                .await
            {
                Ok(Some(FirewallCmd::Unban { ip, .. })) => {
                    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(50, 50, 50, 50)));
                    got_unban = true;
                    break;
                }
                Ok(Some(_) | None) => break,
                Err(_) => {}
            }
        }
        assert!(got_unban, "restored ban should trigger unban after expiry");

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn manual_ban_via_cmd() {
        let mut jails = HashMap::new();
        jails.insert("sshd".to_string(), test_jail_config());

        let (_failure_tx, failure_rx) = mpsc::channel(16);
        let (executor_tx, mut executor_rx) = mpsc::channel(16);
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            crate::track::run(
                test_global_config(),
                jails,
                failure_rx,
                cmd_rx,
                executor_tx,
                vec![],
                std::collections::HashMap::new(),
                test_store(),
                None,
                cancel_clone,
            )
            .await;
        });

        let ip = IpAddr::V4(Ipv4Addr::new(60, 60, 60, 60));
        let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
        cmd_tx
            .send(TrackerCmd::ManualBan {
                ip,
                jail_id: "sshd".to_string(),
                ban_time: 3600,
                respond: respond_tx,
            })
            .await
            .unwrap();

        let result = respond_rx.await.unwrap();
        assert!(result.is_ok());

        // Should receive Ban command.
        let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), executor_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert!(matches!(cmd, FirewallCmd::Ban { .. }));

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn manual_ban_already_banned_error() {
        let mut jails = HashMap::new();
        jails.insert("sshd".to_string(), test_jail_config());

        let ip = IpAddr::V4(Ipv4Addr::new(70, 70, 70, 70));
        let now = chrono::Utc::now().timestamp();
        let restored = vec![crate::track::state::BanRecord {
            ip,
            jail_id: "sshd".to_string(),
            banned_at: now,
            expires_at: Some(now + 3600),
        }];

        let (_failure_tx, failure_rx) = mpsc::channel(16);
        let (executor_tx, _executor_rx) = mpsc::channel(16);
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            crate::track::run(
                test_global_config(),
                jails,
                failure_rx,
                cmd_rx,
                executor_tx,
                restored,
                std::collections::HashMap::new(),
                test_store(),
                None,
                cancel_clone,
            )
            .await;
        });

        let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
        cmd_tx
            .send(TrackerCmd::ManualBan {
                ip,
                jail_id: "sshd".to_string(),
                ban_time: 3600,
                respond: respond_tx,
            })
            .await
            .unwrap();

        let result = respond_rx.await.unwrap();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already banned"));

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn manual_unban_via_cmd() {
        let mut jails = HashMap::new();
        jails.insert("sshd".to_string(), test_jail_config());

        let ip = IpAddr::V4(Ipv4Addr::new(80, 80, 80, 80));
        let now = chrono::Utc::now().timestamp();
        let restored = vec![crate::track::state::BanRecord {
            ip,
            jail_id: "sshd".to_string(),
            banned_at: now,
            expires_at: Some(now + 3600),
        }];

        let (_failure_tx, failure_rx) = mpsc::channel(16);
        let (executor_tx, mut executor_rx) = mpsc::channel(16);
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            crate::track::run(
                test_global_config(),
                jails,
                failure_rx,
                cmd_rx,
                executor_tx,
                restored,
                std::collections::HashMap::new(),
                test_store(),
                None,
                cancel_clone,
            )
            .await;
        });

        let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
        cmd_tx
            .send(TrackerCmd::ManualUnban {
                ip,
                jail_id: "sshd".to_string(),
                respond: respond_tx,
            })
            .await
            .unwrap();

        let result = respond_rx.await.unwrap();
        assert!(result.is_ok());

        // Should receive Unban command.
        let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), executor_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert!(matches!(cmd, FirewallCmd::Unban { .. }));

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn query_bans_via_cmd() {
        let mut jails = HashMap::new();
        jails.insert("sshd".to_string(), test_jail_config());

        let ip = IpAddr::V4(Ipv4Addr::new(90, 90, 90, 90));
        let now = chrono::Utc::now().timestamp();
        let restored = vec![crate::track::state::BanRecord {
            ip,
            jail_id: "sshd".to_string(),
            banned_at: now,
            expires_at: Some(now + 3600),
        }];

        let (_failure_tx, failure_rx) = mpsc::channel(16);
        let (executor_tx, _executor_rx) = mpsc::channel(16);
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            crate::track::run(
                test_global_config(),
                jails,
                failure_rx,
                cmd_rx,
                executor_tx,
                restored,
                std::collections::HashMap::new(),
                test_store(),
                None,
                cancel_clone,
            )
            .await;
        });

        let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
        cmd_tx
            .send(TrackerCmd::QueryBans {
                respond: respond_tx,
            })
            .await
            .unwrap();

        let bans = respond_rx.await.unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].ip, ip);

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn get_stats_via_cmd() {
        let mut jails = HashMap::new();
        jails.insert("sshd".to_string(), test_jail_config());

        let (failure_tx, failure_rx) = mpsc::channel(16);
        let (executor_tx, _executor_rx) = mpsc::channel(16);
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            crate::track::run(
                test_global_config(),
                jails,
                failure_rx,
                cmd_rx,
                executor_tx,
                vec![],
                std::collections::HashMap::new(),
                test_store(),
                None,
                cancel_clone,
            )
            .await;
        });

        // Send some failures first.
        let ip = IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100));
        let now = chrono::Utc::now().timestamp();
        for i in 0..2 {
            failure_tx
                .send(Failure {
                    ip,
                    jail_id: "sshd".to_string(),
                    timestamp: now + i,
                })
                .await
                .unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
        cmd_tx
            .send(TrackerCmd::GetStats {
                respond: respond_tx,
            })
            .await
            .unwrap();

        let stats = respond_rx.await.unwrap();
        assert_eq!(stats.total_failures, 2);
        assert_eq!(stats.active_bans, 0);
        assert!(stats.jails.contains_key("sshd"));
        assert_eq!(stats.jails["sshd"].total_failures, 2);

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn same_ip_different_jails_tracked_independently() {
        let mut jails = HashMap::new();
        jails.insert("sshd".to_string(), test_jail_config());
        let mut nginx = test_jail_config();
        nginx.filter = vec!["client: <HOST>".to_string()];
        jails.insert("nginx".to_string(), nginx);

        let (failure_tx, failure_rx) = mpsc::channel(64);
        let (executor_tx, mut executor_rx) = mpsc::channel(64);
        let (_cmd_tx, cmd_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            crate::track::run(
                test_global_config(),
                jails,
                failure_rx,
                cmd_rx,
                executor_tx,
                vec![],
                std::collections::HashMap::new(),
                test_store(),
                None,
                cancel_clone,
            )
            .await;
        });

        let ip = IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10));
        let now = chrono::Utc::now().timestamp();

        // Trigger ban in sshd (3 failures = max_retry).
        for i in 0..3 {
            failure_tx
                .send(Failure {
                    ip,
                    jail_id: "sshd".to_string(),
                    timestamp: now + i,
                })
                .await
                .unwrap();
        }

        // Should receive Ban for sshd.
        let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), executor_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        match &cmd {
            FirewallCmd::Ban { jail_id, .. } => assert_eq!(jail_id, "sshd"),
            other => panic!("expected Ban for sshd, got: {other:?}"),
        }

        // Same IP, trigger ban in nginx (3 more failures).
        for i in 0..3 {
            failure_tx
                .send(Failure {
                    ip,
                    jail_id: "nginx".to_string(),
                    timestamp: now + 10 + i,
                })
                .await
                .unwrap();
        }

        // Should receive Ban for nginx (same IP, different jail).
        let mut got_nginx_ban = false;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(std::time::Duration::from_millis(200), executor_rx.recv())
                .await
            {
                Ok(Some(FirewallCmd::Ban { jail_id, .. })) if jail_id == "nginx" => {
                    got_nginx_ban = true;
                    break;
                }
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => {}
            }
        }
        assert!(
            got_nginx_ban,
            "same IP should be independently bannable in different jails"
        );

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_maxmind_asn_att() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("info")
            .with_test_writer()
            .try_init();

        let mut jails = HashMap::new();
        jails.insert("sshd".to_string(), test_jail_config());

        let (failure_tx, failure_rx) = mpsc::channel(16);
        let (executor_tx, mut executor_rx) = mpsc::channel(16);
        let (_cmd_tx, cmd_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            crate::track::run(
                test_global_config(),
                jails,
                failure_rx,
                cmd_rx,
                executor_tx,
                vec![],
                HashMap::new(),
                test_store(),
                None,
                cancel_clone,
            )
            .await;
        });

        // Target: ASN 7018 (AT&T Services, Inc.)
        let ip: std::net::IpAddr = "71.134.65.5".parse().unwrap();
        let now = chrono::Utc::now().timestamp();

        for i in 0..3 {
            failure_tx
                .send(Failure {
                    ip,
                    jail_id: "sshd".to_string(),
                    timestamp: now + i,
                })
                .await
                .unwrap();
        }

        let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), executor_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(cmd, FirewallCmd::Ban { .. }));

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_maxmind_country_uk_ipv6() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("info")
            .with_test_writer()
            .try_init();

        let mut jails = HashMap::new();
        jails.insert("sshd".to_string(), test_jail_config());

        let (failure_tx, failure_rx) = mpsc::channel(16);
        let (executor_tx, mut executor_rx) = mpsc::channel(16);
        let (_cmd_tx, cmd_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            crate::track::run(
                test_global_config(),
                jails,
                failure_rx,
                cmd_rx,
                executor_tx,
                vec![],
                HashMap::new(),
                test_store(),
                None,
                cancel_clone,
            )
            .await;
        });

        // Target: United Kingdom (IPv6)
        let ip: std::net::IpAddr = "2a02:dd40:22::42".parse().unwrap();
        let now = chrono::Utc::now().timestamp();

        for i in 0..3 {
            failure_tx
                .send(Failure {
                    ip,
                    jail_id: "sshd".to_string(),
                    timestamp: now + i,
                })
                .await
                .unwrap();
        }

        let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), executor_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(cmd, FirewallCmd::Ban { .. }));

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_maxmind_city_sweden() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("info")
            .with_test_writer()
            .try_init();

        let mut jails = HashMap::new();
        jails.insert("sshd".to_string(), test_jail_config());

        let (failure_tx, failure_rx) = mpsc::channel(16);
        let (executor_tx, mut executor_rx) = mpsc::channel(16);
        let (_cmd_tx, cmd_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            crate::track::run(
                test_global_config(),
                jails,
                failure_rx,
                cmd_rx,
                executor_tx,
                vec![],
                HashMap::new(),
                test_store(),
                None,
                cancel_clone,
            )
            .await;
        });

        // Target: Linköping, Sweden (Validates UTF-8 handling too!)
        let ip: std::net::IpAddr = "89.160.20.142".parse().unwrap();
        let now = chrono::Utc::now().timestamp();

        for i in 0..3 {
            failure_tx
                .send(Failure {
                    ip,
                    jail_id: "sshd".to_string(),
                    timestamp: now + i,
                })
                .await
                .unwrap();
        }

        let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), executor_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(cmd, FirewallCmd::Ban { .. }));

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_manual_ban_unknown_jail_returns_error() {
        let mut jails = HashMap::new();
        jails.insert("sshd".to_string(), test_jail_config());

        let (_failure_tx, failure_rx) = mpsc::channel(16);
        let (executor_tx, _executor_rx) = mpsc::channel(16);
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            crate::track::run(
                test_global_config(),
                jails,
                failure_rx,
                cmd_rx,
                executor_tx,
                vec![],
                std::collections::HashMap::new(),
                test_store(),
                None,
                cancel_clone,
            )
            .await;
        });

        let ip = IpAddr::V4(Ipv4Addr::new(110, 110, 110, 110));
        let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
        cmd_tx
            .send(TrackerCmd::ManualBan {
                ip,
                jail_id: "nonexistent_jail".to_string(),
                ban_time: 3600,
                respond: respond_tx,
            })
            .await
            .unwrap();

        let result = respond_rx.await.unwrap();
        assert!(result.is_err(), "unknown jail should return an error");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("unknown jail"),
            "error should mention unknown jail, got: {err_msg}"
        );

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_manual_unban_unknown_jail_returns_error() {
        let mut jails = HashMap::new();
        jails.insert("sshd".to_string(), test_jail_config());

        let (_failure_tx, failure_rx) = mpsc::channel(16);
        let (executor_tx, _executor_rx) = mpsc::channel(16);
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            crate::track::run(
                test_global_config(),
                jails,
                failure_rx,
                cmd_rx,
                executor_tx,
                vec![],
                std::collections::HashMap::new(),
                test_store(),
                None,
                cancel_clone,
            )
            .await;
        });

        let ip = IpAddr::V4(Ipv4Addr::new(111, 111, 111, 111));
        let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
        cmd_tx
            .send(TrackerCmd::ManualUnban {
                ip,
                jail_id: "nonexistent_jail".to_string(),
                respond: respond_tx,
            })
            .await
            .unwrap();

        let result = respond_rx.await.unwrap();
        assert!(result.is_err(), "unknown jail should return an error");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("unknown jail"),
            "error should mention unknown jail, got: {err_msg}"
        );

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_manual_unban_not_banned_returns_error() {
        let mut jails = HashMap::new();
        jails.insert("sshd".to_string(), test_jail_config());

        // No restored bans — IP is not currently banned.
        let (_failure_tx, failure_rx) = mpsc::channel(16);
        let (executor_tx, _executor_rx) = mpsc::channel(16);
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            crate::track::run(
                test_global_config(),
                jails,
                failure_rx,
                cmd_rx,
                executor_tx,
                vec![],
                std::collections::HashMap::new(),
                test_store(),
                None,
                cancel_clone,
            )
            .await;
        });

        let ip = IpAddr::V4(Ipv4Addr::new(112, 112, 112, 112));
        let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
        cmd_tx
            .send(TrackerCmd::ManualUnban {
                ip,
                jail_id: "sshd".to_string(),
                respond: respond_tx,
            })
            .await
            .unwrap();

        let result = respond_rx.await.unwrap();
        assert!(
            result.is_err(),
            "unbanning a non-banned IP should return an error"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("not banned"),
            "error should mention not banned, got: {err_msg}"
        );

        cancel.cancel();
        handle.await.unwrap();
    }
}
