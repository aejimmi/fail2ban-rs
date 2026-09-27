//! Daemon lifecycle — spawns all tasks, handles signals and config reload.

mod control_dispatch;
mod reload;
mod reload_delta;
mod restored;
mod startup;
mod watchers;

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use restored::{Restored, open_state};
use startup::{DaemonSignal, Signals};

use crate::config::{Config, JailConfig};
use crate::control::{self, ControlCmd};
use crate::detect::watcher::Failure;
use crate::enforce::{self, FirewallCmd};
use crate::logging::Logger;
use crate::track::TrackerCmd;
use crate::track::state::BanRecord;

use control_dispatch::dispatch_control;
use reload::{ReloadContext, reload_config, teardown_firewalls_full};
use watchers::{Watchers, build_watcher_plan};

/// Run the daemon with the given configuration.
pub async fn run(config: Config, config_path: PathBuf) -> crate::error::Result<()> {
    info!(phase = "startup", "fail2ban-rs starting");
    let cancel = CancellationToken::new();
    // Initialize remote logging (no-op if not configured).
    let logger = Logger::init(&config.logging);
    let restored = open_state(&config.global.state_dir).await?;

    let mut daemon = start_tasks(config, config_path, restored, logger, cancel).await?;
    info!(phase = "startup", "fail2ban-rs started");
    let result = daemon.serve().await;

    // Graceful shutdown: close Tell client, then let tasks drain.
    if let Some(t) = daemon.logger.take() {
        t.close().await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    info!(phase = "shutdown", "fail2ban-rs stopped");
    result
}

/// Wire the channels and spawn the executor, tracker, watchers, and control
/// socket, returning the daemon state the main loop runs on.
async fn start_tasks(
    config: Config,
    config_path: PathBuf,
    restored: Restored,
    logger: Option<Logger>,
    cancel: CancellationToken,
) -> crate::error::Result<Daemon> {
    // Compile every watcher up front so a bad filter fails before any task
    // or firewall rule exists.
    let plan = build_watcher_plan(&config)?;
    let (failure_tx, failure_rx) = mpsc::channel::<Failure>(config.global.channel_size);
    let (tracker_cmd_tx, tracker_cmd_rx) = mpsc::channel::<TrackerCmd>(32);
    let tracker_io = (failure_rx, tracker_cmd_rx, tracker_cmd_tx.clone());
    let executor_tx = start_core(&config, restored, tracker_io, logger.clone(), &cancel).await?;
    // Watchers keep their own token and join handles, so a reload can hand
    // each jail's read position to its replacement.
    let watchers = Watchers::spawn(plan, &failure_tx, "startup", HashMap::new());
    let control_rx = spawn_control(&config, &cancel);
    Ok(Daemon {
        config,
        config_path,
        executor_tx,
        tracker_cmd_tx,
        failure_tx,
        control_rx,
        watchers,
        logger,
        cancel,
    })
}

/// Tracker inputs plus the tracker-command sender handed to the executor.
type TrackerIo = (
    mpsc::Receiver<Failure>,
    mpsc::Receiver<TrackerCmd>,
    mpsc::Sender<TrackerCmd>,
);

/// Spawn the executor (after restoring bans) and the tracker; returns the
/// executor command sender.
async fn start_core(
    config: &Config,
    restored: Restored,
    (failure_rx, cmd_rx, tracker_tx): TrackerIo,
    logger: Option<Logger>,
    cancel: &CancellationToken,
) -> crate::error::Result<mpsc::Sender<FirewallCmd>> {
    let (executor_tx, executor_rx) = mpsc::channel::<FirewallCmd>(config.global.channel_size);
    let jail_configs = enabled_jail_configs(config);
    let executor_io = (executor_rx, tracker_tx);
    let active_bans = start_executor(&restored.bans, &jail_configs, executor_io, cancel).await?;
    if let Some(t) = logger.as_ref() {
        t.log_startup(jail_configs.len(), active_bans.len());
    }
    tokio::spawn(crate::track::run(
        config.global.clone(),
        jail_configs,
        failure_rx,
        cmd_rx,
        executor_tx.clone(),
        true,
        active_bans,
        restored.ban_counts,
        restored.store,
        logger,
        cancel.child_token(),
    ));
    Ok(executor_tx)
}

/// Spawn the control-socket listener; returns the request receiver.
fn spawn_control(config: &Config, cancel: &CancellationToken) -> mpsc::Receiver<ControlCmd> {
    let (control_tx, control_rx) = mpsc::channel::<ControlCmd>(32);
    let socket_path = config.global.socket_path.clone();
    let control_cancel = cancel.child_token();
    tokio::spawn(async move { control::run(&socket_path, control_tx, control_cancel).await });
    control_rx
}

/// Enabled jails keyed by name.
fn enabled_jail_configs(config: &Config) -> HashMap<String, JailConfig> {
    config
        .jail
        .iter()
        .filter(|(_, j)| j.enabled)
        .map(|(name, cfg)| (name.clone(), cfg.clone()))
        .collect()
}

/// Receivers and the tracker sender the executor task owns.
type ExecutorIo = (mpsc::Receiver<FirewallCmd>, mpsc::Sender<TrackerCmd>);

/// Create and initialize the firewall backends, re-apply restored bans, then
/// spawn the executor that owns them. Returns the bans actually restored.
///
/// Backends are initialized (chains/sets created) BEFORE restoring bans —
/// otherwise restored bans target sets/chains that do not yet exist and are
/// silently dropped. The executor reports automatic ban-apply failures back
/// to the tracker and services reconcile requests on the same ordered channel.
async fn start_executor(
    restored_bans: &[BanRecord],
    jail_configs: &HashMap<String, JailConfig>,
    (executor_rx, tracker_tx): ExecutorIo,
    cancel: &CancellationToken,
) -> crate::error::Result<Vec<BanRecord>> {
    let backends = enforce::create_backends(jail_configs)?;
    let now = chrono::Utc::now().timestamp();
    let active_bans =
        enforce::init_and_restore(restored_bans, &backends, now, jail_configs).await?;
    info!(
        phase = "startup",
        bans = active_bans.len(),
        "firewall bans restored"
    );
    let executor_cancel = cancel.child_token();
    tokio::spawn(enforce::run(
        executor_rx,
        backends,
        tracker_tx,
        executor_cancel,
    ));
    Ok(active_bans)
}

/// State the daemon's main loop runs on.
struct Daemon {
    config: Config,
    config_path: PathBuf,
    executor_tx: mpsc::Sender<FirewallCmd>,
    tracker_cmd_tx: mpsc::Sender<TrackerCmd>,
    /// Reload-window invariant: the daemon retains this original sender for
    /// its entire lifetime. Reloads clone it for new watchers and stop the old
    /// ones, but because this sender stays alive the whole time, the tracker's
    /// `failure_rx` can never observe all senders dropped mid-reload — so the
    /// tracker will not exit during the watcher respawn window.
    failure_tx: mpsc::Sender<Failure>,
    control_rx: mpsc::Receiver<ControlCmd>,
    watchers: Watchers,
    logger: Option<Logger>,
    cancel: CancellationToken,
}

impl Daemon {
    /// Serve signals and control requests until shutdown.
    async fn serve(&mut self) -> crate::error::Result<()> {
        // Registered once: a signal delivered while a reload or control
        // request runs inline is buffered, not lost.
        let mut signals = Signals::register();
        loop {
            tokio::select! {
                sig = signals.next() => match sig {
                    DaemonSignal::Shutdown => {
                        self.shutdown().await;
                        return Ok(());
                    }
                    DaemonSignal::Reload => self.reload_on_sighup().await?,
                },
                cmd = self.control_rx.recv() => {
                    let Some(ctrl) = cmd else {
                        info!("control channel closed");
                        return Ok(());
                    };
                    self.dispatch(ctrl).await;
                    if self.tracker_cmd_tx.is_closed() {
                        return Err(crate::error::Error::ChannelClosed);
                    }
                }
            }
        }
    }

    /// Tear down every jail's firewall state, stop the watchers (collecting
    /// their final reads), then cancel the remaining tasks.
    async fn shutdown(&mut self) {
        info!(phase = "shutdown", "fail2ban-rs stopping");
        let jails = self.config.enabled_jails().map(|(name, _)| name);
        teardown_firewalls_full(&self.executor_tx, jails, "shutdown").await;
        self.watchers.stop().await;
        self.cancel.cancel();
    }

    /// Reload the config in response to SIGHUP.
    async fn reload_on_sighup(&mut self) -> crate::error::Result<()> {
        info!(
            phase = "reload",
            trigger = "sighup",
            "config reload starting"
        );
        let result = reload_config(
            &self.config_path,
            &self.executor_tx,
            &self.tracker_cmd_tx,
            &mut self.config,
            &mut self.watchers,
            &self.failure_tx,
            self.logger.as_ref(),
        )
        .await;
        match result {
            Ok(()) => info!(phase = "reload", "config reload complete"),
            Err(e) => {
                error!(phase = "reload", error = %e, "config reload failed");
                if self.tracker_cmd_tx.is_closed() {
                    return Err(crate::error::Error::ChannelClosed);
                }
            }
        }
        Ok(())
    }

    /// Serve one control request. Tracker-bound requests are answered on a
    /// spawned task so a slow firewall never delays signal handling here.
    async fn dispatch(&mut self, ctrl: ControlCmd) {
        let mut ctx = ReloadContext {
            config_path: &self.config_path,
            executor_tx: &self.executor_tx,
            config: &mut self.config,
            watchers: &mut self.watchers,
            failure_tx: &self.failure_tx,
            logger: self.logger.as_ref(),
        };
        dispatch_control(ctrl, &self.tracker_cmd_tx, &mut ctx).await;
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
mod mod_test;
