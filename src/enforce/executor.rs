//! Executor task loop and per-command firewall handlers.

use std::collections::HashMap;
use std::hash::BuildHasher;
use std::net::IpAddr;

use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::error::{Error, Result};
use crate::track::TrackerCmd;

use super::{FirewallBackend, FirewallCmd};

#[path = "executor_reload.rs"]
mod reload;

use reload::{JailRules, RunningRules, handle_reload_cmd};

#[path = "executor_reconcile.rs"]
mod reconcile;

use reconcile::reconcile_bans;

/// Run the executor task loop.
///
/// Reads [`FirewallCmd`]s from `rx` — a single ordered channel, so ban,
/// unban, reconcile, and reload commands execute in exactly the order the
/// tracker issued them. When an *automatic* ban (`done: None`) fails to
/// apply, it notifies the tracker on `tracker_tx` with
/// [`TrackerCmd::BanApplyFailed`] so the tracker can roll back its state.
pub async fn run<S: BuildHasher>(
    mut rx: mpsc::Receiver<FirewallCmd>,
    mut backends: HashMap<String, Box<dyn FirewallBackend>, S>,
    tracker_tx: mpsc::Sender<TrackerCmd>,
    cancel: CancellationToken,
) {
    log_startup(&backends);
    let mut running = RunningRules::new();
    loop {
        let cmd = tokio::select! {
            () = cancel.cancelled() => {
                info!(phase = "shutdown", "executor stopping");
                break;
            }
            cmd = rx.recv() => cmd,
        };
        let Some(cmd) = cmd else {
            info!("executor channel closed");
            break;
        };
        handle_cmd(cmd, &mut backends, &mut running, &tracker_tx).await;
    }
}

/// Log the executor start with each jail's backend name.
fn log_startup<S: BuildHasher>(backends: &HashMap<String, Box<dyn FirewallBackend>, S>) {
    let names: Vec<_> = backends
        .iter()
        .map(|(k, v)| format!("{k}={}", v.name()))
        .collect();
    let backends_fmt = format!("[{}]", names.join(","));
    info!(
        phase = "startup",
        backends = %backends_fmt,
        "executor started"
    );
}

/// Dispatch a single firewall command to the matching backend handler.
///
/// Takes the backend map by `&mut` so reload commands (add/replace/remove) can
/// register, swap, or deregister backends in place; the other handlers only
/// need shared access and reborrow it.
async fn handle_cmd<S: BuildHasher>(
    cmd: FirewallCmd,
    backends: &mut HashMap<String, Box<dyn FirewallBackend>, S>,
    running: &mut RunningRules,
    tracker_tx: &mpsc::Sender<TrackerCmd>,
) {
    match cmd {
        ban @ FirewallCmd::Ban { .. } => handle_ban(ban, backends, tracker_tx).await,
        FirewallCmd::Reconcile { bans } => reconcile_bans(backends, bans).await,
        FirewallCmd::Unban { ip, jail_id, done } => {
            let result = apply_unban(backends, ip, &jail_id).await;
            if let Some(done) = done {
                send_done(done, result, &jail_id);
            }
        }
        FirewallCmd::InitJail {
            jail_id,
            ports,
            protocol,
            done,
        } => {
            init_jail(backends, &jail_id, &ports, &protocol, done).await;
            running.insert(jail_id, JailRules::new(ports, protocol));
        }
        FirewallCmd::TeardownJail { jail_id, done } => {
            teardown(backends, &jail_id, false, done).await;
        }
        FirewallCmd::TeardownJailFull { jail_id, done } => {
            teardown(backends, &jail_id, true, done).await;
        }
        reload_cmd => handle_reload_cmd(reload_cmd, backends, running).await,
    }
}

/// Deliver a command result to its requester; a dropped requester (e.g. a
/// reload that gave up) is logged rather than treated as an error.
fn send_done(done: oneshot::Sender<Result<()>>, result: Result<()>, jail_id: &str) {
    if done.send(result).is_err() {
        debug!(jail = %jail_id, "firewall command requester dropped before ack");
    }
}

/// Unpack a `Ban` command and apply it.
async fn handle_ban<S: BuildHasher>(
    cmd: FirewallCmd,
    backends: &HashMap<String, Box<dyn FirewallBackend>, S>,
    tracker_tx: &mpsc::Sender<TrackerCmd>,
) {
    let FirewallCmd::Ban {
        ip,
        jail_id,
        banned_at,
        expires_at,
        done,
    } = cmd
    else {
        return;
    };
    let ban = BanTarget {
        ip,
        jail_id: &jail_id,
        banned_at,
        expires_at,
    };
    apply_ban(backends, tracker_tx, &ban, done).await;
}

/// The ban a `Ban` command asks for.
struct BanTarget<'a> {
    ip: IpAddr,
    jail_id: &'a str,
    /// Identifies the tracker record, echoed back on failure.
    banned_at: i64,
    expires_at: Option<i64>,
}

/// Apply a ban. On the automatic path (`done: None`) a backend failure is
/// reported to the tracker for rollback; the manual path (`done: Some`) returns
/// the result verbatim via the oneshot and never notifies the tracker.
async fn apply_ban<S: BuildHasher>(
    backends: &HashMap<String, Box<dyn FirewallBackend>, S>,
    tracker_tx: &mpsc::Sender<TrackerCmd>,
    ban: &BanTarget<'_>,
    done: Option<oneshot::Sender<Result<()>>>,
) {
    let (ip, jail_id, expires_at) = (ban.ip, ban.jail_id, ban.expires_at);
    let now = chrono::Utc::now().timestamp();
    debug!(%ip, jail = %jail_id, "firewall applying ban");
    let result = if let Some(backend) = backends.get(jail_id) {
        backend
            .ban_with_timeout(&ip, jail_id, expires_at, now)
            .await
    } else {
        Err(Error::firewall(format!(
            "no backend registered for jail {jail_id}"
        )))
    };
    if let Err(ref e) = result {
        error!(%ip, jail = %jail_id, error = %e, "ban failed");
    }
    match done {
        Some(done) => send_done(done, result, jail_id),
        None if result.is_err() => notify_ban_failed(tracker_tx, ban),
        None => {}
    }
}

/// Notify the tracker that an automatic ban failed to apply.
///
/// Uses `try_send` so the executor never blocks (and cannot deadlock against a
/// full tracker-command channel). A dropped notification is self-healing: the
/// periodic reconcile will re-apply the still-persisted ban to the kernel.
fn notify_ban_failed(tracker_tx: &mpsc::Sender<TrackerCmd>, ban: &BanTarget<'_>) {
    let cmd = TrackerCmd::BanApplyFailed {
        ip: ban.ip,
        jail_id: ban.jail_id.to_string(),
        banned_at: ban.banned_at,
    };
    if tracker_tx.try_send(cmd).is_err() {
        warn!(ip = %ban.ip, jail = %ban.jail_id, "ban failure notify dropped; reconcile will heal");
    }
}

/// Remove a ban from the firewall, tolerating an already-absent entry.
async fn apply_unban<S: BuildHasher>(
    backends: &HashMap<String, Box<dyn FirewallBackend>, S>,
    ip: IpAddr,
    jail_id: &str,
) -> Result<()> {
    debug!(%ip, jail = %jail_id, "firewall applying unban");
    let Some(backend) = backends.get(jail_id) else {
        warn!(%ip, jail = %jail_id, reason = "no_backend", "unban skipped");
        return Err(Error::firewall(format!(
            "no backend registered for jail {jail_id}"
        )));
    };
    let result = backend.unban(&ip, jail_id).await;
    if let Err(ref e) = result {
        warn!(%ip, jail = %jail_id, error = %e, "unban failed");
    }
    result
}

/// Initialize a jail's firewall rules, replying on `done`.
async fn init_jail<S: BuildHasher>(
    backends: &HashMap<String, Box<dyn FirewallBackend>, S>,
    jail_id: &str,
    ports: &[String],
    protocol: &str,
    done: oneshot::Sender<Result<()>>,
) {
    debug!(jail = %jail_id, "firewall initializing");
    let result = if let Some(backend) = backends.get(jail_id) {
        backend.init(jail_id, ports, protocol).await
    } else {
        warn!(jail = %jail_id, reason = "no_backend", "firewall initialization skipped");
        Ok(())
    };
    if let Err(ref e) = result {
        debug!(jail = %jail_id, error = %e, "firewall initialization backend error");
    }
    send_done(done, result, jail_id);
}

/// Tear down a jail's firewall rules, replying on `done`. `full` removes shared
/// infrastructure (daemon shutdown); otherwise only the jail's own state.
async fn teardown<S: BuildHasher>(
    backends: &HashMap<String, Box<dyn FirewallBackend>, S>,
    jail_id: &str,
    full: bool,
    done: oneshot::Sender<Result<()>>,
) {
    debug!(jail = %jail_id, full, "firewall tearing down");
    let result = match backends.get(jail_id) {
        Some(backend) if full => backend.teardown_full(jail_id).await,
        Some(backend) => backend.teardown(jail_id).await,
        None => Ok(()),
    };
    if let Err(ref e) = result {
        debug!(jail = %jail_id, full, error = %e, "firewall teardown backend error");
    }
    send_done(done, result, jail_id);
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "executor_test.rs"]
mod executor_test;

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "executor_jail_test.rs"]
mod executor_jail_test;
