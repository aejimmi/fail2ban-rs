//! Executor task loop and per-command firewall handlers.

use std::collections::HashMap;
use std::hash::BuildHasher;
use std::net::IpAddr;

use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::config::Backend;
use crate::error::Result;
use crate::track::TrackerCmd;
use crate::track::state::BanRecord;

use super::{FirewallBackend, FirewallCmd, ReconcileRequest, create_backend};

/// Run the executor task loop.
///
/// Reads [`FirewallCmd`]s from `rx` and [`ReconcileRequest`]s from
/// `reconcile_rx`. When an *automatic* ban (`done: None`) fails to apply, it
/// notifies the tracker on `tracker_tx` with [`TrackerCmd::BanApplyFailed`] so
/// the tracker can roll back its persisted state.
pub async fn run<S: BuildHasher>(
    mut rx: mpsc::Receiver<FirewallCmd>,
    mut reconcile_rx: mpsc::Receiver<ReconcileRequest>,
    mut backends: HashMap<String, Box<dyn FirewallBackend>, S>,
    tracker_tx: mpsc::Sender<TrackerCmd>,
    cancel: CancellationToken,
) {
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

    // Once the reconcile channel closes we disable its select branch so a
    // closed receiver does not spin returning `None`.
    let mut reconcile_open = true;
    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                info!(phase = "shutdown", "executor stopping");
                break;
            }
            cmd = rx.recv() => {
                if let Some(c) = cmd {
                    handle_cmd(c, &mut backends, &tracker_tx).await;
                } else {
                    info!("executor channel closed");
                    break;
                }
            }
            req = reconcile_rx.recv(), if reconcile_open => {
                if let Some(r) = req {
                    reconcile_bans(&backends, r.bans).await;
                } else {
                    reconcile_open = false;
                }
            }
        }
    }
}

/// Dispatch a single firewall command to the matching backend handler.
///
/// Takes the backend map by `&mut` so reload commands ([`FirewallCmd::AddJail`]
/// and [`FirewallCmd::RemoveJail`]) can register/deregister backends in place;
/// the other handlers only need shared access and reborrow it.
async fn handle_cmd<S: BuildHasher>(
    cmd: FirewallCmd,
    backends: &mut HashMap<String, Box<dyn FirewallBackend>, S>,
    tracker_tx: &mpsc::Sender<TrackerCmd>,
) {
    match cmd {
        FirewallCmd::Ban {
            ip,
            jail_id,
            banned_at,
            expires_at,
            done,
        } => {
            let _ = banned_at;
            apply_ban(backends, tracker_tx, ip, &jail_id, expires_at, done).await;
        }
        FirewallCmd::Unban { ip, jail_id } => apply_unban(backends, ip, &jail_id).await,
        FirewallCmd::InitJail {
            jail_id,
            ports,
            protocol,
            done,
        } => init_jail(backends, &jail_id, &ports, &protocol, done).await,
        FirewallCmd::TeardownJail { jail_id, done } => {
            teardown(backends, &jail_id, false, done).await;
        }
        FirewallCmd::TeardownJailFull { jail_id, done } => {
            teardown(backends, &jail_id, true, done).await;
        }
        FirewallCmd::AddJail {
            jail_id,
            backend,
            ports,
            protocol,
            done,
        } => add_jail(backends, jail_id, &backend, &ports, &protocol, done).await,
        FirewallCmd::RemoveJail { jail_id, done } => remove_jail(backends, &jail_id, done).await,
    }
}

/// Register a jail's backend and initialize its kernel state, replying on `done`.
///
/// The backend is inserted only after a successful `init`, so a failed
/// initialization never leaves a half-registered jail behind.
async fn add_jail<S: BuildHasher>(
    backends: &mut HashMap<String, Box<dyn FirewallBackend>, S>,
    jail_id: String,
    backend: &Backend,
    ports: &[String],
    protocol: &str,
    done: oneshot::Sender<Result<()>>,
) {
    debug!(jail = %jail_id, "firewall adding jail");
    let result = register_jail(backends, &jail_id, backend, ports, protocol).await;
    if let Err(ref e) = result {
        error!(jail = %jail_id, error = %e, "firewall add jail failed");
    }
    let _ = done.send(result);
}

/// Build the backend, run `init`, then insert it into the map.
async fn register_jail<S: BuildHasher>(
    backends: &mut HashMap<String, Box<dyn FirewallBackend>, S>,
    jail_id: &str,
    backend: &Backend,
    ports: &[String],
    protocol: &str,
) -> Result<()> {
    let created = create_backend(backend)?;
    created.init(jail_id, ports, protocol).await?;
    backends.insert(jail_id.to_string(), created);
    Ok(())
}

/// Tear down a jail's kernel state and remove its backend, replying on `done`.
///
/// The teardown removes the jail's own chain/set (and every banned element);
/// shared infrastructure is left in place for the still-active jails.
async fn remove_jail<S: BuildHasher>(
    backends: &mut HashMap<String, Box<dyn FirewallBackend>, S>,
    jail_id: &str,
    done: oneshot::Sender<Result<()>>,
) {
    debug!(jail = %jail_id, "firewall removing jail");
    let result = match backends.get(jail_id) {
        Some(backend) => backend.teardown(jail_id).await,
        None => Ok(()),
    };
    backends.remove(jail_id);
    if let Err(ref e) = result {
        debug!(jail = %jail_id, error = %e, "firewall remove jail teardown error");
    }
    let _ = done.send(result);
}

/// Apply a ban. On the automatic path (`done: None`) a backend failure is
/// reported to the tracker for rollback; the manual path (`done: Some`) returns
/// the result verbatim via the oneshot and never notifies the tracker.
async fn apply_ban<S: BuildHasher>(
    backends: &HashMap<String, Box<dyn FirewallBackend>, S>,
    tracker_tx: &mpsc::Sender<TrackerCmd>,
    ip: IpAddr,
    jail_id: &str,
    expires_at: Option<i64>,
    done: Option<oneshot::Sender<Result<()>>>,
) {
    let now = chrono::Utc::now().timestamp();
    debug!(%ip, jail = %jail_id, "firewall applying ban");
    let result = if let Some(backend) = backends.get(jail_id) {
        backend
            .ban_with_timeout(&ip, jail_id, expires_at, now)
            .await
    } else {
        warn!(%ip, jail = %jail_id, reason = "no_backend", "ban skipped");
        Ok(())
    };
    if let Err(ref e) = result {
        error!(%ip, jail = %jail_id, error = %e, "ban failed");
    }
    match done {
        Some(done) => {
            let _ = done.send(result);
        }
        None if result.is_err() => notify_ban_failed(tracker_tx, ip, jail_id),
        None => {}
    }
}

/// Notify the tracker that an automatic ban failed to apply.
///
/// Uses `try_send` so the executor never blocks (and cannot deadlock against a
/// full tracker-command channel). A dropped notification is self-healing: the
/// periodic reconcile will re-apply the still-persisted ban to the kernel.
fn notify_ban_failed(tracker_tx: &mpsc::Sender<TrackerCmd>, ip: IpAddr, jail_id: &str) {
    let cmd = TrackerCmd::BanApplyFailed {
        ip,
        jail_id: jail_id.to_string(),
    };
    if tracker_tx.try_send(cmd).is_err() {
        warn!(%ip, jail = %jail_id, "ban failure notify dropped; reconcile will heal");
    }
}

/// Remove a ban from the firewall, tolerating an already-absent entry.
async fn apply_unban<S: BuildHasher>(
    backends: &HashMap<String, Box<dyn FirewallBackend>, S>,
    ip: IpAddr,
    jail_id: &str,
) {
    debug!(%ip, jail = %jail_id, "firewall applying unban");
    let Some(backend) = backends.get(jail_id) else {
        warn!(%ip, jail = %jail_id, reason = "no_backend", "unban skipped");
        return;
    };
    if let Err(e) = backend.unban(&ip, jail_id).await {
        warn!(%ip, jail = %jail_id, error = %e, "unban failed");
    }
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
    let _ = done.send(result);
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
    let _ = done.send(result);
}

/// Verify each ban against the firewall and re-apply any the kernel is missing.
async fn reconcile_bans<S: BuildHasher>(
    backends: &HashMap<String, Box<dyn FirewallBackend>, S>,
    bans: Vec<BanRecord>,
) {
    let now = chrono::Utc::now().timestamp();
    let mut reapplied = 0usize;
    for ban in &bans {
        if reconcile_one(backends, ban, now).await {
            reapplied += 1;
        }
    }
    if reapplied > 0 {
        info!(
            reapplied,
            checked = bans.len(),
            "reconcile re-applied missing bans"
        );
    } else {
        debug!(checked = bans.len(), "reconcile: all bans present");
    }
}

/// Reconcile a single ban; returns `true` if it was missing and re-applied.
async fn reconcile_one<S: BuildHasher>(
    backends: &HashMap<String, Box<dyn FirewallBackend>, S>,
    ban: &BanRecord,
    now: i64,
) -> bool {
    let Some(backend) = backends.get(&ban.jail_id) else {
        return false;
    };
    match backend.is_banned(&ban.ip, &ban.jail_id).await {
        Ok(true) => false,
        Ok(false) => match backend
            .ban_with_timeout(&ban.ip, &ban.jail_id, ban.expires_at, now)
            .await
        {
            Ok(()) => {
                info!(ip = %ban.ip, jail = %ban.jail_id, "reconcile re-applied missing ban");
                true
            }
            Err(e) => {
                warn!(ip = %ban.ip, jail = %ban.jail_id, error = %e, "reconcile re-ban failed");
                false
            }
        },
        Err(e) => {
            warn!(ip = %ban.ip, jail = %ban.jail_id, error = %e, "reconcile is_banned check failed");
            false
        }
    }
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
