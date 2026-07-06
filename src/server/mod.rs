//! Daemon lifecycle — spawns all tasks, handles signals and config reload.

mod reload;
mod startup;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use etchdb::FlushPolicy;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use startup::{handle_legacy_state, open_store_migrating, shutdown_signal, signal_sighup};

use crate::config::Config;
use crate::control::{self, ControlCmd, Request, Response};
use crate::detect::watcher::Failure;
use crate::enforce::{self, FirewallCmd};
use crate::logging::Logger;
use crate::track::TrackerCmd;

use reload::{
    ReloadContext, build_watcher_plan, reload_config, spawn_watchers, teardown_firewalls_full,
};

/// Run the daemon with the given configuration.
pub async fn run(mut config: Config, config_path: PathBuf) -> crate::error::Result<()> {
    info!(phase = "startup", "fail2ban-rs starting");

    let cancel = CancellationToken::new();

    // Initialize remote logging (no-op if not configured).
    let logger = Logger::init(&config.logging);

    // Move aside an incompatible legacy state.bin file, if present.
    handle_legacy_state(&config.global.state_dir).await?;

    // Open etch store for persistent ban state, migrating aside any WAL whose
    // on-disk schema is incompatible with this build.
    let mut store = open_store_migrating(&config.global.state_dir).await?;
    store.set_flush_policy(FlushPolicy::Grouped {
        interval: Duration::from_millis(100),
    });
    let store = Arc::new(store);

    // Read restored state from etch, purging any expired bans.
    let now = chrono::Utc::now().timestamp();
    let (restored_bans, restored_ban_counts) = {
        let state = store.read();

        let expired_keys: Vec<_> = state
            .bans
            .iter()
            .filter(|(_, ban)| ban.expires_at.is_some_and(|exp| exp <= now))
            .map(|(key, _)| key.clone())
            .collect();

        let bans: Vec<crate::track::state::BanRecord> = state
            .bans
            .values()
            .filter(|ban| ban.expires_at.is_none_or(|exp| exp > now))
            .cloned()
            .collect();
        let counts: HashMap<std::net::IpAddr, crate::track::persist::BanCount> =
            state.ban_counts.clone();
        drop(state);

        if !expired_keys.is_empty() {
            info!(
                phase = "startup",
                bans = expired_keys.len(),
                "expired bans purged"
            );
            let _ = store.write(|tx| {
                for key in &expired_keys {
                    tx.bans.delete(key);
                }
                Ok(())
            });
        }

        if bans.is_empty() {
            info!(phase = "startup", "no persisted state found");
        } else {
            info!(
                phase = "startup",
                bans = bans.len(),
                "persisted state loaded"
            );
        }
        (bans, counts)
    };

    // Create channels.
    let (failure_tx, failure_rx) = mpsc::channel::<Failure>(config.global.channel_size);
    let (executor_tx, executor_rx) = mpsc::channel::<FirewallCmd>(config.global.channel_size);
    let (reconcile_tx, reconcile_rx) = mpsc::channel::<enforce::ReconcileRequest>(4);
    let (control_tx, mut control_rx) = mpsc::channel::<ControlCmd>(32);
    let (tracker_cmd_tx, tracker_cmd_rx) = mpsc::channel::<TrackerCmd>(32);

    // Create per-jail firewall backends.
    let jail_configs: HashMap<String, _> = config
        .jail
        .iter()
        .filter(|(_, j)| j.enabled)
        .map(|(name, cfg)| (name.clone(), cfg.clone()))
        .collect();
    let backends = enforce::create_backends(&jail_configs)?;

    // Initialize firewall backends (create chains/sets) BEFORE restoring bans,
    // then re-apply restored bans — otherwise restored bans target sets/chains
    // that do not yet exist and are silently dropped. Both run directly on the
    // backends before the executor takes ownership.
    let now = chrono::Utc::now().timestamp();
    let active_bans =
        enforce::init_and_restore(&restored_bans, &backends, now, &jail_configs).await?;
    info!(
        phase = "startup",
        bans = active_bans.len(),
        "firewall bans restored"
    );

    // Spawn executor (owns the already-initialized backends). It reports
    // automatic ban-apply failures back to the tracker via the tracker command
    // channel and services reconcile requests on the dedicated channel.
    let executor_cancel = cancel.child_token();
    let executor_tracker_tx = tracker_cmd_tx.clone();
    tokio::spawn(async move {
        enforce::run(
            executor_rx,
            reconcile_rx,
            backends,
            executor_tracker_tx,
            executor_cancel,
        )
        .await;
    });

    // Log startup event.
    if let Some(t) = logger.as_ref() {
        let jail_count = config.enabled_jails().count();
        t.log_startup(jail_count, active_bans.len());
    }

    // Spawn watchers with their own cancellation token (for reload).
    let watcher_plan = build_watcher_plan(&config)?;
    let mut watcher_cancel = CancellationToken::new();
    spawn_watchers(watcher_plan, &failure_tx, &watcher_cancel, "startup");

    // Spawn tracker.
    let tracker_cancel = cancel.child_token();
    let tracker_executor_tx = executor_tx.clone();
    let tracker_logger = logger.clone();
    let tracker_store = Arc::clone(&store);
    let tracker_global_config = config.global.clone();
    tokio::spawn(async move {
        crate::track::run(
            tracker_global_config,
            jail_configs,
            failure_rx,
            tracker_cmd_rx,
            tracker_executor_tx,
            Some(reconcile_tx),
            active_bans,
            restored_ban_counts,
            tracker_store,
            tracker_logger,
            tracker_cancel,
        )
        .await;
    });

    // Spawn control socket.
    let control_cancel = cancel.child_token();
    let socket_path = config.global.socket_path.clone();
    tokio::spawn(async move {
        control::run(&socket_path, control_tx, control_cancel).await;
    });

    info!(phase = "startup", "fail2ban-rs started");

    // Reload-window invariant: the server retains this original `failure_tx`
    // sender for the entire daemon lifetime (it is never dropped inside the
    // select loop below). Reloads clone it for new watchers and cancel the old
    // ones, but because this sender stays alive the whole time, the tracker's
    // `failure_rx` can never observe all senders dropped mid-reload — so the
    // tracker will not exit during the watcher respawn window.
    let failure_tx_for_reload = failure_tx;

    // Main select loop.
    loop {
        tokio::select! {
            () = shutdown_signal() => {
                info!(phase = "shutdown", "fail2ban-rs stopping");
                teardown_firewalls_full(
                    &executor_tx,
                    config.enabled_jails().map(|(name, _)| name),
                    "shutdown",
                ).await;
                cancel.cancel();
                watcher_cancel.cancel();
                break;
            }

            () = signal_sighup() => {
                info!(
                    phase = "reload",
                    trigger = "sighup",
                    "config reload starting"
                );
                match reload_config(
                    &config_path,
                    &executor_tx,
                    &tracker_cmd_tx,
                    &mut config,
                    &mut watcher_cancel,
                    &failure_tx_for_reload,
                    logger.as_ref(),
                ).await {
                    Ok(()) => info!(phase = "reload", "config reload complete"),
                    Err(e) => error!(
                        phase = "reload",
                        error = %e,
                        "config reload failed"
                    ),
                }
            }

            cmd = control_rx.recv() => {
                if let Some(ctrl) = cmd {
                    let mut ctx = ReloadContext {
                        config_path: &config_path,
                        executor_tx: &executor_tx,
                        config: &mut config,
                        watcher_cancel: &mut watcher_cancel,
                        failure_tx: &failure_tx_for_reload,
                        logger: logger.as_ref(),
                    };
                    let response = handle_control_request(
                        ctrl.request,
                        &tracker_cmd_tx,
                        &mut ctx,
                    ).await;
                    let _ = ctrl.respond.send(response);
                } else {
                    info!("control channel closed");
                    break;
                }
            }
        }
    }

    // Graceful shutdown: close Tell client.
    if let Some(t) = logger {
        t.close().await;
    }

    // Allow tasks to drain.
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    info!(phase = "shutdown", "fail2ban-rs stopped");
    Ok(())
}

async fn handle_control_request(
    request: Request,
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    ctx: &mut ReloadContext<'_>,
) -> Response {
    match request {
        Request::Status => Response::ok("fail2ban-rs is running"),

        Request::ListBans => {
            let (tx, rx) = tokio::sync::oneshot::channel();
            if tracker_cmd_tx
                .send(TrackerCmd::QueryBans { respond: tx })
                .await
                .is_err()
            {
                return Response::error("tracker unavailable");
            }
            match rx.await {
                Ok(bans) => {
                    let data: Vec<serde_json::Value> = bans
                        .iter()
                        .map(|b| {
                            serde_json::json!({
                                "ip": b.ip.to_string(),
                                "jail": b.jail_id,
                                "banned_at": b.banned_at,
                                "expires_at": b.expires_at,
                            })
                        })
                        .collect();
                    Response::ok_data(serde_json::json!({ "bans": data }))
                }
                Err(_) => Response::error("tracker did not respond"),
            }
        }

        Request::Ban { ip, jail } => {
            let ban_time = match resolve_ban_time(ctx.config, &jail) {
                Ok(secs) => secs,
                Err(msg) => return Response::error(msg),
            };
            let (tx, rx) = tokio::sync::oneshot::channel();
            if tracker_cmd_tx
                .send(TrackerCmd::ManualBan {
                    ip,
                    jail_id: jail.clone(),
                    ban_time,
                    respond: tx,
                })
                .await
                .is_err()
            {
                return Response::error("tracker unavailable");
            }
            match rx.await {
                Ok(Ok(())) => Response::ok(format!("banned {ip} in {jail}")),
                Ok(Err(e)) => Response::error(e.to_string()),
                Err(_) => Response::error("tracker did not respond"),
            }
        }

        Request::Unban { ip, jail } => {
            let (tx, rx) = tokio::sync::oneshot::channel();
            if tracker_cmd_tx
                .send(TrackerCmd::ManualUnban {
                    ip,
                    jail_id: jail.clone(),
                    respond: tx,
                })
                .await
                .is_err()
            {
                return Response::error("tracker unavailable");
            }
            match rx.await {
                Ok(Ok(())) => Response::ok(format!("unbanned {ip} from {jail}")),
                Ok(Err(e)) => Response::error(e.to_string()),
                Err(_) => Response::error("tracker did not respond"),
            }
        }

        Request::Reload => {
            info!(
                phase = "reload",
                trigger = "control_socket",
                "config reload starting"
            );
            match reload_config(
                ctx.config_path,
                ctx.executor_tx,
                tracker_cmd_tx,
                ctx.config,
                ctx.watcher_cancel,
                ctx.failure_tx,
                ctx.logger,
            )
            .await
            {
                Ok(()) => {
                    info!(phase = "reload", "config reload complete");
                    Response::ok("config reloaded")
                }
                Err(e) => {
                    error!(
                        phase = "reload",
                        error = %e,
                        "config reload failed"
                    );
                    Response::error(format!("reload failed: {e}"))
                }
            }
        }

        Request::Stats => {
            let (tx, rx) = tokio::sync::oneshot::channel();
            if tracker_cmd_tx
                .send(TrackerCmd::GetStats { respond: tx })
                .await
                .is_err()
            {
                return Response::error("tracker unavailable");
            }
            match rx.await {
                Ok(stats) => match serde_json::to_value(&stats) {
                    Ok(v) => Response::ok_data(v),
                    Err(e) => Response::error(format!("serialize stats: {e}")),
                },
                Err(_) => Response::error("tracker did not respond"),
            }
        }
    }
}

/// Resolve the configured ban time (seconds) for a manual ban on `jail`.
///
/// Returns an error message string when the jail is unknown or disabled, so
/// the caller can reject the request instead of applying a bogus default.
fn resolve_ban_time(config: &Config, jail: &str) -> std::result::Result<i64, String> {
    match config.jail.get(jail) {
        Some(cfg) if cfg.enabled => Ok(cfg.ban_time),
        Some(_) => Err(format!("jail '{jail}' is not enabled")),
        None => Err(format!("unknown jail '{jail}'")),
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
