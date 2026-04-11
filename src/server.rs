//! Daemon lifecycle — spawns all tasks, handles signals and config reload.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use etchdb::{FlushPolicy, Store};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::config::Config;
use crate::control::{self, ControlCmd, Request, Response};
use crate::detect::date::DateParser;
use crate::detect::ignore::IgnoreList;
use crate::detect::matcher::JailMatcher;
use crate::detect::watcher::Failure;
use crate::enforce::{self, FirewallCmd};
use crate::logging::Logger;
use crate::track::TrackerCmd;
use crate::track::persist::BanState;

/// Run the daemon with the given configuration.
pub async fn run(config: Config, config_path: PathBuf) -> crate::error::Result<()> {
    let cancel = CancellationToken::new();

    // Initialize remote logging (no-op if not configured).
    let logger = Logger::init(&config.logging);

    // Migrate: if state_dir points to an old state.bin file, move it aside.
    if config.global.state_dir.is_file() {
        let backup = config.global.state_dir.with_extension("bin.bak");
        info!(
            old = %config.global.state_dir.display(),
            backup = %backup.display(),
            "migrating old state file out of the way for etch store"
        );
        std::fs::rename(&config.global.state_dir, &backup).map_err(|e| {
            crate::error::Error::io(
                format!(
                    "renaming old state file: {}",
                    config.global.state_dir.display()
                ),
                e,
            )
        })?;
    }

    // Open etch store for persistent ban state.
    let mut store =
        Store::<BanState, etchdb::WalBackend<BanState>>::open_wal(config.global.state_dir.clone())
            .map_err(crate::error::Error::Etch)?;
    store.set_flush_policy(FlushPolicy::Grouped {
        interval: Duration::from_millis(100),
    });
    let store = Arc::new(store);

    // Read restored state from etch, purging any expired bans.
    let now = chrono::Utc::now().timestamp();
    let (restored_bans, restored_ban_counts) = {
        let state = store.read();

        // Collect expired ban keys to purge from the store.
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
        let counts: HashMap<std::net::IpAddr, u32> = state.ban_counts.clone();
        drop(state);

        // Remove expired bans from the store.
        if !expired_keys.is_empty() {
            info!(
                count = expired_keys.len(),
                "purging expired bans from store"
            );
            let _ = store.write(|tx| {
                for key in &expired_keys {
                    tx.bans.delete(key);
                }
                Ok(())
            });
        }

        if bans.is_empty() {
            info!("no persisted state found");
        } else {
            info!(bans = bans.len(), "loaded persisted state");
        }
        (bans, counts)
    };

    // Create channels.
    let (failure_tx, failure_rx) = mpsc::channel::<Failure>(config.global.channel_size);
    let (executor_tx, executor_rx) = mpsc::channel::<FirewallCmd>(config.global.channel_size);
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

    // Restore bans in the firewall (directly via backends, before executor owns them).
    let now = chrono::Utc::now().timestamp();
    let active_bans = enforce::restore_bans(&restored_bans, &backends, now, &jail_configs).await;
    info!(restored = active_bans.len(), "bans restored in firewall");

    // Spawn executor (must be running before we send init commands).
    let executor_cancel = cancel.child_token();
    tokio::spawn(async move {
        enforce::run(executor_rx, backends, executor_cancel).await;
    });

    // Initialize firewall rules for each jail and await confirmation.
    for (name, jail) in config.enabled_jails() {
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let cmd = enforce::FirewallCmd::InitJail {
            jail_id: name.to_string(),
            ports: jail.port.clone(),
            protocol: jail.protocol.clone(),
            done: done_tx,
        };
        if executor_tx.send(cmd).await.is_err() {
            tracing::warn!(jail = %name, "failed to send init command");
            continue;
        }
        match done_rx.await {
            Ok(Ok(())) => info!(jail = %name, "firewall initialized"),
            Ok(Err(e)) => error!(jail = %name, error = %e, "firewall init failed"),
            Err(_) => tracing::warn!(jail = %name, "executor dropped init response"),
        }
    }

    // Log startup event.
    if let Some(t) = logger.as_ref() {
        let jail_count = config.enabled_jails().count();
        t.log_startup(jail_count, active_bans.len());
    }

    // Spawn watchers with their own cancellation token (for reload).
    let mut watcher_cancel = CancellationToken::new();
    spawn_watchers(&config, &failure_tx, &watcher_cancel)?;

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

    info!("fail2ban-rs daemon started");

    // Keep a mutable reference to config path and failure_tx for reloads.
    let failure_tx_for_reload = failure_tx;

    // Main select loop.
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("received SIGINT, shutting down");
                // Tear down firewall rules for each jail and await confirmation.
                for (name, _) in config.enabled_jails() {
                    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
                    let cmd = enforce::FirewallCmd::TeardownJail {
                        jail_id: name.to_string(),
                        done: done_tx,
                    };
                    if executor_tx.send(cmd).await.is_err() {
                        break;
                    }
                    match done_rx.await {
                        Ok(Ok(())) => info!(jail = %name, "firewall torn down"),
                        Ok(Err(e)) => tracing::warn!(jail = %name, error = %e, "teardown failed"),
                        Err(_) => break,
                    }
                }
                cancel.cancel();
                watcher_cancel.cancel();
                break;
            }

            () = signal_sighup() => {
                info!("received SIGHUP, reloading config");
                match reload_config(
                    &config_path,
                    &mut watcher_cancel,
                    &failure_tx_for_reload,
                    &tracker_cmd_tx,
                    logger.as_ref(),
                ).await {
                    Ok(()) => info!("config reload complete"),
                    Err(e) => error!(error = %e, "config reload failed, keeping old config"),
                }
            }

            cmd = control_rx.recv() => {
                if let Some(ctrl) = cmd {
                    let response = handle_control_request(
                        ctrl.request,
                        &tracker_cmd_tx,
                        &config_path,
                        &mut watcher_cancel,
                        &failure_tx_for_reload,
                        logger.as_ref(),
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
    info!("fail2ban-rs stopped");
    Ok(())
}

fn spawn_watchers(
    config: &Config,
    failure_tx: &mpsc::Sender<Failure>,
    cancel: &CancellationToken,
) -> crate::error::Result<()> {
    for (name, jail) in config.enabled_jails() {
        let matcher = if jail.ignoreregex.is_empty() {
            JailMatcher::new(&jail.filter)?
        } else {
            JailMatcher::with_ignoreregex(&jail.filter, &jail.ignoreregex)?
        };
        let date_parser = DateParser::new(jail.date_format)?;
        let ignore_list = IgnoreList::new(&jail.ignoreip, jail.ignoreself)?;

        let tx = failure_tx.clone();
        let cancel = cancel.child_token();
        let name = name.to_string();

        if jail.log_backend == crate::config::LogBackend::Systemd {
            let journalmatch = jail.journalmatch.clone();
            tokio::spawn(async move {
                crate::detect::journal::run(
                    name,
                    journalmatch,
                    matcher,
                    date_parser,
                    ignore_list,
                    tx,
                    cancel,
                )
                .await;
            });
            continue;
        }

        let log_path = jail.log_path.clone();
        tokio::spawn(async move {
            crate::detect::watcher::run(
                name,
                log_path,
                matcher,
                date_parser,
                ignore_list,
                tx,
                cancel,
            )
            .await;
        });
    }
    Ok(())
}

async fn reload_config(
    config_path: &std::path::Path,
    watcher_cancel: &mut CancellationToken,
    failure_tx: &mpsc::Sender<Failure>,
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    logger: Option<&Logger>,
) -> crate::error::Result<()> {
    // Parse and validate new config.
    let new_config = Config::from_file(config_path)?;

    // Cancel old watchers.
    watcher_cancel.cancel();
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Spawn new watchers with fresh token.
    let new_cancel = CancellationToken::new();
    spawn_watchers(&new_config, failure_tx, &new_cancel)?;
    *watcher_cancel = new_cancel;

    // Update tracker jail configs.
    let jail_configs: HashMap<String, _> = new_config
        .jail
        .iter()
        .filter(|(_, j)| j.enabled)
        .map(|(name, cfg)| (name.clone(), cfg.clone()))
        .collect();
    let jail_count = jail_configs.len();

    let _ = tracker_cmd_tx
        .send(TrackerCmd::UpdateConfig {
            global: new_config.global.clone(),
            jails: jail_configs,
        })
        .await;

    if let Some(t) = logger {
        t.log_reload(jail_count);
    }

    Ok(())
}

async fn handle_control_request(
    request: Request,
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    config_path: &std::path::Path,
    watcher_cancel: &mut CancellationToken,
    failure_tx: &mpsc::Sender<Failure>,
    logger: Option<&Logger>,
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
            let (tx, rx) = tokio::sync::oneshot::channel();
            if tracker_cmd_tx
                .send(TrackerCmd::ManualBan {
                    ip,
                    jail_id: jail.clone(),
                    ban_time: 3600, // default 1 hour for manual bans
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
            match reload_config(
                config_path,
                watcher_cancel,
                failure_tx,
                tracker_cmd_tx,
                logger,
            )
            .await
            {
                Ok(()) => Response::ok("config reloaded"),
                Err(e) => Response::error(format!("reload failed: {e}")),
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

#[cfg(unix)]
async fn signal_sighup() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut stream = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "failed to register SIGHUP handler");
            std::future::pending::<()>().await;
            return;
        }
    };
    stream.recv().await;
}

#[cfg(not(unix))]
async fn signal_sighup() {
    std::future::pending::<()>().await;
}

#[cfg(test)]
mod tests {
    use crate::control::{Request, Response};

    #[test]
    fn status_request_response() {
        // Verify that serde roundtrip works for all request types.
        let requests = vec![
            Request::Status,
            Request::ListBans,
            Request::Ban {
                ip: "1.2.3.4".parse().unwrap(),
                jail: "sshd".to_string(),
            },
            Request::Unban {
                ip: "10.0.0.1".parse().unwrap(),
                jail: "nginx".to_string(),
            },
            Request::Reload,
            Request::Stats,
        ];

        for req in requests {
            let json = serde_json::to_string(&req).unwrap();
            let _parsed: Request = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn response_ok_serialization() {
        let resp = Response::ok("running");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("ok"));
        assert!(json.contains("running"));
    }

    #[test]
    fn response_error_serialization() {
        let resp = Response::error("something went wrong");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("error"));
        assert!(json.contains("something went wrong"));
    }

    #[test]
    fn response_ok_data_serialization() {
        let data = serde_json::json!({ "bans": [{"ip": "1.2.3.4"}] });
        let resp = Response::ok_data(data);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("1.2.3.4"));
    }

    #[test]
    fn stats_request_serialization() {
        let req = Request::Stats;
        let json = serde_json::to_string(&req).unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Request::Stats));
    }
}
