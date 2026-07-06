use super::*;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::control::{Request, Response};
use crate::enforce::FirewallCmd;
use crate::track::TrackerCmd;
use crate::track::persist::BanState;

fn test_config() -> Config {
    Config::parse(
        r#"
        [global]

        [jail.sshd]
        enabled = true
        filter = ['from <HOST>']
        log_path = "/var/log/auth.log"
        ban_time = 7200

        [jail.nginx]
        enabled = false
        filter = ['from <HOST>']
        log_path = "/var/log/nginx/error.log"
        ban_time = 600
        "#,
    )
    .expect("test config parses")
}

#[test]
fn resolve_ban_time_uses_jail_config() {
    let config = test_config();
    assert_eq!(resolve_ban_time(&config, "sshd"), Ok(7200));
}

#[test]
fn resolve_ban_time_unknown_jail_errors() {
    let config = test_config();
    let err = resolve_ban_time(&config, "nope").unwrap_err();
    assert!(err.contains("unknown jail"), "got: {err}");
}

#[test]
fn resolve_ban_time_disabled_jail_errors() {
    let config = test_config();
    let err = resolve_ban_time(&config, "nginx").unwrap_err();
    assert!(err.contains("not enabled"), "got: {err}");
}

#[test]
fn status_request_response() {
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

/// Spin up a real tracker task (no mock handler) and drive
/// [`handle_control_request`] directly, the way the daemon's main select
/// loop does. This is the seam that was completely untested: every other
/// control-socket test fakes the handler side, so a bug in how requests map
/// to `TrackerCmd`s (wrong variant, wrong response on error) would not have
/// been caught anywhere else.
struct RealTrackerHarness {
    tracker_cmd_tx: mpsc::Sender<TrackerCmd>,
    executor_rx: mpsc::Receiver<FirewallCmd>,
    tracker_cancel: CancellationToken,
    tracker_handle: tokio::task::JoinHandle<()>,
    // Kept alive for the harness's lifetime: dropping the failure sender
    // would close the failure channel and make the tracker's select! loop
    // exit ("failure channel closed") almost immediately.
    _failure_tx: mpsc::Sender<crate::detect::watcher::Failure>,
    _dir: tempfile::TempDir,
}

fn spawn_real_tracker(config: &Config) -> RealTrackerHarness {
    let dir = tempfile::tempdir().expect("tempdir");
    let store =
        etchdb::Store::<BanState, etchdb::WalBackend<BanState>>::open_wal(dir.path().to_path_buf())
            .expect("open WAL store");
    let store = std::sync::Arc::new(store);

    let jail_configs: HashMap<String, _> = config
        .jail
        .iter()
        .filter(|(_, j)| j.enabled)
        .map(|(name, cfg)| (name.clone(), cfg.clone()))
        .collect();

    let (failure_tx, failure_rx) = mpsc::channel(16);
    let (executor_tx, executor_rx) = mpsc::channel::<FirewallCmd>(16);
    let (tracker_cmd_tx, tracker_cmd_rx) = mpsc::channel::<TrackerCmd>(16);
    let tracker_cancel = CancellationToken::new();

    let cancel_clone = tracker_cancel.clone();
    let tracker_handle = tokio::spawn(async move {
        crate::track::run(
            crate::config::GlobalConfig::default(),
            jail_configs,
            failure_rx,
            tracker_cmd_rx,
            executor_tx,
            None,
            vec![],
            HashMap::new(),
            store,
            None,
            cancel_clone,
        )
        .await;
    });

    RealTrackerHarness {
        tracker_cmd_tx,
        executor_rx,
        tracker_cancel,
        tracker_handle,
        _failure_tx: failure_tx,
        _dir: dir,
    }
}

#[tokio::test]
async fn control_request_ban_and_unban_round_trip_through_real_tracker() {
    let mut config = test_config();
    let mut harness = spawn_real_tracker(&config);

    // A second, unused channel to satisfy ReloadContext — none of the
    // requests exercised here take the Reload path.
    let (unused_executor_tx, _unused_executor_rx) = mpsc::channel::<FirewallCmd>(4);
    let (unused_failure_tx, _unused_failure_rx) = mpsc::channel(4);
    let mut watcher_cancel = CancellationToken::new();
    let config_path = std::path::PathBuf::from("/nonexistent/fail2ban-rs-test.toml");

    let mut ctx = ReloadContext {
        config_path: &config_path,
        executor_tx: &unused_executor_tx,
        config: &mut config,
        watcher_cancel: &mut watcher_cancel,
        failure_tx: &unused_failure_tx,
        logger: None,
    };

    let ip: IpAddr = "203.0.113.42".parse().unwrap();

    // Stats before any ban: zero active bans.
    match handle_control_request(Request::Stats, &harness.tracker_cmd_tx, &mut ctx).await {
        Response::Ok { data: Some(v), .. } => {
            assert_eq!(v["active_bans"], 0, "no bans yet: {v}");
        }
        other => panic!("expected Ok stats, got {other:?}"),
    }

    // Ban through the real dispatch path.
    let response = handle_control_request(
        Request::Ban {
            ip,
            jail: "sshd".to_string(),
        },
        &harness.tracker_cmd_tx,
        &mut ctx,
    )
    .await;
    match response {
        Response::Ok { message, .. } => {
            let msg = message.expect("ban response has a message");
            assert!(msg.contains("203.0.113.42"), "got: {msg}");
            assert!(msg.contains("sshd"), "got: {msg}");
        }
        Response::Error { message } => panic!("ban should succeed, got error: {message}"),
    }

    // The real executor channel must have received the Ban command — proof
    // the request reached the tracker rather than short-circuiting.
    let cmd = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        harness.executor_rx.recv(),
    )
    .await
    .expect("timeout waiting for Ban on the executor channel")
    .expect("executor channel closed");
    match cmd {
        FirewallCmd::Ban {
            ip: banned_ip,
            jail_id,
            ..
        } => {
            assert_eq!(banned_ip, ip);
            assert_eq!(jail_id, "sshd");
        }
        other => panic!("expected FirewallCmd::Ban, got {other:?}"),
    }

    // ListBans must reflect the just-applied ban.
    match handle_control_request(Request::ListBans, &harness.tracker_cmd_tx, &mut ctx).await {
        Response::Ok { data: Some(v), .. } => {
            let bans = v["bans"].as_array().expect("bans array");
            assert_eq!(bans.len(), 1);
            assert_eq!(bans[0]["ip"], "203.0.113.42");
            assert_eq!(bans[0]["jail"], "sshd");
        }
        other => panic!("expected Ok with data, got {other:?}"),
    }

    // A second ban of the same IP/jail must be rejected (already banned).
    let dup = handle_control_request(
        Request::Ban {
            ip,
            jail: "sshd".to_string(),
        },
        &harness.tracker_cmd_tx,
        &mut ctx,
    )
    .await;
    match dup {
        Response::Error { message } => {
            assert!(message.to_lowercase().contains("banned"), "got: {message}");
        }
        Response::Ok { .. } => panic!("re-banning an already-banned ip must not succeed"),
    }

    // Unban through the real dispatch path.
    let response = handle_control_request(
        Request::Unban {
            ip,
            jail: "sshd".to_string(),
        },
        &harness.tracker_cmd_tx,
        &mut ctx,
    )
    .await;
    assert!(
        matches!(response, Response::Ok { .. }),
        "unban should succeed: {response:?}"
    );

    let cmd = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        harness.executor_rx.recv(),
    )
    .await
    .expect("timeout waiting for Unban on the executor channel")
    .expect("executor channel closed");
    assert!(
        matches!(cmd, FirewallCmd::Unban { ip: unbanned_ip, .. } if unbanned_ip == ip),
        "expected FirewallCmd::Unban for {ip}, got {cmd:?}"
    );

    // Banning an unknown jail must be rejected before it ever reaches the
    // tracker's ban logic.
    let response = handle_control_request(
        Request::Ban {
            ip,
            jail: "does-not-exist".to_string(),
        },
        &harness.tracker_cmd_tx,
        &mut ctx,
    )
    .await;
    match response {
        Response::Error { message } => assert!(message.contains("unknown jail"), "got: {message}"),
        Response::Ok { .. } => panic!("banning an unknown jail must fail"),
    }

    harness.tracker_cancel.cancel();
    harness.tracker_handle.await.unwrap();
}

#[tokio::test]
async fn control_request_reports_tracker_unavailable_once_tracker_is_gone() {
    let mut config = test_config();
    let harness = spawn_real_tracker(&config);

    // Stop the tracker and let its command channel close.
    harness.tracker_cancel.cancel();
    harness.tracker_handle.await.unwrap();

    let (unused_executor_tx, _unused_executor_rx) = mpsc::channel::<FirewallCmd>(4);
    let (unused_failure_tx, _unused_failure_rx) = mpsc::channel(4);
    let mut watcher_cancel = CancellationToken::new();
    let config_path = std::path::PathBuf::from("/nonexistent/fail2ban-rs-test.toml");
    let mut ctx = ReloadContext {
        config_path: &config_path,
        executor_tx: &unused_executor_tx,
        config: &mut config,
        watcher_cancel: &mut watcher_cancel,
        failure_tx: &unused_failure_tx,
        logger: None,
    };

    let response = handle_control_request(Request::Stats, &harness.tracker_cmd_tx, &mut ctx).await;
    match response {
        Response::Error { message } => {
            assert!(message.contains("tracker unavailable"), "got: {message}");
        }
        Response::Ok { .. } => panic!("stats must fail once the tracker task has exited"),
    }
}

/// Build TOML for a single-jail config with a distinguishing `ban_time`,
/// keeping the same jail set as `test_config()` (sshd enabled, nginx
/// disabled) so a reload against it computes an empty firewall delta (jail
/// kept, nothing added/removed) — isolating the `Request::Reload` dispatch
/// and config-swap behavior from firewall backend concerns.
fn jail_config_toml(ban_time: i64) -> String {
    format!(
        r#"
        [global]

        [jail.sshd]
        enabled = true
        filter = ['from <HOST>']
        log_path = "/var/log/auth.log"
        ban_time = {ban_time}

        [jail.nginx]
        enabled = false
        filter = ['from <HOST>']
        log_path = "/var/log/nginx/error.log"
        ban_time = 600
        "#
    )
}

/// Jail names recorded from each `TrackerCmd::UpdateConfig` seen by
/// [`spawn_tracker_stub`], in receipt order.
type UpdateConfigLog = Arc<Mutex<Vec<Vec<String>>>>;

/// Minimal stand-in for the tracker on the reload seam: answers `QueryBans`
/// with an empty list (nothing to reapply) and records every `UpdateConfig`
/// it receives — proof the reload signal actually reached this seam, without
/// needing a full real tracker task (which `reload_config` doesn't otherwise
/// exercise beyond these two commands).
fn spawn_tracker_stub(
    mut rx: mpsc::Receiver<TrackerCmd>,
) -> (UpdateConfigLog, tokio::task::JoinHandle<()>) {
    let log: UpdateConfigLog = Arc::new(Mutex::new(Vec::new()));
    let log_clone = Arc::clone(&log);
    let handle = tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                TrackerCmd::QueryBans { respond } => {
                    let _ = respond.send(Vec::new());
                }
                TrackerCmd::UpdateConfig { jails, .. } => {
                    let mut names: Vec<String> = jails.keys().cloned().collect();
                    names.sort();
                    log_clone.lock().expect("lock").push(names);
                }
                _ => {}
            }
        }
    });
    (log, handle)
}

/// The `Request::Reload` branch must re-read the config file at
/// `config_path`, swap it into the in-memory `Config`, and dispatch the
/// reloaded jail set to the tracker via `TrackerCmd::UpdateConfig` — the
/// seam that was previously completely untested.
#[tokio::test]
async fn control_request_reload_swaps_config_and_dispatches_update_to_tracker() {
    let mut config = Config::parse(&jail_config_toml(7200)).expect("initial config parses");

    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("fail2ban-rs.toml");
    std::fs::write(&config_path, jail_config_toml(999)).expect("write reloaded config");

    let (tracker_cmd_tx, tracker_cmd_rx) = mpsc::channel::<TrackerCmd>(16);
    let (log, tracker_handle) = spawn_tracker_stub(tracker_cmd_rx);

    let (executor_tx, _executor_rx) = mpsc::channel::<FirewallCmd>(4);
    let (failure_tx, _failure_rx) = mpsc::channel(4);
    let mut watcher_cancel = CancellationToken::new();

    let mut ctx = ReloadContext {
        config_path: &config_path,
        executor_tx: &executor_tx,
        config: &mut config,
        watcher_cancel: &mut watcher_cancel,
        failure_tx: &failure_tx,
        logger: None,
    };

    let response = handle_control_request(Request::Reload, &tracker_cmd_tx, &mut ctx).await;
    match response {
        Response::Ok { message, .. } => {
            assert_eq!(message, Some("config reloaded".to_string()));
        }
        Response::Error { message } => panic!("reload should succeed, got error: {message}"),
    }

    // The in-memory config must have been swapped to the reloaded file's
    // content — proof the reload actually re-read `config_path` rather than
    // just acking without doing anything.
    assert_eq!(
        config.jail.get("sshd").expect("sshd present").ban_time,
        999,
        "config must reflect the reloaded file's ban_time"
    );

    // Drop the sender and join the stub task so every message it buffered
    // (the `UpdateConfig` sent by the reload) is guaranteed to have been
    // processed before we inspect its log.
    watcher_cancel.cancel();
    drop(tracker_cmd_tx);
    tracker_handle.await.expect("tracker stub join");

    // The tracker seam (`UpdateConfig`) must have been reached with the
    // reloaded jail set.
    let log = log.lock().expect("lock");
    assert_eq!(log.len(), 1, "expected exactly one UpdateConfig: {log:?}");
    assert_eq!(log[0], vec!["sshd".to_string()]);
}

/// A `Request::Reload` whose config file cannot be read must return an
/// error response and must leave the in-memory config untouched — the error
/// must surface before the reload ever touches the tracker.
#[tokio::test]
async fn control_request_reload_returns_error_and_leaves_config_unchanged_on_bad_file() {
    let mut config = Config::parse(&jail_config_toml(7200)).expect("initial config parses");
    let config_path = std::path::PathBuf::from("/nonexistent/fail2ban-rs-reload-test.toml");

    // The receiver is dropped immediately: if reload ever tried to send on
    // this channel, the send would fail loudly rather than silently
    // succeeding into a black hole, so this also proves the failure happens
    // before the tracker is ever contacted.
    let (tracker_cmd_tx, tracker_cmd_rx) = mpsc::channel::<TrackerCmd>(4);
    drop(tracker_cmd_rx);

    let (executor_tx, _executor_rx) = mpsc::channel::<FirewallCmd>(4);
    let (failure_tx, _failure_rx) = mpsc::channel(4);
    let mut watcher_cancel = CancellationToken::new();

    let mut ctx = ReloadContext {
        config_path: &config_path,
        executor_tx: &executor_tx,
        config: &mut config,
        watcher_cancel: &mut watcher_cancel,
        failure_tx: &failure_tx,
        logger: None,
    };

    let response = handle_control_request(Request::Reload, &tracker_cmd_tx, &mut ctx).await;
    match response {
        Response::Error { message } => {
            assert!(message.contains("reload failed"), "got: {message}");
        }
        Response::Ok { .. } => panic!("reload of a nonexistent config file must fail"),
    }

    assert_eq!(
        config.jail.get("sshd").expect("sshd present").ban_time,
        7200,
        "config must be left untouched when the reload fails"
    );
}
