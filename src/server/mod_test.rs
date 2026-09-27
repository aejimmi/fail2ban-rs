use super::*;

use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use crate::config::Config;
use crate::control::{Request, Response};
use crate::enforce::FirewallCmd;
use crate::track::TrackerCmd;

use super::control_dispatch::handle_control_request;

#[test]
fn test_status_request_response() {
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
fn test_response_ok_serialization() {
    let resp = Response::ok("running");
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains("ok"));
    assert!(json.contains("running"));
}

#[test]
fn test_response_error_serialization() {
    let resp = Response::error("something went wrong");
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains("error"));
    assert!(json.contains("something went wrong"));
}

#[test]
fn test_response_ok_data_serialization() {
    let data = serde_json::json!({ "bans": [{"ip": "1.2.3.4"}] });
    let resp = Response::ok_data(data);
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains("1.2.3.4"));
}

#[test]
fn test_stats_request_serialization() {
    let req = Request::Stats;
    let json = serde_json::to_string(&req).unwrap();
    let parsed: Request = serde_json::from_str(&json).unwrap();
    assert!(matches!(parsed, Request::Stats));
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
                TrackerCmd::UpdateConfig { jails, respond, .. } => {
                    let mut names: Vec<String> = jails.keys().cloned().collect();
                    names.sort();
                    log_clone.lock().expect("lock").push(names);
                    let _ = respond.send(());
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
async fn test_control_request_reload_swaps_config_and_dispatches_update_to_tracker() {
    let mut config = Config::parse(&jail_config_toml(7200)).expect("initial config parses");

    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("fail2ban-rs.toml");
    std::fs::write(&config_path, jail_config_toml(999)).expect("write reloaded config");

    let (tracker_cmd_tx, tracker_cmd_rx) = mpsc::channel::<TrackerCmd>(16);
    let (log, tracker_handle) = spawn_tracker_stub(tracker_cmd_rx);

    let (executor_tx, _executor_rx) = mpsc::channel::<FirewallCmd>(4);
    let (failure_tx, _failure_rx) = mpsc::channel(4);
    let mut watchers = Watchers::default();

    let mut ctx = ReloadContext {
        config_path: &config_path,
        executor_tx: &executor_tx,
        config: &mut config,
        watchers: &mut watchers,
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
    watchers.stop().await;
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
async fn test_control_request_reload_returns_error_and_leaves_config_unchanged_on_bad_file() {
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
    let mut watchers = Watchers::default();

    let mut ctx = ReloadContext {
        config_path: &config_path,
        executor_tx: &executor_tx,
        config: &mut config,
        watchers: &mut watchers,
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
