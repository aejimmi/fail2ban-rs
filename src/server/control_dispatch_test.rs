use super::*;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::server::watchers::Watchers;

use crate::enforce::{FirewallBackend, FirewallCmd};
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

struct FailingBanBackend;

#[async_trait::async_trait]
impl FirewallBackend for FailingBanBackend {
    async fn init(
        &self,
        _jail: &str,
        _ports: &[String],
        _protocol: &str,
    ) -> crate::error::Result<()> {
        Ok(())
    }

    async fn teardown(&self, _jail: &str) -> crate::error::Result<()> {
        Ok(())
    }

    async fn ban(&self, _ip: &IpAddr, _jail: &str) -> crate::error::Result<()> {
        Err(crate::error::Error::firewall("mock ban failure"))
    }

    async fn unban(&self, _ip: &IpAddr, _jail: &str) -> crate::error::Result<()> {
        Ok(())
    }

    async fn is_banned(&self, _ip: &IpAddr, _jail: &str) -> crate::error::Result<bool> {
        Ok(false)
    }

    fn name(&self) -> &'static str {
        "failing-ban"
    }
}

#[test]
fn test_resolve_ban_time_uses_jail_config() {
    let config = test_config();
    assert_eq!(resolve_ban_time(&config, "sshd"), Ok(7200));
}

#[test]
fn test_resolve_ban_time_unknown_jail_errors() {
    let config = test_config();
    let err = resolve_ban_time(&config, "nope").unwrap_err();
    assert!(err.contains("unknown jail"), "got: {err}");
}

#[test]
fn test_resolve_ban_time_disabled_jail_errors() {
    let config = test_config();
    let err = resolve_ban_time(&config, "nginx").unwrap_err();
    assert!(err.contains("not enabled"), "got: {err}");
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
            false,
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
async fn test_control_request_ban_and_unban_round_trip_through_real_tracker() {
    let mut config = test_config();
    let mut harness = spawn_real_tracker(&config);

    // A second, unused channel to satisfy ReloadContext — none of the
    // requests exercised here take the Reload path.
    let (unused_executor_tx, _unused_executor_rx) = mpsc::channel::<FirewallCmd>(4);
    let (unused_failure_tx, _unused_failure_rx) = mpsc::channel(4);
    let mut watchers = Watchers::default();
    let config_path = std::path::PathBuf::from("/nonexistent/fail2ban-rs-test.toml");

    let mut ctx = ReloadContext {
        config_path: &config_path,
        executor_tx: &unused_executor_tx,
        config: &mut config,
        watchers: &mut watchers,
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
    let response_fut = handle_control_request(
        Request::Ban {
            ip,
            jail: "sshd".to_string(),
        },
        &harness.tracker_cmd_tx,
        &mut ctx,
    );
    let backend_fut = async {
        let cmd = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            harness.executor_rx.recv(),
        )
        .await
        .expect("timeout waiting for Ban on the executor channel")
        .expect("executor channel closed");
        let FirewallCmd::Ban {
            ip: banned_ip,
            jail_id,
            done: Some(done),
            ..
        } = cmd
        else {
            panic!("expected acknowledged FirewallCmd::Ban, got {cmd:?}");
        };
        assert_eq!(banned_ip, ip);
        assert_eq!(jail_id, "sshd");
        done.send(Ok(())).expect("tracker dropped backend result");
    };
    let (response, ()) = tokio::join!(response_fut, backend_fut);
    match response {
        Response::Ok { message, .. } => {
            let msg = message.expect("ban response has a message");
            assert!(msg.contains("203.0.113.42"), "got: {msg}");
            assert!(msg.contains("sshd"), "got: {msg}");
        }
        Response::Error { message } => panic!("ban should succeed, got error: {message}"),
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
    let response_fut = handle_control_request(
        Request::Unban {
            ip,
            jail: "sshd".to_string(),
        },
        &harness.tracker_cmd_tx,
        &mut ctx,
    );
    let backend_fut = async {
        let cmd = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            harness.executor_rx.recv(),
        )
        .await
        .expect("timeout waiting for Unban on the executor channel")
        .expect("executor channel closed");
        let FirewallCmd::Unban {
            ip: unbanned_ip,
            done: Some(done),
            ..
        } = cmd
        else {
            panic!("expected acknowledged Unban for {ip}, got {cmd:?}");
        };
        assert_eq!(unbanned_ip, ip);
        done.send(Ok(())).expect("unban ack");
    };
    let (response, ()) = tokio::join!(response_fut, backend_fut);
    assert!(
        matches!(response, Response::Ok { .. }),
        "unban should succeed: {response:?}"
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
async fn test_control_request_reports_backend_ban_failure_after_tracker_rollback() {
    let mut config = test_config();
    let dir = tempfile::tempdir().expect("tempdir");
    let store =
        etchdb::Store::<BanState, etchdb::WalBackend<BanState>>::open_wal(dir.path().to_path_buf())
            .expect("open WAL store");
    let store = Arc::new(store);
    let jail_configs: HashMap<String, _> = config
        .jail
        .iter()
        .filter(|(_, jail)| jail.enabled)
        .map(|(name, jail)| (name.clone(), jail.clone()))
        .collect();

    let (failure_tx, failure_rx) = mpsc::channel(16);
    let (executor_tx, executor_rx) = mpsc::channel(16);
    let (tracker_cmd_tx, tracker_cmd_rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();

    let tracker_cancel = cancel.child_token();
    let tracker_store = Arc::clone(&store);
    let tracker_handle = tokio::spawn(async move {
        crate::track::run(
            crate::config::GlobalConfig::default(),
            jail_configs,
            failure_rx,
            tracker_cmd_rx,
            executor_tx,
            true,
            vec![],
            HashMap::new(),
            tracker_store,
            None,
            tracker_cancel,
        )
        .await;
    });

    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert("sshd".to_string(), Box::new(FailingBanBackend));
    let executor_cancel = cancel.child_token();
    let executor_tracker_tx = tracker_cmd_tx.clone();
    let executor_handle = tokio::spawn(async move {
        crate::enforce::run(executor_rx, backends, executor_tracker_tx, executor_cancel).await;
    });

    let (unused_executor_tx, _unused_executor_rx) = mpsc::channel::<FirewallCmd>(4);
    let (unused_failure_tx, _unused_failure_rx) = mpsc::channel(4);
    let mut watchers = Watchers::default();
    let config_path = std::path::PathBuf::from("/nonexistent/fail2ban-rs-test.toml");
    let mut ctx = ReloadContext {
        config_path: &config_path,
        executor_tx: &unused_executor_tx,
        config: &mut config,
        watchers: &mut watchers,
        failure_tx: &unused_failure_tx,
        logger: None,
    };
    let ip = "203.0.113.99".parse().unwrap();

    let response = handle_control_request(
        Request::Ban {
            ip,
            jail: "sshd".to_string(),
        },
        &tracker_cmd_tx,
        &mut ctx,
    )
    .await;
    match response {
        Response::Error { message } => {
            assert!(message.contains("mock ban failure"), "got: {message}");
        }
        Response::Ok { .. } => panic!("failed backend ban must not report success"),
    }

    match handle_control_request(Request::ListBans, &tracker_cmd_tx, &mut ctx).await {
        Response::Ok {
            data: Some(data), ..
        } => {
            assert_eq!(data["bans"].as_array().unwrap().len(), 0);
        }
        other => panic!("expected empty ban list after rollback, got {other:?}"),
    }
    match handle_control_request(Request::Stats, &tracker_cmd_tx, &mut ctx).await {
        Response::Ok {
            data: Some(data), ..
        } => {
            assert_eq!(data["active_bans"], 0);
            assert_eq!(data["total_bans"], 0);
        }
        other => panic!("expected rolled-back stats, got {other:?}"),
    }

    cancel.cancel();
    drop(failure_tx);
    tracker_handle.await.unwrap();
    executor_handle.await.unwrap();
}

#[tokio::test]
async fn test_control_request_reports_tracker_unavailable_once_tracker_is_gone() {
    let mut config = test_config();
    let harness = spawn_real_tracker(&config);

    // Stop the tracker and let its command channel close.
    harness.tracker_cancel.cancel();
    harness.tracker_handle.await.unwrap();

    let (unused_executor_tx, _unused_executor_rx) = mpsc::channel::<FirewallCmd>(4);
    let (unused_failure_tx, _unused_failure_rx) = mpsc::channel(4);
    let mut watchers = Watchers::default();
    let config_path = std::path::PathBuf::from("/nonexistent/fail2ban-rs-test.toml");
    let mut ctx = ReloadContext {
        config_path: &config_path,
        executor_tx: &unused_executor_tx,
        config: &mut config,
        watchers: &mut watchers,
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

/// H1: the main loop's dispatch must return without waiting for a tracker
/// that has not answered (e.g. a manual ban pending on a slow firewall); the
/// reply is delivered later by the spawned task.
#[tokio::test]
async fn test_dispatch_control_ban_does_not_block_main_loop() {
    let mut config = test_config();
    let (tracker_cmd_tx, mut tracker_cmd_rx) = mpsc::channel::<TrackerCmd>(4);
    let (executor_tx, _executor_rx) = mpsc::channel::<FirewallCmd>(4);
    let (failure_tx, _failure_rx) = mpsc::channel(4);
    let mut watchers = Watchers::default();
    let config_path = std::path::PathBuf::from("/nonexistent/fail2ban-rs-test.toml");
    let mut ctx = ReloadContext {
        config_path: &config_path,
        executor_tx: &executor_tx,
        config: &mut config,
        watchers: &mut watchers,
        failure_tx: &failure_tx,
        logger: None,
    };

    let (respond, mut response_rx) = tokio::sync::oneshot::channel();
    let ctrl = ControlCmd {
        request: Request::Ban {
            ip: "203.0.113.7".parse().unwrap(),
            jail: "sshd".to_string(),
        },
        respond,
    };
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        dispatch_control(ctrl, &tracker_cmd_tx, &mut ctx),
    )
    .await
    .expect("dispatch must not wait for the tracker's answer");
    assert!(response_rx.try_recv().is_err(), "no answer yet");

    let Some(TrackerCmd::ManualBan { respond, .. }) = tracker_cmd_rx.recv().await else {
        panic!("expected ManualBan");
    };
    respond.send(Ok(())).unwrap();
    match response_rx.await.unwrap() {
        Response::Ok { message, .. } => assert!(message.unwrap().contains("banned")),
        Response::Error { message } => panic!("unexpected error: {message}"),
    }
}

/// Requests rejected up front (disabled jail) never reach the tracker.
#[test]
fn test_classify_request_rejects_disabled_jail_immediately() {
    let config = test_config();
    let request = Request::Ban {
        ip: "203.0.113.8".parse().unwrap(),
        jail: "nginx".to_string(),
    };
    match classify_request(request, &config) {
        Dispatch::Immediate(Response::Error { message }) => {
            assert!(message.contains("not enabled"), "{message}");
        }
        _ => panic!("expected an immediate error"),
    }
}
