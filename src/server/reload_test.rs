use super::*;

use crate::server::reload_delta::reload_delta_test::minimal_config;
use crate::server::reload_delta::reload_forward_test::spawn_mock_executor;

#[tokio::test]
async fn test_teardown_firewalls_full_success() {
    let (tx, rx) = mpsc::channel::<FirewallCmd>(16);
    let handle = spawn_mock_executor(rx);

    let names = vec!["sshd", "nginx"];
    teardown_firewalls_full(&tx, names.into_iter(), "shutdown").await;

    drop(tx);
    let log = handle.await.unwrap();

    assert_eq!(log.len(), 2);
    assert_eq!(log[0], "teardown_full:sshd");
    assert_eq!(log[1], "teardown_full:nginx");
}

/// Shutdown teardown stops (rather than hangs or errors) once the executor is gone.
#[tokio::test]
async fn test_teardown_firewalls_full_stops_on_closed_executor() {
    let (tx, rx) = mpsc::channel::<FirewallCmd>(16);
    drop(rx);
    teardown_firewalls_full(&tx, ["sshd", "nginx"].into_iter(), "shutdown").await;
}

#[test]
fn test_build_watcher_plan_invalid_regex() {
    let mut config = minimal_config();
    // Set an invalid regex as the filter pattern.
    config.jail.get_mut("sshd").unwrap().filter = vec!["[invalid regex".to_string()];

    let result = build_watcher_plan(&config);
    assert!(
        result.is_err(),
        "invalid regex in filter should produce an error"
    );
}

/// Config TOML with one enabled `sshd` jail; `script` switches its backend.
fn sshd_toml(script: bool) -> String {
    let backend = if script {
        "[jail.sshd.backend.script]\nban_cmd = \"true\"\nunban_cmd = \"true\"\n"
    } else {
        ""
    };
    format!(
        "[global]\n\n[jail.sshd]\nenabled = true\nfilter = ['from <HOST>']\n\
         log_path = \"/var/log/auth.log\"\n{backend}"
    )
}

/// Executor stub answering `ReplaceJail` with `Ok` or a failure.
fn spawn_replace_executor(
    mut rx: mpsc::Receiver<FirewallCmd>,
    succeed: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            let FirewallCmd::ReplaceJail { done, .. } = cmd else {
                panic!("unexpected command: {cmd:?}");
            };
            let result = if succeed {
                Ok(())
            } else {
                Err(crate::error::Error::firewall("mock replace failure"))
            };
            done.send(result).unwrap();
        }
    })
}

/// Tracker stub: forwards `ForwardFirewall` commands (with no bans) to the
/// executor and records the other command kinds.
fn spawn_tracker_recorder(
    mut rx: mpsc::Receiver<TrackerCmd>,
    executor_tx: mpsc::Sender<FirewallCmd>,
) -> tokio::task::JoinHandle<Vec<String>> {
    tokio::spawn(async move {
        let mut log = Vec::new();
        while let Some(cmd) = rx.recv().await {
            match cmd {
                TrackerCmd::ForwardFirewall { build, .. } => {
                    executor_tx.send(build(Vec::new())).await.unwrap();
                }
                TrackerCmd::ReconcileJail { jail_id } => log.push(format!("reconcile:{jail_id}")),
                TrackerCmd::UpdateConfig { respond, .. } => {
                    log.push("update_config".to_string());
                    let _ = respond.send(());
                }
                _ => log.push("other".to_string()),
            }
        }
        log
    })
}

/// Run a reload from the default-backend `sshd` jail to a script backend and
/// return the reload result plus the tracker commands seen.
async fn reload_with_replacement(succeed: bool) -> (crate::error::Result<()>, Vec<String>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("fail2ban-rs.toml");
    std::fs::write(&path, sshd_toml(true)).expect("write config");
    let mut config = Config::parse(&sshd_toml(false)).expect("parse");

    let (executor_tx, executor_rx) = mpsc::channel(4);
    let executor = spawn_replace_executor(executor_rx, succeed);
    let (tracker_tx, tracker_rx) = mpsc::channel(8);
    let tracker = spawn_tracker_recorder(tracker_rx, executor_tx.clone());
    let (failure_tx, _failure_rx) = mpsc::channel(4);
    let mut watchers = Watchers::default();

    let result = reload_config(
        &path,
        &executor_tx,
        &tracker_tx,
        &mut config,
        &mut watchers,
        &failure_tx,
        None,
    )
    .await;
    watchers.stop().await;
    drop((executor_tx, tracker_tx));
    executor.await.unwrap();
    (result, tracker.await.unwrap())
}

/// M2: a committed backend replacement triggers an immediate reconcile of
/// that jail so bans issued during the replacement are not lost.
#[tokio::test]
async fn test_reload_replacement_success_requests_jail_reconcile() {
    let (result, log) = reload_with_replacement(true).await;
    result.expect("reload should succeed");
    assert_eq!(log, ["reconcile:sshd", "update_config"]);
}

/// M2: a rolled-back replacement also reconciles the jail, and the failed
/// reload never pushes the new config to the tracker.
#[tokio::test]
async fn test_reload_replacement_failure_still_requests_jail_reconcile() {
    let (result, log) = reload_with_replacement(false).await;
    let error = result.expect_err("reload must fail");
    assert!(error.to_string().contains("mock replace failure"));
    assert_eq!(log, ["reconcile:sshd"]);
}

/// `send_and_ack` maps a dropped ack (executor gave up) to `ChannelClosed`.
#[tokio::test]
async fn test_send_and_ack_dropped_ack_is_channel_closed() {
    let (tx, mut rx) = mpsc::channel::<FirewallCmd>(1);
    let handle = tokio::spawn(async move { drop(rx.recv().await) });
    let result = send_and_ack(&tx, |done| FirewallCmd::RemoveJail {
        jail_id: "sshd".to_string(),
        done,
    })
    .await;
    assert!(matches!(result, Err(crate::error::Error::ChannelClosed)));
    handle.await.unwrap();
}

/// L3: an executor that accepts the command but never acknowledges must not
/// wedge the (inline) reload — `send_and_ack` times out with an error.
#[tokio::test]
async fn test_send_and_ack_never_acked_times_out() {
    let (tx, mut rx) = mpsc::channel::<FirewallCmd>(1);
    // Hold every received command (and its ack sender) without answering.
    let handle = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Some(cmd) = rx.recv().await {
            held.push(cmd);
        }
        held.len()
    });
    let started = std::time::Instant::now();
    let result = send_and_ack(&tx, |done| FirewallCmd::RemoveJail {
        jail_id: "sshd".to_string(),
        done,
    })
    .await;
    let error = result.expect_err("an unacknowledged command must fail");
    assert!(error.to_string().contains("did not acknowledge"), "{error}");
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    drop(tx);
    assert_eq!(handle.await.unwrap(), 1);
}

/// L3: a full executor queue that never drains also hits the bound.
#[tokio::test]
async fn test_send_and_ack_full_queue_times_out() {
    let (tx, _rx) = mpsc::channel::<FirewallCmd>(1);
    let (filler, _filler_rx) = tokio::sync::oneshot::channel();
    tx.send(FirewallCmd::RemoveJail {
        jail_id: "a".to_string(),
        done: filler,
    })
    .await
    .unwrap();
    let result = send_and_ack(&tx, |done| FirewallCmd::RemoveJail {
        jail_id: "b".to_string(),
        done,
    })
    .await;
    assert!(
        result
            .expect_err("must time out")
            .to_string()
            .contains("did not acknowledge")
    );
}

#[tokio::test]
async fn test_update_tracker_config_closed_channel_is_error() {
    let (tx, rx) = mpsc::channel(1);
    drop(rx);
    let config = Config::parse(&sshd_toml(false)).expect("config");
    let result = super::update_tracker_config(&tx, &config).await;
    assert!(matches!(result, Err(crate::error::Error::ChannelClosed)));
}

#[tokio::test]
async fn test_update_tracker_config_requires_application_ack() {
    let (tx, mut rx) = mpsc::channel(1);
    let config = Config::parse(&sshd_toml(false)).expect("config");
    let waiter = tokio::spawn(async move { super::update_tracker_config(&tx, &config).await });
    let Some(TrackerCmd::UpdateConfig { respond, .. }) = rx.recv().await else {
        panic!("expected tracker update");
    };
    assert!(
        !waiter.is_finished(),
        "enqueue alone must not complete reload"
    );
    respond.send(()).expect("ack");
    assert!(waiter.await.expect("join").is_ok());
}
