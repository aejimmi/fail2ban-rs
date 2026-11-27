use super::*;

use std::net::Ipv4Addr;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::detect::watcher::Failure;
use crate::enforce::FirewallCmd;
use crate::track::test_support::{test_global_config, test_jail_config, test_store};

#[tokio::test]
async fn test_bans_after_threshold() {
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
            false,
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
                log_line: None,
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
async fn test_reban_on_restart_false_still_bans_new_offenders() {
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
            false,
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
                log_line: None,
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
async fn test_no_ban_below_threshold() {
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
            false,
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
                log_line: None,
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
async fn test_no_ban_outside_find_time() {
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
            false,
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
                log_line: None,
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
async fn test_already_banned_ip_ignored() {
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
            false,
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
                log_line: None,
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
                log_line: None,
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
async fn test_unknown_jail_failure_ignored() {
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
            false,
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
            log_line: None,
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

/// L1/L2: an automatic ban whose command cannot reach the executor (channel
/// closed) is rolled back instead of lingering as a ban the firewall never saw.
#[tokio::test]
async fn test_automatic_ban_executor_closed_rolls_back() {
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), test_jail_config());

    let (failure_tx, failure_rx) = mpsc::channel(16);
    let (executor_tx, executor_rx) = mpsc::channel(16);
    let (cmd_tx, cmd_rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    drop(executor_rx);

    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move {
        crate::track::run(
            test_global_config(),
            jails,
            failure_rx,
            cmd_rx,
            executor_tx,
            false,
            vec![],
            std::collections::HashMap::new(),
            test_store(),
            None,
            cancel_clone,
        )
        .await;
    });

    let now = chrono::Utc::now().timestamp();
    for i in 0..3 {
        failure_tx
            .send(Failure {
                ip: IpAddr::V4(Ipv4Addr::new(31, 31, 31, 31)),
                jail_id: "sshd".to_string(),
                timestamp: now + i,
                log_line: None,
            })
            .await
            .unwrap();
    }

    // Failures and commands arrive on different channels; poll until the
    // tracker has consumed all three failures.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let stats = loop {
        let (respond, rx) = tokio::sync::oneshot::channel();
        cmd_tx.send(TrackerCmd::GetStats { respond }).await.unwrap();
        let stats = rx.await.unwrap();
        if stats.total_failures == 3 || tokio::time::Instant::now() > deadline {
            break stats;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    };
    assert_eq!(stats.total_failures, 3);
    assert_eq!(
        stats.active_bans, 0,
        "undeliverable ban must be rolled back"
    );
    assert_eq!(stats.total_bans, 0);

    cancel.cancel();
    handle.await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn test_ban_logs_keep_only_the_bounded_tail_of_the_threshold_window() {
    use crate::track::failure::handle_failure;
    use crate::track::fault_support::{FaultStore, rig};
    use crate::track::state::BanLogLine;

    let store = FaultStore::open();
    let mut rig = rig(store.store());
    let params = rig.state.jail_params.get_mut("sshd").unwrap();
    params.max_retry = 17;
    params.find_time = 30;
    params.save_ban_logs = true;

    let ip: IpAddr = "192.0.2.10".parse().unwrap();
    let key = (ip, "sshd".to_string());
    let now = chrono::Utc::now().timestamp();
    let mut failure = Failure {
        ip,
        jail_id: "sshd".to_string(),
        timestamp: now - 60,
        log_line: Some(BanLogLine::capture("stale")),
    };
    handle_failure(failure.clone(), &mut rig.state).await;

    failure.timestamp = now;
    for i in 0..16 {
        failure.log_line = Some(BanLogLine::capture(&format!("failure {i}")));
        handle_failure(failure.clone(), &mut rig.state).await;
    }

    assert!(rig.state.store.read().ban_logs.is_empty());
    assert!(rig.executor_rx.try_recv().is_err());

    let long_line = format!("{}é", "x".repeat(4095));
    failure.log_line = Some(BanLogLine::capture(&long_line));
    handle_failure(failure, &mut rig.state).await;

    let state = rig.state.store.read();
    let logs = &state.ban_logs[&key];
    assert_eq!(logs.banned_at, state.bans[&key].banned_at);
    assert_eq!(logs.lines.len(), 16);
    assert_eq!(logs.lines.first().unwrap().text, "failure 1");
    let last_line = logs.lines.last().unwrap();
    assert_eq!(last_line.text, "x".repeat(4095));
    assert!(last_line.truncated);
}
