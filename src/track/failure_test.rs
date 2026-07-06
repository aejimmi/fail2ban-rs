use super::*;

use std::net::Ipv4Addr;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::detect::watcher::Failure;
use crate::enforce::FirewallCmd;
use crate::track::test_support::{test_global_config, test_jail_config, test_store};

#[tokio::test]
async fn bans_after_threshold() {
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
            None,
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
async fn reban_on_restart_false_still_bans_new_offenders() {
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
            None,
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
async fn no_ban_below_threshold() {
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
            None,
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
async fn no_ban_outside_find_time() {
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
            None,
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
async fn already_banned_ip_ignored() {
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
            None,
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
async fn unknown_jail_failure_ignored() {
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
            None,
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
