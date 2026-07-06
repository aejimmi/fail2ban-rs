use super::*;

use std::net::Ipv4Addr;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::detect::watcher::Failure;
use crate::enforce::FirewallCmd;
use crate::track::test_support::{
    expect_ban, manual_ban, manual_unban, test_global_config, test_jail_config, test_store,
};

/// Regression (fix 1): after an unban the failure buffer must be empty, so a
/// previously-banned IP has to reach the full `max_retry` threshold again.
#[tokio::test]
async fn reban_requires_full_threshold_after_unban() {
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), test_jail_config()); // max_retry = 3

    let (failure_tx, failure_rx) = mpsc::channel(64);
    let (executor_tx, mut executor_rx) = mpsc::channel(64);
    let (cmd_tx, cmd_rx) = mpsc::channel(16);
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

    let ip = IpAddr::V4(Ipv4Addr::new(21, 21, 21, 21));
    let now = chrono::Utc::now().timestamp();

    // First ban: 3 failures reach the threshold.
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
        .expect("timeout")
        .expect("closed");
    assert!(matches!(cmd, FirewallCmd::Ban { .. }));

    // Manual unban.
    let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrackerCmd::ManualUnban {
            ip,
            jail_id: "sshd".to_string(),
            respond: respond_tx,
        })
        .await
        .unwrap();
    assert!(respond_rx.await.unwrap().is_ok());
    let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), executor_rx.recv())
        .await
        .expect("timeout")
        .expect("closed");
    assert!(matches!(cmd, FirewallCmd::Unban { .. }));

    // Two fresh failures (< max_retry): buffer was cleared, so no re-ban.
    for i in 0..2 {
        failure_tx
            .send(Failure {
                ip,
                jail_id: "sshd".to_string(),
                timestamp: now + 10 + i,
            })
            .await
            .unwrap();
    }
    let result =
        tokio::time::timeout(std::time::Duration::from_millis(300), executor_rx.recv()).await;
    assert!(
        result.is_err(),
        "stale failures must not trigger an instant re-ban"
    );

    // The third fresh failure reaches the threshold again → re-ban.
    failure_tx
        .send(Failure {
            ip,
            jail_id: "sshd".to_string(),
            timestamp: now + 12,
        })
        .await
        .unwrap();
    let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), executor_rx.recv())
        .await
        .expect("timeout")
        .expect("closed");
    assert!(matches!(cmd, FirewallCmd::Ban { .. }));

    cancel.cancel();
    handle.await.unwrap();
}

/// Regression (fix 2): a manual unban followed by a re-ban must keep the new
/// expiry — no obsolete schedule may prematurely unban the fresh ban.
#[tokio::test]
async fn reban_keeps_new_expiry_no_premature_unban() {
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), test_jail_config());

    let (_failure_tx, failure_rx) = mpsc::channel(16);
    let (executor_tx, mut executor_rx) = mpsc::channel(64);
    let (cmd_tx, cmd_rx) = mpsc::channel(16);
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

    let ip = IpAddr::V4(Ipv4Addr::new(22, 22, 22, 22));

    // Short ban, then immediate unban.
    manual_ban(&cmd_tx, ip, 2).await;
    expect_ban(&mut executor_rx).await;
    manual_unban(&cmd_tx, ip).await;
    let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), executor_rx.recv())
        .await
        .expect("timeout")
        .expect("closed");
    assert!(matches!(cmd, FirewallCmd::Unban { .. }));

    // Re-ban with a long expiry.
    manual_ban(&cmd_tx, ip, 3600).await;
    expect_ban(&mut executor_rx).await;

    // Wait past the old 2s schedule: the fresh ban must still stand.
    let result = tokio::time::timeout(std::time::Duration::from_secs(3), executor_rx.recv()).await;
    assert!(
        result.is_err(),
        "obsolete schedule must not unban the re-banned IP"
    );

    cancel.cancel();
    handle.await.unwrap();
}

/// Regression (fixes 3 + escalation): the persisted ban count survives across
/// ban/unban cycles, so successive bans escalate their duration.
#[tokio::test]
async fn ban_count_escalates_across_bans() {
    let mut jail = test_jail_config();
    jail.ban_time = 10;
    jail.bantime_increment = true;
    jail.bantime_maxtime = 0; // no cap
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), jail);

    let (failure_tx, failure_rx) = mpsc::channel(64);
    let (executor_tx, mut executor_rx) = mpsc::channel(64);
    let (cmd_tx, cmd_rx) = mpsc::channel(16);
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

    let ip = IpAddr::V4(Ipv4Addr::new(23, 23, 23, 23));
    let now = chrono::Utc::now().timestamp();

    // Cycle 1: count 0 → 10 * 2^0 = 10s.
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
    assert_eq!(expect_ban(&mut executor_rx).await, 10);

    manual_unban(&cmd_tx, ip).await;
    let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), executor_rx.recv())
        .await
        .expect("timeout")
        .expect("closed");
    assert!(matches!(cmd, FirewallCmd::Unban { .. }));

    // Cycle 2: count 1 → 10 * 2^1 = 20s.
    for i in 0..3 {
        failure_tx
            .send(Failure {
                ip,
                jail_id: "sshd".to_string(),
                timestamp: now + 100 + i,
            })
            .await
            .unwrap();
    }
    assert_eq!(expect_ban(&mut executor_rx).await, 20);

    cancel.cancel();
    handle.await.unwrap();
}

/// (a) An automatic ban whose firewall apply fails must be rolled back:
/// the store no longer contains the ban and `banned_keys` is clean, so a
/// subsequent round of failures can re-trigger a ban.
#[tokio::test]
async fn ban_apply_failed_rolls_back_and_allows_retry() {
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), test_jail_config()); // max_retry = 3

    let (failure_tx, failure_rx) = mpsc::channel(64);
    let (executor_tx, mut executor_rx) = mpsc::channel(64);
    let (cmd_tx, cmd_rx) = mpsc::channel(16);
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

    let ip = IpAddr::V4(Ipv4Addr::new(24, 24, 24, 24));
    let now = chrono::Utc::now().timestamp();

    // First ban: 3 failures reach the threshold; the test plays the role of
    // the executor and drains the resulting Ban command.
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
        .expect("timeout")
        .expect("closed");
    assert!(matches!(cmd, FirewallCmd::Ban { .. }));

    // Simulate the executor reporting that the firewall apply failed.
    cmd_tx
        .send(TrackerCmd::BanApplyFailed {
            ip,
            jail_id: "sshd".to_string(),
        })
        .await
        .unwrap();

    // Rollback is ordered before this QueryBans (same FIFO channel): the
    // store must now be empty.
    let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrackerCmd::QueryBans {
            respond: respond_tx,
        })
        .await
        .unwrap();
    let bans = respond_rx.await.unwrap();
    assert!(bans.is_empty(), "rolled-back ban must not remain: {bans:?}");

    // banned_keys is clean: three fresh failures re-trigger a ban.
    for i in 0..3 {
        failure_tx
            .send(Failure {
                ip,
                jail_id: "sshd".to_string(),
                timestamp: now + 100 + i,
            })
            .await
            .unwrap();
    }
    let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), executor_rx.recv())
        .await
        .expect("timeout — re-ban after rollback")
        .expect("closed");
    assert!(matches!(cmd, FirewallCmd::Ban { .. }));

    cancel.cancel();
    handle.await.unwrap();
}
