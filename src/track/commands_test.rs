use super::*;

use std::net::Ipv4Addr;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::detect::watcher::Failure;
use crate::enforce::FirewallCmd;
use crate::track::test_support::{test_global_config, test_jail_config, test_store};

#[tokio::test]
async fn manual_ban_via_cmd() {
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), test_jail_config());

    let (_failure_tx, failure_rx) = mpsc::channel(16);
    let (executor_tx, mut executor_rx) = mpsc::channel(16);
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

    let ip = IpAddr::V4(Ipv4Addr::new(60, 60, 60, 60));
    let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrackerCmd::ManualBan {
            ip,
            jail_id: "sshd".to_string(),
            ban_time: 3600,
            respond: respond_tx,
        })
        .await
        .unwrap();

    let result = respond_rx.await.unwrap();
    assert!(result.is_ok());

    // Should receive Ban command.
    let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), executor_rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");
    assert!(matches!(cmd, FirewallCmd::Ban { .. }));

    cancel.cancel();
    handle.await.unwrap();
}

#[tokio::test]
async fn manual_ban_already_banned_error() {
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), test_jail_config());

    let ip = IpAddr::V4(Ipv4Addr::new(70, 70, 70, 70));
    let now = chrono::Utc::now().timestamp();
    let restored = vec![crate::track::state::BanRecord {
        ip,
        jail_id: "sshd".to_string(),
        banned_at: now,
        expires_at: Some(now + 3600),
    }];

    let (_failure_tx, failure_rx) = mpsc::channel(16);
    let (executor_tx, _executor_rx) = mpsc::channel(16);
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
            restored,
            std::collections::HashMap::new(),
            test_store(),
            None,
            cancel_clone,
        )
        .await;
    });

    let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrackerCmd::ManualBan {
            ip,
            jail_id: "sshd".to_string(),
            ban_time: 3600,
            respond: respond_tx,
        })
        .await
        .unwrap();

    let result = respond_rx.await.unwrap();
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("already banned"));

    cancel.cancel();
    handle.await.unwrap();
}

#[tokio::test]
async fn manual_unban_via_cmd() {
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), test_jail_config());

    let ip = IpAddr::V4(Ipv4Addr::new(80, 80, 80, 80));
    let now = chrono::Utc::now().timestamp();
    let restored = vec![crate::track::state::BanRecord {
        ip,
        jail_id: "sshd".to_string(),
        banned_at: now,
        expires_at: Some(now + 3600),
    }];

    let (_failure_tx, failure_rx) = mpsc::channel(16);
    let (executor_tx, mut executor_rx) = mpsc::channel(16);
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
            restored,
            std::collections::HashMap::new(),
            test_store(),
            None,
            cancel_clone,
        )
        .await;
    });

    let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrackerCmd::ManualUnban {
            ip,
            jail_id: "sshd".to_string(),
            respond: respond_tx,
        })
        .await
        .unwrap();

    let result = respond_rx.await.unwrap();
    assert!(result.is_ok());

    // Should receive Unban command.
    let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), executor_rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");
    assert!(matches!(cmd, FirewallCmd::Unban { .. }));

    cancel.cancel();
    handle.await.unwrap();
}

#[tokio::test]
async fn query_bans_via_cmd() {
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), test_jail_config());

    let ip = IpAddr::V4(Ipv4Addr::new(90, 90, 90, 90));
    let now = chrono::Utc::now().timestamp();
    let restored = vec![crate::track::state::BanRecord {
        ip,
        jail_id: "sshd".to_string(),
        banned_at: now,
        expires_at: Some(now + 3600),
    }];

    let (_failure_tx, failure_rx) = mpsc::channel(16);
    let (executor_tx, _executor_rx) = mpsc::channel(16);
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
            restored,
            std::collections::HashMap::new(),
            test_store(),
            None,
            cancel_clone,
        )
        .await;
    });

    let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrackerCmd::QueryBans {
            respond: respond_tx,
        })
        .await
        .unwrap();

    let bans = respond_rx.await.unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].ip, ip);

    cancel.cancel();
    handle.await.unwrap();
}

#[tokio::test]
async fn get_stats_via_cmd() {
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), test_jail_config());

    let (failure_tx, failure_rx) = mpsc::channel(16);
    let (executor_tx, _executor_rx) = mpsc::channel(16);
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

    // Send some failures first.
    let ip = IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100));
    let now = chrono::Utc::now().timestamp();
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
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrackerCmd::GetStats {
            respond: respond_tx,
        })
        .await
        .unwrap();

    let stats = respond_rx.await.unwrap();
    assert_eq!(stats.total_failures, 2);
    assert_eq!(stats.active_bans, 0);
    assert!(stats.jails.contains_key("sshd"));
    assert_eq!(stats.jails["sshd"].total_failures, 2);

    cancel.cancel();
    handle.await.unwrap();
}

#[tokio::test]
async fn test_manual_ban_unknown_jail_returns_error() {
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), test_jail_config());

    let (_failure_tx, failure_rx) = mpsc::channel(16);
    let (executor_tx, _executor_rx) = mpsc::channel(16);
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

    let ip = IpAddr::V4(Ipv4Addr::new(110, 110, 110, 110));
    let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrackerCmd::ManualBan {
            ip,
            jail_id: "nonexistent_jail".to_string(),
            ban_time: 3600,
            respond: respond_tx,
        })
        .await
        .unwrap();

    let result = respond_rx.await.unwrap();
    assert!(result.is_err(), "unknown jail should return an error");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("unknown jail"),
        "error should mention unknown jail, got: {err_msg}"
    );

    cancel.cancel();
    handle.await.unwrap();
}

#[tokio::test]
async fn test_manual_unban_unknown_jail_returns_error() {
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), test_jail_config());

    let (_failure_tx, failure_rx) = mpsc::channel(16);
    let (executor_tx, _executor_rx) = mpsc::channel(16);
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

    let ip = IpAddr::V4(Ipv4Addr::new(111, 111, 111, 111));
    let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrackerCmd::ManualUnban {
            ip,
            jail_id: "nonexistent_jail".to_string(),
            respond: respond_tx,
        })
        .await
        .unwrap();

    let result = respond_rx.await.unwrap();
    assert!(result.is_err(), "unknown jail should return an error");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("unknown jail"),
        "error should mention unknown jail, got: {err_msg}"
    );

    cancel.cancel();
    handle.await.unwrap();
}

#[tokio::test]
async fn test_manual_unban_not_banned_returns_error() {
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), test_jail_config());

    // No restored bans — IP is not currently banned.
    let (_failure_tx, failure_rx) = mpsc::channel(16);
    let (executor_tx, _executor_rx) = mpsc::channel(16);
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

    let ip = IpAddr::V4(Ipv4Addr::new(112, 112, 112, 112));
    let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrackerCmd::ManualUnban {
            ip,
            jail_id: "sshd".to_string(),
            respond: respond_tx,
        })
        .await
        .unwrap();

    let result = respond_rx.await.unwrap();
    assert!(
        result.is_err(),
        "unbanning a non-banned IP should return an error"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not banned"),
        "error should mention not banned, got: {err_msg}"
    );

    cancel.cancel();
    handle.await.unwrap();
}
