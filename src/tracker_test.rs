//! Tests for the tracker module.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use etchdb::Store;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::ban_state::BanState;
use crate::config::JailConfig;
use crate::executor::FirewallCmd;
use crate::tracker::{self, TrackerCmd};
use crate::watcher::Failure;

fn test_jail_config() -> JailConfig {
    JailConfig {
        enabled: true,
        log_path: "/tmp/test.log".into(),
        date_format: crate::date::DateFormat::Syslog,
        filter: vec!["from <HOST>".to_string()],
        max_retry: 3,
        find_time: 600,
        ban_time: 60,
        port: vec![],
        protocol: "tcp".to_string(),
        bantime_increment: false,
        bantime_factor: 1.0,
        bantime_multipliers: vec![],
        bantime_maxtime: 604800,
        backend: crate::config::Backend::Nftables,
        log_backend: crate::config::LogBackend::default(),
        journalmatch: vec![],
        ignoreregex: vec![],
        ignoreip: vec![],
        ignoreself: false,
        webhook: None,
    }
}

fn test_store() -> Arc<Store<BanState, etchdb::WalBackend<BanState>>> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    std::mem::forget(dir); // keep the tempdir alive
    let store = Store::<BanState, etchdb::WalBackend<BanState>>::open_wal(path).unwrap();
    Arc::new(store)
}

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
        tracker::run(
            jails,
            failure_rx,
            cmd_rx,
            executor_tx,
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
async fn no_ban_below_threshold() {
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), test_jail_config());

    let (failure_tx, failure_rx) = mpsc::channel(16);
    let (executor_tx, mut executor_rx) = mpsc::channel(16);
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();

    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move {
        tracker::run(
            jails,
            failure_rx,
            cmd_rx,
            executor_tx,
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
        tracker::run(
            jails,
            failure_rx,
            cmd_rx,
            executor_tx,
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
        tracker::run(
            jails,
            failure_rx,
            cmd_rx,
            executor_tx,
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
        tracker::run(
            jails,
            failure_rx,
            cmd_rx,
            executor_tx,
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

#[tokio::test]
async fn unban_timer_fires() {
    let mut jail = test_jail_config();
    jail.ban_time = 1; // 1 second ban
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), jail);

    let (failure_tx, failure_rx) = mpsc::channel(64);
    let (executor_tx, mut executor_rx) = mpsc::channel(64);
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();

    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move {
        tracker::run(
            jails,
            failure_rx,
            cmd_rx,
            executor_tx,
            vec![],
            std::collections::HashMap::new(),
            test_store(),
            None,
            cancel_clone,
        )
        .await;
    });

    let ip = IpAddr::V4(Ipv4Addr::new(40, 40, 40, 40));
    let now = chrono::Utc::now().timestamp();

    // Trigger ban.
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

    // Receive Ban.
    let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), executor_rx.recv())
        .await
        .expect("timeout waiting for ban")
        .expect("channel closed");
    assert!(matches!(cmd, FirewallCmd::Ban { .. }));

    // Wait for unban timer (1 second ban + some buffer).
    let mut got_unban = false;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(std::time::Duration::from_millis(500), executor_rx.recv()).await
        {
            Ok(Some(FirewallCmd::Unban {
                ip: unban_ip,
                jail_id,
            })) => {
                assert_eq!(unban_ip, ip);
                assert_eq!(jail_id, "sshd");
                got_unban = true;
                break;
            }
            Ok(Some(other)) => panic!("unexpected command: {other:?}"),
            Ok(None) => break,
            Err(_) => continue, // timeout, try again
        }
    }
    assert!(
        got_unban,
        "should have received Unban after ban_time expired"
    );

    cancel.cancel();
    handle.await.unwrap();
}

#[tokio::test]
async fn restored_bans_populate_unban_queue() {
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), test_jail_config());

    let now = chrono::Utc::now().timestamp();
    let restored = vec![crate::state::BanRecord {
        ip: IpAddr::V4(Ipv4Addr::new(50, 50, 50, 50)),
        jail_id: "sshd".to_string(),
        banned_at: now - 10,
        expires_at: Some(now + 1), // expires in 1 second
    }];

    let (_failure_tx, failure_rx) = mpsc::channel(16);
    let (executor_tx, mut executor_rx) = mpsc::channel(64);
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();

    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move {
        tracker::run(
            jails,
            failure_rx,
            cmd_rx,
            executor_tx,
            restored,
            std::collections::HashMap::new(),
            test_store(),
            None,
            cancel_clone,
        )
        .await;
    });

    // The restored ban should expire after ~1 second.
    let mut got_unban = false;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(4);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(std::time::Duration::from_millis(500), executor_rx.recv()).await
        {
            Ok(Some(FirewallCmd::Unban { ip, .. })) => {
                assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(50, 50, 50, 50)));
                got_unban = true;
                break;
            }
            Ok(Some(_)) | Ok(None) => break,
            Err(_) => continue,
        }
    }
    assert!(got_unban, "restored ban should trigger unban after expiry");

    cancel.cancel();
    handle.await.unwrap();
}

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
        tracker::run(
            jails,
            failure_rx,
            cmd_rx,
            executor_tx,
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
    let restored = vec![crate::state::BanRecord {
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
        tracker::run(
            jails,
            failure_rx,
            cmd_rx,
            executor_tx,
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
    let restored = vec![crate::state::BanRecord {
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
        tracker::run(
            jails,
            failure_rx,
            cmd_rx,
            executor_tx,
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
    let restored = vec![crate::state::BanRecord {
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
        tracker::run(
            jails,
            failure_rx,
            cmd_rx,
            executor_tx,
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
        tracker::run(
            jails,
            failure_rx,
            cmd_rx,
            executor_tx,
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
async fn same_ip_different_jails_tracked_independently() {
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), test_jail_config());
    let mut nginx = test_jail_config();
    nginx.filter = vec!["client: <HOST>".to_string()];
    jails.insert("nginx".to_string(), nginx);

    let (failure_tx, failure_rx) = mpsc::channel(64);
    let (executor_tx, mut executor_rx) = mpsc::channel(64);
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();

    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move {
        tracker::run(
            jails,
            failure_rx,
            cmd_rx,
            executor_tx,
            vec![],
            std::collections::HashMap::new(),
            test_store(),
            None,
            cancel_clone,
        )
        .await;
    });

    let ip = IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10));
    let now = chrono::Utc::now().timestamp();

    // Trigger ban in sshd (3 failures = max_retry).
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

    // Should receive Ban for sshd.
    let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), executor_rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");
    match &cmd {
        FirewallCmd::Ban { jail_id, .. } => assert_eq!(jail_id, "sshd"),
        other => panic!("expected Ban for sshd, got: {other:?}"),
    }

    // Same IP, trigger ban in nginx (3 more failures).
    for i in 0..3 {
        failure_tx
            .send(Failure {
                ip,
                jail_id: "nginx".to_string(),
                timestamp: now + 10 + i,
            })
            .await
            .unwrap();
    }

    // Should receive Ban for nginx (same IP, different jail).
    let mut got_nginx_ban = false;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(std::time::Duration::from_millis(200), executor_rx.recv()).await
        {
            Ok(Some(FirewallCmd::Ban { jail_id, .. })) if jail_id == "nginx" => {
                got_nginx_ban = true;
                break;
            }
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    assert!(
        got_nginx_ban,
        "same IP should be independently bannable in different jails"
    );

    cancel.cancel();
    handle.await.unwrap();
}
