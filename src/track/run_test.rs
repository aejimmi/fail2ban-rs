use super::*;

use std::net::Ipv4Addr;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::detect::watcher::Failure;
use crate::enforce::FirewallCmd;
use crate::track::test_support::{test_global_config, test_jail_config, test_store};

#[tokio::test]
async fn test_maxmind_asn_att() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

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
            HashMap::new(),
            test_store(),
            None,
            cancel_clone,
        )
        .await;
    });

    // Target: ASN 7018 (AT&T Services, Inc.)
    let ip: std::net::IpAddr = "71.134.65.5".parse().unwrap();
    let now = chrono::Utc::now().timestamp();

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
        .unwrap()
        .unwrap();
    assert!(matches!(cmd, FirewallCmd::Ban { .. }));

    cancel.cancel();
    handle.await.unwrap();
}

#[tokio::test]
async fn test_maxmind_country_uk_ipv6() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

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
            HashMap::new(),
            test_store(),
            None,
            cancel_clone,
        )
        .await;
    });

    // Target: United Kingdom (IPv6)
    let ip: std::net::IpAddr = "2a02:dd40:22::42".parse().unwrap();
    let now = chrono::Utc::now().timestamp();

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
        .unwrap()
        .unwrap();
    assert!(matches!(cmd, FirewallCmd::Ban { .. }));

    cancel.cancel();
    handle.await.unwrap();
}

#[tokio::test]
async fn test_maxmind_city_sweden() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

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
            HashMap::new(),
            test_store(),
            None,
            cancel_clone,
        )
        .await;
    });

    // Target: Linköping, Sweden (Validates UTF-8 handling too!)
    let ip: std::net::IpAddr = "89.160.20.142".parse().unwrap();
    let now = chrono::Utc::now().timestamp();

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
        .unwrap()
        .unwrap();
    assert!(matches!(cmd, FirewallCmd::Ban { .. }));

    cancel.cancel();
    handle.await.unwrap();
}

#[tokio::test]
async fn dropping_all_failure_senders_exits_run_loop() {
    // Hardening: when every failure sender is dropped, `failure_rx.recv()`
    // yields None and the tracker's select loop must break (and log at error!)
    // rather than spin or hang. We assert the loop exits by awaiting the task.
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), test_jail_config());

    let (failure_tx, failure_rx) = mpsc::channel::<Failure>(16);
    let (executor_tx, _executor_rx) = mpsc::channel(16);
    // Hold the command sender so only the failure channel closes.
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();

    let handle = tokio::spawn(async move {
        crate::track::run(
            test_global_config(),
            jails,
            failure_rx,
            cmd_rx,
            executor_tx,
            None,
            vec![],
            HashMap::new(),
            test_store(),
            None,
            cancel,
        )
        .await;
    });

    // Drop the only failure sender: the run loop should observe the closed
    // channel and return on its own, without cancellation.
    drop(failure_tx);

    tokio::time::timeout(std::time::Duration::from_secs(5), handle)
        .await
        .expect("tracker run loop must exit when all failure senders drop")
        .expect("tracker task panicked");
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
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {}
        }
    }
    assert!(
        got_nginx_ban,
        "same IP should be independently bannable in different jails"
    );

    cancel.cancel();
    handle.await.unwrap();
}
