use super::*;

use std::net::Ipv4Addr;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::detect::watcher::Failure;
use crate::enforce::FirewallCmd;
use crate::track::ban_calc::JailParams;
use crate::track::circular::CircularTimestamps;
use crate::track::persist::BanCount;
use crate::track::sweep::{ban_count_decayed, prune_decayed_ban_counts, prune_stale_failures};
use crate::track::test_support::{test_global_config, test_jail_config, test_store};
use crate::track::tracker_state::FailState;

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
            Err(_) => {} // timeout, try again
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
    let restored = vec![crate::track::state::BanRecord {
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
            Ok(Some(_) | None) => break,
            Err(_) => {}
        }
    }
    assert!(got_unban, "restored ban should trigger unban after expiry");

    cancel.cancel();
    handle.await.unwrap();
}

/// Regression (fix 6): failure buffers whose newest timestamp has fallen out
/// of the jail's find_time window (or whose jail is gone) get pruned.
#[test]
fn prune_stale_failures_drops_out_of_window_entries() {
    let mk_params = |find_time: i64| JailParams {
        max_retry: 3,
        find_time,
        ban_time: 60,
        webhook: None,
        bantime_increment: false,
        bantime_factor: 1.0,
        bantime_multipliers: vec![],
        bantime_maxtime: 0,
    };

    let mut jail_params = HashMap::new();
    jail_params.insert("sshd".to_string(), mk_params(600));

    let now = 10_000i64;
    let fresh_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let stale_ip = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
    let orphan_ip = IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3));

    let mut failures = HashMap::new();
    let mut fresh = CircularTimestamps::new(3);
    fresh.push(now - 100); // within window
    failures.insert(
        (fresh_ip, "sshd".to_string()),
        FailState { timestamps: fresh },
    );
    let mut stale = CircularTimestamps::new(3);
    stale.push(now - 1000); // outside 600s window
    failures.insert(
        (stale_ip, "sshd".to_string()),
        FailState { timestamps: stale },
    );
    let mut orphan = CircularTimestamps::new(3);
    orphan.push(now); // jail no longer configured
    failures.insert(
        (orphan_ip, "gone".to_string()),
        FailState { timestamps: orphan },
    );

    prune_stale_failures(&mut failures, &jail_params, now);

    assert!(failures.contains_key(&(fresh_ip, "sshd".to_string())));
    assert!(!failures.contains_key(&(stale_ip, "sshd".to_string())));
    assert!(!failures.contains_key(&(orphan_ip, "gone".to_string())));
}

#[test]
fn ban_count_decay_semantics() {
    let now = 1_000_000i64;
    let decay = 100i64;
    // Exactly at the boundary is NOT stale (strictly older required).
    assert!(!ban_count_decayed(now - decay, decay, now));
    // Older than the window is stale.
    assert!(ban_count_decayed(now - decay - 1, decay, now));
    // A fresh ban is never stale.
    assert!(!ban_count_decayed(now, decay, now));
    // decay <= 0 disables decay entirely.
    assert!(!ban_count_decayed(0, 0, now));
    assert!(!ban_count_decayed(0, -1, now));
}

#[test]
fn prune_decayed_ban_counts_drops_only_stale_entries() {
    let store = test_store();
    let now = 1_000_000i64;
    let decay = 30 * 86_400i64; // 30 days

    let fresh_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let stale_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));

    store
        .write(|tx| {
            tx.ban_counts.put(
                fresh_ip,
                BanCount {
                    count: 2,
                    last_ban: now - 10, // well within the window
                },
            );
            tx.ban_counts.put(
                stale_ip,
                BanCount {
                    count: 9,
                    last_ban: now - decay - 1, // just past the window
                },
            );
            Ok(())
        })
        .expect("seed ban_counts");

    prune_decayed_ban_counts(&store, decay, now);

    let state = store.read();
    assert!(
        state.ban_counts.contains_key(&fresh_ip),
        "a recently-banned IP's count must survive"
    );
    assert!(
        !state.ban_counts.contains_key(&stale_ip),
        "a count whose last ban predates the decay window must be reset"
    );
}

#[test]
fn prune_decayed_ban_counts_disabled_keeps_everything() {
    let store = test_store();
    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3));
    store
        .write(|tx| {
            tx.ban_counts.put(
                ip,
                BanCount {
                    count: 4,
                    last_ban: 0, // ancient
                },
            );
            Ok(())
        })
        .expect("seed");

    // decay = 0 disables decay: even an ancient count is retained.
    prune_decayed_ban_counts(&store, 0, i64::MAX);

    assert!(store.read().ban_counts.contains_key(&ip));
}
