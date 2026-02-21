//! End-to-end test: write log lines → detect failures → trigger ban.
//!
//! Uses a mock firewall backend (script backend with `true` command)
//! to avoid requiring root permissions.

use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};

use tempfile::NamedTempFile;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use fail2ban_rs::circular::CircularTimestamps;
use fail2ban_rs::config::JailConfig;
use fail2ban_rs::date::{DateFormat, DateParser};
use fail2ban_rs::executor::FirewallCmd;
use fail2ban_rs::ignore::IgnoreList;
use fail2ban_rs::matcher::JailMatcher;
use fail2ban_rs::state::{self, BanRecord, StateSnapshot};
use fail2ban_rs::tracker::{self, TrackerCmd};
use fail2ban_rs::watcher::{self, Failure};

/// Full pipeline: watcher → tracker → verify ban command.
#[tokio::test]
async fn watcher_to_tracker_ban() {
    let mut tmpfile = NamedTempFile::new().unwrap();
    let log_path = tmpfile.path().to_path_buf();

    // Channels.
    let (failure_tx, failure_rx) = mpsc::channel::<Failure>(64);
    let (executor_tx, mut executor_rx) = mpsc::channel::<FirewallCmd>(64);
    let cancel = CancellationToken::new();

    // Jail config: ban after 3 failures in 600s.
    let jail_config = JailConfig {
        enabled: true,
        log_path: log_path.clone(),
        date_format: DateFormat::Syslog,
        filter: vec![r"sshd\[\d+\]: Failed password for .* from <HOST>".to_string()],
        max_retry: 3,
        find_time: 600,
        ban_time: 60,
        port: vec![],
        protocol: "tcp".to_string(),
        bantime_increment: false,
        bantime_factor: 1.0,
        bantime_multipliers: vec![],
        bantime_maxtime: 604800,
        backend: fail2ban_rs::config::Backend::Nftables,
        log_backend: fail2ban_rs::config::LogBackend::default(),
        journalmatch: vec![],
        ignoreregex: vec![],
        ignoreip: vec![],
        ignoreself: false,
        webhook: None,
    };

    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), jail_config.clone());

    // Spawn tracker.
    let (_cmd_tx, cmd_rx) = mpsc::channel::<TrackerCmd>(16);
    let tracker_cancel = cancel.child_token();
    tokio::spawn(async move {
        tracker::run(
            jails,
            failure_rx,
            cmd_rx,
            executor_tx,
            vec![],
            std::collections::HashMap::new(),
            None,
            tracker_cancel,
        )
        .await;
    });

    // Spawn watcher.
    let matcher = JailMatcher::new(&jail_config.filter).unwrap();
    let date_parser = DateParser::new(DateFormat::Syslog).unwrap();
    let ignore_list = IgnoreList::new(&[], false).unwrap();
    let watcher_cancel = cancel.child_token();

    tokio::spawn(async move {
        watcher::run(
            "sshd".to_string(),
            log_path,
            matcher,
            date_parser,
            ignore_list,
            failure_tx,
            watcher_cancel,
        )
        .await;
    });

    // Give watcher time to start.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Write 3 failure lines (enough to trigger ban).
    for i in 1..=3 {
        writeln!(
            tmpfile,
            "Jan 15 10:30:0{i} server sshd[123{i}]: Failed password for root from 192.168.1.100 port 22 ssh2"
        )
        .unwrap();
    }
    tmpfile.flush().unwrap();

    // Wait for ban command.
    let cmd = tokio::time::timeout(std::time::Duration::from_secs(5), executor_rx.recv())
        .await
        .expect("timeout waiting for ban command")
        .expect("channel closed");

    match cmd {
        FirewallCmd::Ban { ip, jail_id, .. } => {
            assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
            assert_eq!(jail_id, "sshd");
        }
        other => panic!("expected Ban command, got: {other:?}"),
    }

    cancel.cancel();
}

/// State persistence roundtrip.
#[test]
fn state_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.bin");

    let snapshot = StateSnapshot {
        bans: vec![BanRecord {
            ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            jail_id: "sshd".to_string(),
            banned_at: 1000,
            expires_at: Some(2000),
        }],
        ban_counts: vec![],
        snapshot_time: 1500,
    };

    state::save(&path, &snapshot).unwrap();
    let loaded = state::load(&path).unwrap().unwrap();
    assert_eq!(loaded.bans.len(), 1);
    assert_eq!(loaded.bans[0].ip, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
}

/// Circular buffer threshold check.
#[test]
fn circular_threshold() {
    let mut buf = CircularTimestamps::new(5);
    for i in 0..5 {
        buf.push(1000 + i * 10);
    }
    assert!(buf.threshold_reached(600));
    assert!(!buf.threshold_reached(30));
}

/// Matcher extracts correct IP from SSH log.
#[test]
fn matcher_ssh_log() {
    let matcher = JailMatcher::new(&[
        r"sshd\[\d+\]: Failed password for .* from <HOST>".to_string(),
        r"sshd\[\d+\]: Invalid user .* from <HOST>".to_string(),
    ])
    .unwrap();

    let line = "Jan 15 10:30:01 server sshd[1235]: Failed password for root from 192.168.1.100 port 22 ssh2";
    let result = matcher.try_match(line).unwrap();
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
    assert_eq!(result.pattern_idx, 0);

    let line2 =
        "Jan 15 10:30:05 server sshd[1238]: Invalid user admin from 10.20.30.40 port 22 ssh2";
    let result2 = matcher.try_match(line2).unwrap();
    assert_eq!(result2.ip, IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)));
    assert_eq!(result2.pattern_idx, 1);
}
