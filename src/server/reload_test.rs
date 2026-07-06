use super::*;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use tokio::sync::mpsc;

use crate::config::{Config, JailConfig};
use crate::enforce::FirewallCmd;
use crate::track::state::BanRecord;

/// Spawn a mock executor that auto-responds Ok(()) to InitJail,
/// TeardownJail, and Ban commands.
fn spawn_mock_executor(
    mut rx: mpsc::Receiver<FirewallCmd>,
) -> tokio::task::JoinHandle<Vec<String>> {
    tokio::spawn(async move {
        let mut log = Vec::new();
        while let Some(cmd) = rx.recv().await {
            match cmd {
                FirewallCmd::InitJail { jail_id, done, .. } => {
                    log.push(format!("init:{jail_id}"));
                    let _ = done.send(Ok(()));
                }
                FirewallCmd::TeardownJail { jail_id, done } => {
                    log.push(format!("teardown:{jail_id}"));
                    let _ = done.send(Ok(()));
                }
                FirewallCmd::TeardownJailFull { jail_id, done } => {
                    log.push(format!("teardown_full:{jail_id}"));
                    let _ = done.send(Ok(()));
                }
                FirewallCmd::AddJail { jail_id, done, .. } => {
                    log.push(format!("add:{jail_id}"));
                    let _ = done.send(Ok(()));
                }
                FirewallCmd::RemoveJail { jail_id, done } => {
                    log.push(format!("remove:{jail_id}"));
                    let _ = done.send(Ok(()));
                }
                FirewallCmd::Ban {
                    ip, jail_id, done, ..
                } => {
                    log.push(format!("ban:{ip}:{jail_id}"));
                    if let Some(done) = done {
                        let _ = done.send(Ok(()));
                    }
                }
                FirewallCmd::Unban { ip, jail_id } => {
                    log.push(format!("unban:{ip}:{jail_id}"));
                }
            }
        }
        log
    })
}

/// Build a minimal `Config` with one enabled jail named `sshd`.
fn minimal_config() -> Config {
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), test_jail_config());
    Config {
        global: crate::config::GlobalConfig::default(),
        logging: crate::config::LoggingConfig::default(),
        jail: jails,
    }
}

/// Build a minimal `JailConfig` with a valid filter.
fn test_jail_config() -> JailConfig {
    JailConfig {
        enabled: true,
        log_path: "/tmp/test.log".into(),
        date_format: crate::detect::date::DateFormat::Syslog,
        filter: vec!["from <HOST>".to_string()],
        max_retry: 3,
        find_time: 600,
        ban_time: 60,
        port: vec!["22".to_string()],
        protocol: "tcp".to_string(),
        bantime_increment: false,
        bantime_factor: 1.0,
        bantime_multipliers: vec![],
        bantime_maxtime: 604_800,
        backend: crate::config::Backend::Nftables,
        log_backend: crate::config::LogBackend::default(),
        journalmatch: vec![],
        ignoreregex: vec![],
        ignoreip: vec![],
        ignoreself: false,
        reban_on_restart: true,
        webhook: None,
        maxmind: vec![],
    }
}

/// (a) A reload with an unchanged jail must issue NO firewall commands for it:
/// no teardown, no init, and no ban reapplication — its kernel state is left
/// completely alone.
#[tokio::test]
async fn test_reload_delta_keeps_unchanged_jail_silent() {
    let (tx, rx) = mpsc::channel::<FirewallCmd>(16);
    let handle = spawn_mock_executor(rx);

    let old = minimal_config();
    let new = minimal_config();
    let delta = FirewallDelta::compute(&old, &new);
    assert_eq!(delta.kept, vec!["sshd".to_string()]);
    assert!(delta.added.is_empty());
    assert!(delta.removed.is_empty());

    // A live ban for the kept jail must NOT be reapplied.
    let bans = vec![BanRecord {
        ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        jail_id: "sshd".to_string(),
        banned_at: 1000,
        expires_at: Some(9999),
    }];
    apply_firewall_delta(&tx, &delta, &new, &bans)
        .await
        .unwrap();

    drop(tx);
    let log = handle.await.unwrap();
    assert!(
        log.is_empty(),
        "unchanged jail must issue no firewall commands: {log:?}"
    );
}

/// (b) A reload with an added jail must init that jail and reapply ONLY that
/// jail's stored bans — the kept jail's ban is left untouched.
#[tokio::test]
async fn test_reload_delta_adds_jail_and_reapplies_only_its_bans() {
    let (tx, rx) = mpsc::channel::<FirewallCmd>(16);
    let handle = spawn_mock_executor(rx);

    let old = minimal_config();
    let mut new = minimal_config();
    new.jail.insert("nginx".to_string(), test_jail_config());

    let delta = FirewallDelta::compute(&old, &new);
    assert_eq!(delta.added, vec!["nginx".to_string()]);
    assert_eq!(delta.kept, vec!["sshd".to_string()]);
    assert!(delta.removed.is_empty());

    let bans = vec![
        BanRecord {
            ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            jail_id: "sshd".to_string(),
            banned_at: 1000,
            expires_at: Some(9999),
        },
        BanRecord {
            ip: IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            jail_id: "nginx".to_string(),
            banned_at: 1000,
            expires_at: Some(9999),
        },
    ];
    apply_firewall_delta(&tx, &delta, &new, &bans)
        .await
        .unwrap();

    drop(tx);
    let log = handle.await.unwrap();
    assert!(log.contains(&"add:nginx".to_string()), "log: {log:?}");
    assert!(
        log.contains(&"ban:2.2.2.2:nginx".to_string()),
        "added jail's ban must be reapplied: {log:?}"
    );
    assert!(
        !log.iter().any(|c| c == "add:sshd"),
        "kept jail must not be re-added: {log:?}"
    );
    assert!(
        !log.iter()
            .any(|c| c.ends_with(":sshd") && c.starts_with("ban:")),
        "kept jail's ban must not be reapplied: {log:?}"
    );
}

/// (c) A reload with a removed jail must tear down ONLY that jail and issue no
/// commands for the surviving jail.
#[tokio::test]
async fn test_reload_delta_removes_only_dropped_jail() {
    let (tx, rx) = mpsc::channel::<FirewallCmd>(16);
    let handle = spawn_mock_executor(rx);

    let mut old = minimal_config();
    old.jail.insert("nginx".to_string(), test_jail_config());
    let new = minimal_config();

    let delta = FirewallDelta::compute(&old, &new);
    assert_eq!(delta.removed, vec!["nginx".to_string()]);
    assert_eq!(delta.kept, vec!["sshd".to_string()]);
    assert!(delta.added.is_empty());

    apply_firewall_delta(&tx, &delta, &new, &[]).await.unwrap();

    drop(tx);
    let log = handle.await.unwrap();
    assert_eq!(log, vec!["remove:nginx".to_string()], "log: {log:?}");
}

/// (d) A backend-TYPE change for an existing jail must be treated as remove +
/// add (torn down, then rebuilt and its bans reapplied) — never as `kept`.
#[tokio::test]
async fn test_reload_delta_backend_type_change_is_remove_then_add() {
    let (tx, rx) = mpsc::channel::<FirewallCmd>(16);
    let handle = spawn_mock_executor(rx);

    let old = minimal_config(); // sshd => nftables
    let mut new = minimal_config();
    new.jail.get_mut("sshd").unwrap().backend = crate::config::Backend::Script {
        ban_cmd: "echo ban <IP>".to_string(),
        unban_cmd: "echo unban <IP>".to_string(),
    };

    let delta = FirewallDelta::compute(&old, &new);
    assert_eq!(delta.removed, vec!["sshd".to_string()]);
    assert_eq!(delta.added, vec!["sshd".to_string()]);
    assert!(delta.kept.is_empty());

    let bans = vec![BanRecord {
        ip: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
        jail_id: "sshd".to_string(),
        banned_at: 1000,
        expires_at: Some(9999),
    }];
    apply_firewall_delta(&tx, &delta, &new, &bans)
        .await
        .unwrap();

    drop(tx);
    let log = handle.await.unwrap();
    let remove_idx = log.iter().position(|c| c == "remove:sshd");
    let add_idx = log.iter().position(|c| c == "add:sshd");
    assert!(
        remove_idx.is_some() && add_idx.is_some() && remove_idx < add_idx,
        "backend type change must remove before add: {log:?}"
    );
    assert!(
        log.contains(&"ban:9.9.9.9:sshd".to_string()),
        "rebuilt jail's ban must be reapplied: {log:?}"
    );
}

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

/// A reload with a channel-closed executor surfaces the error while adding a
/// jail rather than silently succeeding.
#[tokio::test]
async fn test_add_jail_fails_on_channel_closed() {
    let (tx, rx) = mpsc::channel::<FirewallCmd>(16);
    drop(rx); // close the channel

    let old = minimal_config();
    let mut new = minimal_config();
    new.jail.insert("nginx".to_string(), test_jail_config());
    let delta = FirewallDelta::compute(&old, &new);

    let result = apply_firewall_delta(&tx, &delta, &new, &[]).await;
    assert!(
        matches!(result, Err(crate::error::Error::ChannelClosed)),
        "expected ChannelClosed, got: {result:?}"
    );
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
