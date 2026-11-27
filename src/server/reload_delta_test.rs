use super::*;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use tokio::sync::mpsc;

use crate::config::{Config, JailConfig};
use crate::enforce::FirewallCmd;
use crate::track::state::BanRecord;

use super::reload_forward_test::{apply_with_bans, spawn_mock_executor};

/// Build a minimal `Config` with one enabled jail named `sshd`.
pub(crate) fn minimal_config() -> Config {
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), test_jail_config());
    Config {
        global: crate::config::GlobalConfig::default(),
        logging: crate::config::LoggingConfig::default(),
        jail: jails,
    }
}

/// Build a minimal `JailConfig` with a valid filter.
pub(crate) fn test_jail_config() -> JailConfig {
    JailConfig {
        enabled: true,
        log_path: "/tmp/test.log".into(),
        date_format: crate::detect::date::DateFormat::Syslog,
        filter: vec!["from <HOST>".to_string()],
        save_ban_logs: false,
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

// ---------------------------------------------------------------------------
// ipset backend delta
// ---------------------------------------------------------------------------

/// Build an ipset backend config with the given settings.
pub(crate) fn ipset_backend(maxelem: u32, chain: &str) -> crate::config::Backend {
    crate::config::Backend::Ipset {
        maxelem,
        chain: chain.to_string(),
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
    apply_with_bans(&tx, &delta, &old, &new, &bans)
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
    apply_with_bans(&tx, &delta, &old, &new, &bans)
        .await
        .unwrap();

    drop(tx);
    let log = handle.await.unwrap();
    assert!(log.contains(&"add:nginx".to_string()), "log: {log:?}");
    assert!(
        log.contains(&"add_ban:2.2.2.2:nginx".to_string()),
        "added jail's ban must be reapplied: {log:?}"
    );
    assert!(
        !log.iter().any(|c| c == "add:sshd"),
        "kept jail must not be re-added: {log:?}"
    );
    assert!(
        !log.iter()
            .any(|c| c.ends_with(":sshd") && c.contains("ban:")),
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

    apply_with_bans(&tx, &delta, &old, &new, &[]).await.unwrap();

    drop(tx);
    let log = handle.await.unwrap();
    assert_eq!(log, vec!["remove:nginx".to_string()], "log: {log:?}");
}

/// (d) A backend-TYPE change for an existing jail must use the executor's
/// transactional replacement command and seed its active bans.
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
    apply_with_bans(&tx, &delta, &old, &new, &bans)
        .await
        .unwrap();

    drop(tx);
    let log = handle.await.unwrap();
    assert_eq!(log[0], "replace:sshd", "log: {log:?}");
    assert!(
        log.contains(&"replace_ban:9.9.9.9:sshd".to_string()),
        "rebuilt jail's ban must be reapplied: {log:?}"
    );
}

/// If a later addition fails, reload must reverse an already-committed backend
/// replacement before returning the error and retaining the old config.
#[tokio::test]
async fn test_reload_delta_rolls_back_replacement_when_later_add_fails() {
    let (tx, mut rx) = mpsc::channel::<FirewallCmd>(16);
    let handle = tokio::spawn(async move {
        let mut log = Vec::new();
        while let Some(cmd) = rx.recv().await {
            match cmd {
                FirewallCmd::ReplaceJail { jail_id, done, .. } => {
                    log.push(format!("replace:{jail_id}"));
                    let _ = done.send(Ok(()));
                }
                FirewallCmd::AddJail { jail_id, done, .. } => {
                    log.push(format!("add:{jail_id}"));
                    let _ = done.send(Err(crate::error::Error::firewall("mock add failure")));
                }
                other => panic!("unexpected command: {other:?}"),
            }
        }
        log
    });

    let old = minimal_config();
    let mut new = minimal_config();
    new.jail.get_mut("sshd").unwrap().backend = crate::config::Backend::Script {
        ban_cmd: "true".to_string(),
        unban_cmd: "true".to_string(),
    };
    new.jail.insert("nginx".to_string(), test_jail_config());
    let delta = FirewallDelta::compute(&old, &new);

    let result = apply_with_bans(&tx, &delta, &old, &new, &[]).await;
    assert!(result.is_err(), "failed addition must fail reload");

    drop(tx);
    let log = handle.await.unwrap();
    assert_eq!(
        log,
        ["replace:sshd", "add:nginx", "replace:sshd"],
        "the final replacement command must restore the old backend"
    );
}

/// If reversing a committed replacement itself fails, the rollback error is
/// logged and the ORIGINAL failure (the addition) is what the reload reports;
/// the rollback still restores the old rules (`from` = new, `to` = old).
#[tokio::test]
async fn test_reload_delta_failed_replacement_rollback_reports_original_error() {
    let (tx, mut rx) = mpsc::channel::<FirewallCmd>(16);
    let handle = tokio::spawn(async move {
        let mut log = Vec::new();
        let mut replaces = 0;
        while let Some(cmd) = rx.recv().await {
            match cmd {
                FirewallCmd::ReplaceJail {
                    jail_id,
                    new_ports,
                    done,
                    ..
                } => {
                    replaces += 1;
                    log.push(format!("replace:{jail_id}:{}", new_ports.join(",")));
                    let result = if replaces == 1 {
                        Ok(())
                    } else {
                        Err(crate::error::Error::firewall("mock rollback failure"))
                    };
                    done.send(result).unwrap();
                }
                FirewallCmd::AddJail { jail_id, done, .. } => {
                    log.push(format!("add:{jail_id}"));
                    done.send(Err(crate::error::Error::firewall("mock add failure")))
                        .unwrap();
                }
                other => panic!("unexpected command: {other:?}"),
            }
        }
        log
    });

    let old = minimal_config();
    let mut new = minimal_config();
    new.jail.get_mut("sshd").unwrap().port = vec!["2222".to_string()];
    new.jail.insert("nginx".to_string(), test_jail_config());
    let delta = FirewallDelta::compute(&old, &new);

    let error = apply_with_bans(&tx, &delta, &old, &new, &[])
        .await
        .expect_err("failed addition must fail reload");
    assert!(error.to_string().contains("mock add failure"), "{error}");

    drop(tx);
    let log = handle.await.unwrap();
    assert_eq!(log, ["replace:sshd:2222", "add:nginx", "replace:sshd:22"]);
}

/// A port-only change alters every native backend's rule match, so it must
/// rebuild the jail rather than leave the old port rule installed.
#[test]
fn test_reload_delta_port_change_is_remove_then_add() {
    let old = minimal_config();
    let mut new = minimal_config();
    new.jail.get_mut("sshd").unwrap().port = vec!["2222".to_string()];

    let delta = FirewallDelta::compute(&old, &new);
    assert_eq!(delta.removed, vec!["sshd".to_string()]);
    assert_eq!(delta.added, vec!["sshd".to_string()]);
    assert!(delta.kept.is_empty());
}

/// Changing from all ports to a scoped port list also changes the rule match.
#[test]
fn test_reload_delta_empty_to_scoped_port_list_is_remove_then_add() {
    let mut old = minimal_config();
    old.jail.get_mut("sshd").unwrap().port.clear();
    let new = minimal_config();

    let delta = FirewallDelta::compute(&old, &new);
    assert_eq!(delta.removed, vec!["sshd".to_string()]);
    assert_eq!(delta.added, vec!["sshd".to_string()]);
    assert!(delta.kept.is_empty());
}

/// A protocol-only change must rebuild the rule even when its port list stays
/// the same.
#[test]
fn test_reload_delta_protocol_change_is_remove_then_add() {
    let old = minimal_config();
    let mut new = minimal_config();
    new.jail.get_mut("sshd").unwrap().protocol = "udp".to_string();

    let delta = FirewallDelta::compute(&old, &new);
    assert_eq!(delta.removed, vec!["sshd".to_string()]);
    assert_eq!(delta.added, vec!["sshd".to_string()]);
    assert!(delta.kept.is_empty());
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

    let result = apply_with_bans(&tx, &delta, &old, &new, &[]).await;
    assert!(
        matches!(result, Err(crate::error::Error::ChannelClosed)),
        "expected ChannelClosed, got: {result:?}"
    );
}

#[test]
fn test_identical_ipset_backends_do_not_differ() {
    assert!(!backend_differs(
        &ipset_backend(65_536, "INPUT"),
        &ipset_backend(65_536, "INPUT")
    ));
}

/// `ipset -exist create` only suppresses the already-exists error when every
/// create parameter matches, so a changed capacity must force a rebuild.
#[test]
fn test_changed_ipset_maxelem_differs() {
    assert!(backend_differs(
        &ipset_backend(65_536, "INPUT"),
        &ipset_backend(200_000, "INPUT")
    ));
}

#[test]
fn test_changed_ipset_chain_differs() {
    assert!(backend_differs(
        &ipset_backend(65_536, "INPUT"),
        &ipset_backend(65_536, "DOCKER-USER")
    ));
}

#[test]
fn test_ipset_differs_from_other_backend_types() {
    assert!(backend_differs(
        &ipset_backend(65_536, "INPUT"),
        &crate::config::Backend::Nftables
    ));
    assert!(backend_differs(
        &crate::config::Backend::Iptables,
        &ipset_backend(65_536, "INPUT")
    ));
}

/// A reload that only raises `maxelem` must destroy and recreate the jail's
/// sets — remove then add, never `kept`.
#[test]
fn test_reload_delta_ipset_maxelem_change_is_remove_then_add() {
    let mut old = minimal_config();
    old.jail.get_mut("sshd").unwrap().backend = ipset_backend(65_536, "INPUT");
    let mut new = minimal_config();
    new.jail.get_mut("sshd").unwrap().backend = ipset_backend(200_000, "INPUT");

    let delta = FirewallDelta::compute(&old, &new);
    assert_eq!(delta.removed, vec!["sshd".to_string()]);
    assert_eq!(delta.added, vec!["sshd".to_string()]);
    assert!(delta.kept.is_empty());
}

/// An unchanged ipset jail keeps its kernel state — no ban window on reload.
#[test]
fn test_reload_delta_unchanged_ipset_jail_is_kept() {
    let mut old = minimal_config();
    old.jail.get_mut("sshd").unwrap().backend = ipset_backend(65_536, "INPUT");
    let mut new = minimal_config();
    new.jail.get_mut("sshd").unwrap().backend = ipset_backend(65_536, "INPUT");

    let delta = FirewallDelta::compute(&old, &new);
    assert_eq!(delta.kept, vec!["sshd".to_string()]);
    assert!(delta.added.is_empty());
    assert!(delta.removed.is_empty());
}
