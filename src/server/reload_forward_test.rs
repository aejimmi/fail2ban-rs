//! Reload steps routed through the tracker: ban-seed ordering (C1) and
//! rollback of unacknowledged steps (C5).

use super::*;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use super::reload_delta_test::{minimal_config, test_jail_config};
use crate::config::{Backend, Config};
use crate::enforce::FirewallCmd;
use crate::track::TrackerCmd;
use crate::track::persist::BanState;
use crate::track::state::BanRecord;

/// Spawn a mock executor that auto-responds Ok(()) to InitJail,
/// TeardownJail, and Ban commands.
pub(crate) fn spawn_mock_executor(
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
                FirewallCmd::AddJail {
                    jail_id,
                    active_bans,
                    done,
                    ..
                } => {
                    log.push(format!("add:{jail_id}"));
                    for ban in active_bans {
                        log.push(format!("add_ban:{}:{}", ban.ip, ban.jail_id));
                    }
                    let _ = done.send(Ok(()));
                }
                FirewallCmd::ReplaceJail {
                    jail_id,
                    active_bans,
                    done,
                    ..
                } => {
                    log.push(format!("replace:{jail_id}"));
                    for ban in active_bans {
                        log.push(format!("replace_ban:{}:{}", ban.ip, ban.jail_id));
                    }
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
                FirewallCmd::Unban { ip, jail_id, done } => {
                    log.push(format!("unban:{ip}:{jail_id}"));
                    if let Some(done) = done {
                        let _ = done.send(Ok(()));
                    }
                }
                FirewallCmd::Reconcile { bans } => log.push(format!("reconcile:{}", bans.len())),
            }
        }
        log
    })
}

/// Tracker stub: answers `ForwardFirewall` by seeding the command with the
/// matching entries of `bans` and forwarding it to `executor_tx`.
pub(crate) fn spawn_forwarding_tracker(
    executor_tx: mpsc::Sender<FirewallCmd>,
    bans: Vec<BanRecord>,
) -> mpsc::Sender<TrackerCmd> {
    let (tx, mut rx) = mpsc::channel::<TrackerCmd>(16);
    tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            let TrackerCmd::ForwardFirewall { jail_id, build } = cmd else {
                continue;
            };
            let seed = bans.iter().filter(|b| b.jail_id == jail_id).cloned();
            if executor_tx.send(build(seed.collect())).await.is_err() {
                return;
            }
        }
    });
    tx
}

/// Apply a delta with a forwarding tracker stub that knows `bans`.
pub(crate) async fn apply_with_bans(
    executor_tx: &mpsc::Sender<FirewallCmd>,
    delta: &FirewallDelta,
    old: &Config,
    new: &Config,
    bans: &[BanRecord],
) -> Result<()> {
    let tracker_tx = spawn_forwarding_tracker(executor_tx.clone(), bans.to_vec());
    apply_firewall_delta(executor_tx, &tracker_tx, delta, old, new).await
}

/// Executor stub that never acknowledges the first reload command (holding
/// its ack so it is not dropped) and acks everything after it.
fn spawn_first_unacked_executor(
    mut rx: mpsc::Receiver<FirewallCmd>,
) -> tokio::task::JoinHandle<Vec<String>> {
    tokio::spawn(async move {
        let (mut log, mut held) = (Vec::new(), Vec::new());
        while let Some(cmd) = rx.recv().await {
            let (entry, done) = match cmd {
                FirewallCmd::ReplaceJail {
                    jail_id,
                    new_ports,
                    done,
                    ..
                } => (format!("replace:{jail_id}:{}", new_ports.join(",")), done),
                FirewallCmd::AddJail { jail_id, done, .. } => (format!("add:{jail_id}"), done),
                FirewallCmd::RemoveJail { jail_id, done } => (format!("remove:{jail_id}"), done),
                other => panic!("unexpected command: {other:?}"),
            };
            log.push(entry);
            if log.len() == 1 {
                held.push(done);
            } else {
                done.send(Ok(())).unwrap();
            }
        }
        log
    })
}

/// C5: a replacement whose ack times out may still run, so it is rolled
/// back (after it, on the same ordered path) like a committed one.
#[tokio::test]
async fn test_reload_delta_timed_out_replacement_is_rolled_back() {
    let (tx, rx) = mpsc::channel::<FirewallCmd>(16);
    let handle = spawn_first_unacked_executor(rx);
    let old = minimal_config();
    let mut new = minimal_config();
    new.jail.get_mut("sshd").unwrap().port = vec!["2222".to_string()];
    let delta = FirewallDelta::compute(&old, &new);

    let error = apply_with_bans(&tx, &delta, &old, &new, &[])
        .await
        .expect_err("an unacknowledged replacement must fail the reload");
    assert!(error.to_string().contains("did not acknowledge"), "{error}");
    drop(tx);
    assert_eq!(
        handle.await.unwrap(),
        ["replace:sshd:2222", "replace:sshd:22"]
    );
}

/// C5: an addition whose ack times out is removed again on rollback.
#[tokio::test]
async fn test_reload_delta_timed_out_addition_is_rolled_back() {
    let (tx, rx) = mpsc::channel::<FirewallCmd>(16);
    let handle = spawn_first_unacked_executor(rx);
    let old = minimal_config();
    let mut new = minimal_config();
    new.jail.insert("nginx".to_string(), test_jail_config());
    let delta = FirewallDelta::compute(&old, &new);

    assert!(apply_with_bans(&tx, &delta, &old, &new, &[]).await.is_err());
    drop(tx);
    assert_eq!(handle.await.unwrap(), ["add:nginx", "remove:nginx"]);
}

/// In-memory firewall: per-jail banned sets, updated in command order.
type Sets = HashMap<String, HashSet<IpAddr>>;

/// Executor stub modelling kernel state. On the first `ReplaceJail` it
/// reports the jail on `first_tx` and waits for `go_rx` before acking.
fn spawn_stateful_executor(
    mut rx: mpsc::Receiver<FirewallCmd>,
    first_tx: mpsc::Sender<String>,
    mut go_rx: mpsc::Receiver<()>,
) -> tokio::task::JoinHandle<Sets> {
    tokio::spawn(async move {
        let mut sets = Sets::new();
        let mut first = true;
        while let Some(cmd) = rx.recv().await {
            match cmd {
                FirewallCmd::ReplaceJail {
                    jail_id,
                    active_bans,
                    done,
                    ..
                } => {
                    sets.insert(jail_id.clone(), active_bans.iter().map(|b| b.ip).collect());
                    if std::mem::take(&mut first) {
                        first_tx.send(jail_id).await.unwrap();
                        go_rx.recv().await.unwrap();
                    }
                    done.send(Ok(())).unwrap();
                }
                FirewallCmd::Unban { ip, jail_id, done } => {
                    sets.entry(jail_id).or_default().remove(&ip);
                    if let Some(done) = done {
                        let _ = done.send(Ok(()));
                    }
                }
                FirewallCmd::Ban { ip, jail_id, .. } => {
                    sets.entry(jail_id).or_default().insert(ip);
                }
                FirewallCmd::Reconcile { .. } => {}
                other => panic!("unexpected command: {other:?}"),
            }
        }
        sets
    })
}

/// Two jails `a`, `b`; `script` switches both to a script backend.
fn two_jail_config(script: bool) -> Config {
    let mut config = minimal_config();
    config.jail.clear();
    for name in ["a", "b"] {
        let mut jail = test_jail_config();
        if script {
            jail.backend = Backend::Script {
                ban_cmd: "true".to_string(),
                unban_cmd: "true".to_string(),
            };
        }
        config.jail.insert(name.to_string(), jail);
    }
    config
}

/// Spawn a real tracker holding `bans`, wired to `executor_tx`. Returns its
/// command sender and the failure sender (which must outlive the test).
fn spawn_real_tracker(
    config: &Config,
    executor_tx: mpsc::Sender<FirewallCmd>,
    bans: Vec<BanRecord>,
    dir: &std::path::Path,
    cancel: CancellationToken,
) -> (
    mpsc::Sender<TrackerCmd>,
    mpsc::Sender<crate::detect::watcher::Failure>,
) {
    let store = etchdb::Store::<BanState, etchdb::WalBackend<BanState>>::open_wal(dir.into())
        .expect("open WAL store");
    let (cmd_tx, cmd_rx) = mpsc::channel(16);
    let (failure_tx, failure_rx) = mpsc::channel(16);
    let jails: HashMap<_, _> = config.jail.clone().into_iter().collect();
    tokio::spawn(crate::track::run(
        config.global.clone(),
        jails,
        failure_rx,
        cmd_rx,
        executor_tx,
        false,
        bans,
        HashMap::new(),
        Arc::new(store),
        None,
        cancel,
    ));
    (cmd_tx, failure_tx)
}

/// C1: an IP unbanned while an earlier reload step is in flight must not be
/// re-banned by a later replacement seeded from a stale ban snapshot.
#[tokio::test]
async fn test_reload_unban_during_reload_is_not_rebanned() {
    let dir = tempfile::tempdir().unwrap();
    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
    let now = chrono::Utc::now().timestamp();
    let ban = |jail: &str| BanRecord {
        ip,
        jail_id: jail.to_string(),
        banned_at: now,
        expires_at: Some(now + 3600),
    };
    let (old, new) = (two_jail_config(false), two_jail_config(true));
    let (executor_tx, executor_rx) = mpsc::channel(16);
    let (first_tx, mut first_rx) = mpsc::channel(1);
    let (go_tx, go_rx) = mpsc::channel(1);
    let executor = spawn_stateful_executor(executor_rx, first_tx, go_rx);
    let cancel = CancellationToken::new();
    let bans = vec![ban("a"), ban("b")];
    let (tracker_tx, _failure_tx) =
        spawn_real_tracker(&old, executor_tx.clone(), bans, dir.path(), cancel.clone());

    let (reload_exec, reload_tracker) = (executor_tx.clone(), tracker_tx.clone());
    let reload = tokio::spawn(async move {
        let delta = FirewallDelta::compute(&old, &new);
        apply_firewall_delta(&reload_exec, &reload_tracker, &delta, &old, &new).await
    });

    // While the first replacement is in flight, unban the IP in the other jail.
    let first = first_rx.recv().await.unwrap();
    let other = if first == "a" { "b" } else { "a" };
    let (respond, unbanned) = oneshot::channel();
    let unban = TrackerCmd::ManualUnban {
        ip,
        jail_id: other.to_string(),
        respond,
    };
    tracker_tx.send(unban).await.unwrap();
    go_tx.send(()).await.unwrap();
    unbanned.await.unwrap().expect("manual unban");

    reload.await.unwrap().expect("reload");
    cancel.cancel();
    drop((executor_tx, tracker_tx));
    let sets = executor.await.unwrap();
    assert!(sets[&first].contains(&ip), "untouched ban must be seeded");
    assert!(
        !sets[other].contains(&ip),
        "unbanned IP was re-banned by a stale snapshot: {sets:?}"
    );
}
