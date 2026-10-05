//! Ban persistence failures against the real WAL store (fault injected by
//! making the open state directory read-only; see `fault_support`).

use super::*;

use std::net::Ipv4Addr;

use crate::detect::watcher::Failure;
use crate::error::Error;
use crate::track::commands::handle_cmd;
use crate::track::execute::record_ban;
use crate::track::failure::handle_failure;
use crate::track::fault_support::{FaultStore, Rig, rig};

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

fn key() -> (IpAddr, String) {
    (IP, "sshd".to_string())
}

fn failure(ts: i64) -> Failure {
    Failure {
        ip: IP,
        jail_id: "sshd".to_string(),
        timestamp: ts,
    }
}

fn manual_ban_cmd(respond: oneshot::Sender<crate::error::Result<()>>) -> TrackerCmd {
    TrackerCmd::ManualBan {
        ip: IP,
        jail_id: "sshd".to_string(),
        ban_time: 60,
        respond,
    }
}

/// Assert the tracker holds no trace of a ban for `IP`.
fn assert_no_ban_state(r: &mut Rig) {
    assert!(!r.state.index.banned_keys.contains(&key()));
    assert_eq!(r.state.counters.total_bans, 0);
    assert!(r.state.counters.jail_bans.is_empty());
    assert!(r.state.pending_manual.by_key.is_empty());
    assert!(
        r.executor_rx.try_recv().is_err(),
        "no firewall command may be sent when the ban was not persisted"
    );
}

#[tokio::test]
async fn test_auto_ban_store_write_failure_skips_index_counters_and_firewall() {
    let fs = FaultStore::open();
    let mut r = rig(fs.store());
    if !fs.inject() {
        eprintln!("skipped: running as root, cannot make the state dir unwritable");
        return;
    }
    let now = chrono::Utc::now().timestamp();
    handle_failure(failure(now), &mut r.state).await;
    handle_failure(failure(now + 1), &mut r.state).await;

    assert_no_ban_state(&mut r);
    assert_eq!(r.state.counters.total_failures, 2);
    // The failure buffer is retained so the next failure retries the ban.
    assert_eq!(
        r.state.failures.get(&key()).map(|f| f.timestamps.len()),
        Some(2)
    );
}

#[tokio::test]
async fn test_auto_ban_failure_comes_from_the_store() {
    let fs = FaultStore::open();
    let mut r = rig(fs.store());
    if !fs.inject() {
        eprintln!("skipped: running as root, cannot make the state dir unwritable");
        return;
    }
    let err = record_ban(IP, "sshd", 60, Some(1), &mut r.state).unwrap_err();
    let Error::Persistence { message } = err else {
        panic!("expected persistence error, got: {err:?}");
    };
    assert!(message.starts_with("recording ban:"), "{message}");
    assert_no_ban_state(&mut r);
}

#[tokio::test]
async fn test_auto_ban_retries_after_store_recovers() {
    let fs = FaultStore::open();
    let mut r = rig(fs.store());
    if !fs.inject() {
        eprintln!("skipped: running as root, cannot make the state dir unwritable");
        return;
    }
    let now = chrono::Utc::now().timestamp();
    handle_failure(failure(now), &mut r.state).await;
    handle_failure(failure(now + 1), &mut r.state).await;
    assert_no_ban_state(&mut r);

    fs.heal();
    // One more failure is enough only because the buffer survived.
    handle_failure(failure(now + 2), &mut r.state).await;
    assert!(r.state.index.banned_keys.contains(&key()));
    assert_eq!(r.state.counters.total_bans, 1);
    assert!(!r.state.failures.contains_key(&key()));
    let cmd = r.executor_rx.try_recv().expect("ban dispatched");
    assert!(matches!(cmd, FirewallCmd::Ban { ip, .. } if ip == IP));
}

/// Documents the real store semantics behind the injected fault: etch appends
/// and fsyncs the WAL entry and merges it into memory *before* it attempts the
/// compaction that fails, then returns the error. The tracker correctly treats
/// the write as failed (no index, counters, or firewall command), but the
/// store itself now holds the ban record and the escalation count. If etch or
/// the tracker ever rolls this back, update this test.
#[tokio::test]
async fn test_auto_ban_compaction_failure_leaves_record_and_count_in_store() {
    let fs = FaultStore::open();
    let mut r = rig(fs.store());
    if !fs.inject() {
        eprintln!("skipped: running as root, cannot make the state dir unwritable");
        return;
    }
    let now = chrono::Utc::now().timestamp();
    handle_failure(failure(now), &mut r.state).await;
    handle_failure(failure(now + 1), &mut r.state).await;
    assert_no_ban_state(&mut r);

    let store = fs.store();
    let persisted = store.read();
    assert!(persisted.bans.contains_key(&key()));
    assert_eq!(persisted.ban_counts.get(&IP).map(|c| c.count), Some(1));
}

#[tokio::test]
async fn test_manual_ban_store_write_failure_returns_persistence_error() {
    let fs = FaultStore::open();
    let mut r = rig(fs.store());
    if !fs.inject() {
        eprintln!("skipped: running as root, cannot make the state dir unwritable");
        return;
    }
    let (respond, reply) = oneshot::channel();
    handle_cmd(manual_ban_cmd(respond), &mut r.state).await;

    let err = reply.await.unwrap().unwrap_err();
    let Error::Persistence { message } = err else {
        panic!("expected persistence error, got: {err:?}");
    };
    assert!(message.starts_with("recording ban:"), "{message}");
    assert_no_ban_state(&mut r);
}

#[tokio::test]
async fn test_manual_ban_dispatches_again_after_store_recovers() {
    let fs = FaultStore::open();
    let mut r = rig(fs.store());
    if !fs.inject() {
        eprintln!("skipped: running as root, cannot make the state dir unwritable");
        return;
    }
    let (respond, reply) = oneshot::channel();
    handle_cmd(manual_ban_cmd(respond), &mut r.state).await;
    assert!(reply.await.unwrap().is_err());

    fs.heal();
    let (respond, _reply) = oneshot::channel();
    handle_cmd(manual_ban_cmd(respond), &mut r.state).await;
    // The failed attempt left no AlreadyBanned residue: the ban is dispatched.
    let cmd = r.executor_rx.try_recv().expect("ban dispatched");
    assert!(matches!(cmd, FirewallCmd::Ban { done: Some(_), .. }));
    assert!(r.state.index.banned_keys.contains(&key()));
}
