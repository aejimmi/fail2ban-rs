//! Expiry-unban failure handling: retained record, scheduled retry, re-send.

use super::*;

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::error::Error;
use crate::track::execute::record_ban;
use crate::track::fault_support::{FaultStore, Rig, rig};
use crate::track::sweep::process_unbans;
use crate::track::unban::{RETRY_SECS, handle_unban_outcome};

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));

fn key() -> (IpAddr, String) {
    (IP, "sshd".to_string())
}

/// A rig holding an already-expired ban (indexed and persisted).
fn rig_with_expired_ban(fs: &FaultStore) -> Rig {
    let mut r = rig(fs.store());
    record_ban(IP, "sshd", 0, None, &mut r.state).unwrap();
    assert!(r.state.index.banned_keys.contains(&key()));
    r
}

/// Take the next `Unban` command, answer its acknowledgement, and feed the
/// resulting outcome back into the tracker.
async fn answer_unban(r: &mut Rig, result: crate::error::Result<()>) {
    let cmd = r.executor_rx.try_recv().expect("an Unban must be sent");
    let FirewallCmd::Unban {
        ip,
        done: Some(done),
        ..
    } = cmd
    else {
        panic!("expected acknowledged Unban, got: {cmd:?}");
    };
    assert_eq!(ip, IP);
    done.send(result).unwrap();
    feed_outcome(r).await;
}

async fn feed_outcome(r: &mut Rig) {
    let outcome = tokio::time::timeout(Duration::from_secs(5), r.unban_rx.recv())
        .await
        .expect("outcome timeout")
        .expect("outcome channel closed");
    handle_unban_outcome(outcome, &mut r.state);
}

fn persisted(r: &Rig) -> bool {
    r.state.store.read().bans.contains_key(&key())
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

#[tokio::test]
async fn test_expiry_unban_firewall_failure_keeps_record_and_retries_after_delay() {
    let fs = FaultStore::open();
    let mut r = rig_with_expired_ban(&fs);

    process_unbans(&mut r.state).await;
    let before = now();
    answer_unban(&mut r, Err(Error::firewall("nft exploded"))).await;
    let after = now();

    // Record stays persisted and indexed; nothing counted; retry scheduled.
    assert!(persisted(&r));
    assert!(r.state.index.banned_keys.contains(&key()));
    assert_eq!(r.state.counters.total_unbans, 0);
    assert!(r.state.pending_unbans.is_empty());
    let retry = *r
        .state
        .unban_retry_after
        .get(&key())
        .expect("retry scheduled");
    assert!(
        retry >= before + RETRY_SECS && retry <= after + RETRY_SECS,
        "{retry}"
    );

    // Before the retry delay a sweep must not resend.
    process_unbans(&mut r.state).await;
    assert!(r.executor_rx.try_recv().is_err(), "unban resent too early");
    assert!(persisted(&r));

    // Once the delay has elapsed (the retry clock is wall time, so move the
    // deadline into the past) the sweep sends the Unban again.
    r.state.unban_retry_after.insert(key(), now() - 1);
    process_unbans(&mut r.state).await;
    answer_unban(&mut r, Ok(())).await;

    assert!(!persisted(&r));
    assert!(!r.state.index.banned_keys.contains(&key()));
    assert!(r.state.unban_retry_after.is_empty());
    assert_eq!(r.state.counters.total_unbans, 1);

    // A further sweep neither resends nor double counts.
    process_unbans(&mut r.state).await;
    assert!(r.executor_rx.try_recv().is_err());
    assert_eq!(r.state.counters.total_unbans, 1);
}

#[tokio::test]
async fn test_expiry_unban_repeated_failures_keep_rescheduling() {
    let fs = FaultStore::open();
    let mut r = rig_with_expired_ban(&fs);
    for _ in 0..2 {
        r.state.unban_retry_after.insert(key(), now() - 1);
        process_unbans(&mut r.state).await;
        answer_unban(&mut r, Err(Error::firewall("still failing"))).await;
        assert!(persisted(&r));
        let retry = r.state.unban_retry_after[&key()];
        assert!(retry > now());
    }
    assert_eq!(r.state.counters.total_unbans, 0);
}

#[tokio::test]
async fn test_expiry_unban_executor_channel_closed_keeps_record_and_schedules_retry() {
    let fs = FaultStore::open();
    let mut r = rig_with_expired_ban(&fs);
    let before = now();
    // Close the executor channel by dropping its only receiver.
    drop(std::mem::replace(
        &mut r.executor_rx,
        tokio::sync::mpsc::channel(1).1,
    ));

    process_unbans(&mut r.state).await;

    assert!(persisted(&r));
    assert!(r.state.index.banned_keys.contains(&key()));
    assert!(
        r.state.pending_unbans.is_empty(),
        "key must not stay pending"
    );
    assert_eq!(r.state.counters.total_unbans, 0);
    let retry = *r
        .state
        .unban_retry_after
        .get(&key())
        .expect("retry scheduled");
    assert!(retry >= before + RETRY_SECS);
}

#[tokio::test]
async fn test_expiry_unban_acknowledgement_dropped_keeps_record() {
    let fs = FaultStore::open();
    let mut r = rig_with_expired_ban(&fs);
    process_unbans(&mut r.state).await;
    // The executor takes the command and dies without answering.
    drop(r.executor_rx.try_recv().expect("an Unban must be sent"));
    feed_outcome(&mut r).await;
    assert!(persisted(&r));
    assert!(r.state.unban_retry_after.contains_key(&key()));
    assert_eq!(r.state.counters.total_unbans, 0);
}
