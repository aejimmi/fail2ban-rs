//! Tracker startup over a store that still holds an already-expired ban.
//!
//! This is the state left behind when an expiry unban failed and the daemon
//! restarted before the retry succeeded. The tracker itself recovers: it
//! indexes the record, the first sweep fires immediately, and it re-sends the
//! `Unban`. (The server's `open_state` purges expired records before the
//! tracker ever sees them; see `server::restored_test` for that behaviour.)

use super::*;

use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::config::JailConfig;
use crate::enforce::FirewallCmd;
use crate::error::Error;
use crate::track::persist::open_ban_store;
use crate::track::state::BanRecord;
use crate::track::test_support::{test_global_config, test_jail_config};

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44));

/// Persist an expired ban for `IP` into a fresh store at `dir` and close it.
fn write_expired_ban(dir: &std::path::Path) {
    let store = open_ban_store(dir.to_path_buf()).unwrap();
    let now = chrono::Utc::now().timestamp();
    let record = BanRecord {
        ip: IP,
        jail_id: "sshd".to_string(),
        banned_at: now - 120,
        expires_at: Some(now - 60),
    };
    store
        .write(|tx| {
            tx.bans.put((IP, "sshd".to_string()), record.clone())?;
            Ok(())
        })
        .unwrap();
}

struct Running {
    cmd_tx: mpsc::Sender<TrackerCmd>,
    executor_rx: mpsc::Receiver<FirewallCmd>,
    cancel: CancellationToken,
    _failure_tx: mpsc::Sender<crate::detect::watcher::Failure>,
    handle: tokio::task::JoinHandle<()>,
}

fn start(dir: &std::path::Path) -> Running {
    let store = std::sync::Arc::new(open_ban_store(dir.to_path_buf()).unwrap());
    let jails: HashMap<String, JailConfig> =
        HashMap::from([("sshd".to_string(), test_jail_config())]);
    let (failure_tx, failure_rx) = mpsc::channel(8);
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    let (executor_tx, executor_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let handle = tokio::spawn(crate::track::run(
        test_global_config(),
        jails,
        failure_rx,
        cmd_rx,
        executor_tx,
        false,
        vec![],
        HashMap::new(),
        store,
        None,
        cancel.clone(),
    ));
    Running {
        cmd_tx,
        executor_rx,
        cancel,
        _failure_tx: failure_tx,
        handle,
    }
}

async fn stats(cmd_tx: &mpsc::Sender<TrackerCmd>) -> Stats {
    let (respond, rx) = oneshot::channel();
    cmd_tx.send(TrackerCmd::GetStats { respond }).await.unwrap();
    rx.await.unwrap()
}

#[tokio::test]
async fn test_restart_with_expired_ban_in_store_resends_unban_and_clears_record() {
    let dir = tempfile::tempdir().unwrap();
    write_expired_ban(dir.path());
    let mut run = start(dir.path());

    // The expired record is indexed at startup, so the first sweep unbans it.
    let cmd = tokio::time::timeout(Duration::from_secs(10), run.executor_rx.recv())
        .await
        .expect("expired ban must be unbanned at startup")
        .expect("executor channel closed");
    let FirewallCmd::Unban {
        ip,
        jail_id,
        done: Some(done),
    } = cmd
    else {
        panic!("expected acknowledged Unban, got: {cmd:?}");
    };
    assert_eq!((ip, jail_id.as_str()), (IP, "sshd"));
    assert_eq!(stats(&run.cmd_tx).await.active_bans, 1, "kept until acked");

    done.send(Ok(())).unwrap();
    let cleared = async {
        loop {
            let s = stats(&run.cmd_tx).await;
            if s.active_bans == 0 {
                return s;
            }
            tokio::task::yield_now().await;
        }
    };
    let s = tokio::time::timeout(Duration::from_secs(10), cleared)
        .await
        .expect("record must clear after the acknowledged unban");
    assert_eq!(s.total_unbans, 1);
    run.cancel.cancel();
    run.handle.await.unwrap();
}

#[tokio::test]
async fn test_restart_with_expired_ban_failed_unban_keeps_record_for_retry() {
    let dir = tempfile::tempdir().unwrap();
    write_expired_ban(dir.path());
    let mut run = start(dir.path());

    let cmd = tokio::time::timeout(Duration::from_secs(10), run.executor_rx.recv())
        .await
        .expect("expired ban must be unbanned at startup")
        .expect("executor channel closed");
    let FirewallCmd::Unban {
        done: Some(done), ..
    } = cmd
    else {
        panic!("expected acknowledged Unban, got: {cmd:?}");
    };
    done.send(Err(Error::firewall("still failing"))).unwrap();

    // The retry is delayed, so no second Unban arrives straight away and the
    // record must remain.
    let resent = tokio::time::timeout(Duration::from_millis(300), run.executor_rx.recv()).await;
    assert!(
        resent.is_err(),
        "unban resent without waiting out the retry delay"
    );
    let s = stats(&run.cmd_tx).await;
    assert_eq!(s.active_bans, 1);
    assert_eq!(s.total_unbans, 0);
    run.cancel.cancel();
    run.handle.await.unwrap();
}
