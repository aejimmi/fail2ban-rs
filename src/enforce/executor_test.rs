use super::*;

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::enforce::test_support::{FailingMockBackend, MockBackend};
use crate::track::state::BanRecord;

pub(super) fn mock_backends(
    calls: Arc<Mutex<Vec<String>>>,
) -> HashMap<String, Box<dyn FirewallBackend>> {
    let mut map: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    map.insert(
        "sshd".to_string(),
        Box::new(MockBackend {
            calls: Arc::clone(&calls),
        }),
    );
    map
}

/// Spawn the executor with a tracker channel whose receiver is returned for
/// assertion.
pub(super) fn spawn_executor(
    rx: mpsc::Receiver<FirewallCmd>,
    backends: HashMap<String, Box<dyn FirewallBackend>>,
    cancel: CancellationToken,
) -> (
    mpsc::Receiver<crate::track::TrackerCmd>,
    tokio::task::JoinHandle<()>,
) {
    let (tracker_tx, tracker_rx) = mpsc::channel(16);
    let handle = tokio::spawn(async move {
        crate::enforce::run(rx, backends, tracker_tx, cancel).await;
    });
    (tracker_rx, handle)
}

#[tokio::test]
async fn test_ban_and_unban_order() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let backends = mock_backends(Arc::clone(&calls));
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();

    let (_tracker_rx, handle) = spawn_executor(rx, backends, cancel.clone());

    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

    tx.send(FirewallCmd::Ban {
        ip,
        jail_id: "sshd".to_string(),
        banned_at: 1000,
        expires_at: Some(2000),
        done: None,
    })
    .await
    .unwrap();

    tx.send(FirewallCmd::Unban {
        ip,
        jail_id: "sshd".to_string(),
        done: None,
    })
    .await
    .unwrap();

    // Give executor time to process.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    cancel.cancel();
    handle.await.unwrap();

    let calls = calls.lock().expect("lock");
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0], "ban:1.2.3.4:sshd");
    assert_eq!(calls[1], "unban:1.2.3.4:sshd");
}

/// Records ban calls and reports every IP as *not* currently banned, so a
/// reconcile request always re-applies.
struct MissingBanMock {
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl FirewallBackend for MissingBanMock {
    async fn init(&self, _jail: &str, _ports: &[String], _protocol: &str) -> Result<()> {
        Ok(())
    }
    async fn teardown(&self, _jail: &str) -> Result<()> {
        Ok(())
    }
    async fn ban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        self.calls
            .lock()
            .expect("lock")
            .push(format!("ban:{ip}:{jail}"));
        Ok(())
    }
    async fn unban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        self.calls
            .lock()
            .expect("lock")
            .push(format!("unban:{ip}:{jail}"));
        Ok(())
    }
    async fn is_banned(&self, ip: &IpAddr, jail: &str) -> Result<bool> {
        self.calls
            .lock()
            .expect("lock")
            .push(format!("is_banned:{ip}:{jail}"));
        Ok(false)
    }
    fn name(&self) -> &'static str {
        "missing-mock"
    }
}

/// (a2) An automatic ban (`done: None`) whose backend errors must notify the
/// tracker with `BanApplyFailed` so it can roll back persisted state.
#[tokio::test]
async fn test_automatic_ban_failure_notifies_tracker() {
    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert("sshd".to_string(), Box::new(FailingMockBackend));
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (mut tracker_rx, handle) = spawn_executor(rx, backends, cancel.clone());

    let ip = IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7));
    tx.send(FirewallCmd::Ban {
        ip,
        jail_id: "sshd".to_string(),
        banned_at: 1000,
        expires_at: Some(2000),
        done: None,
    })
    .await
    .unwrap();

    let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), tracker_rx.recv())
        .await
        .expect("timeout waiting for rollback notify")
        .expect("tracker channel closed");
    match cmd {
        crate::track::TrackerCmd::BanApplyFailed {
            ip: got_ip,
            jail_id,
            banned_at,
        } => {
            assert_eq!(got_ip, ip);
            assert_eq!(jail_id, "sshd");
            assert_eq!(banned_at, 1000, "notice must identify the failed ban");
        }
        _ => panic!("expected BanApplyFailed"),
    }

    cancel.cancel();
    handle.await.unwrap();
}

/// (c) A manual ban (`done: Some`) whose backend errors must return the error
/// via the done channel and must NOT notify the tracker.
#[tokio::test]
async fn test_manual_ban_failure_returns_error_via_done() {
    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert("sshd".to_string(), Box::new(FailingMockBackend));
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (mut tracker_rx, handle) = spawn_executor(rx, backends, cancel.clone());

    let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    tx.send(FirewallCmd::Ban {
        ip,
        jail_id: "sshd".to_string(),
        banned_at: 1000,
        expires_at: Some(2000),
        done: Some(done_tx),
    })
    .await
    .unwrap();

    let result = tokio::time::timeout(std::time::Duration::from_secs(2), done_rx)
        .await
        .expect("timeout")
        .expect("done channel dropped");
    assert!(result.is_err(), "manual ban should return backend error");

    // The tracker must NOT be notified on the manual path.
    let notified =
        tokio::time::timeout(std::time::Duration::from_millis(200), tracker_rx.recv()).await;
    assert!(
        notified.is_err(),
        "manual ban failure must not notify tracker"
    );

    cancel.cancel();
    handle.await.unwrap();
}

#[tokio::test]
async fn test_manual_ban_without_backend_returns_error_via_done() {
    let backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, handle) = spawn_executor(rx, backends, cancel.clone());

    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    tx.send(FirewallCmd::Ban {
        ip: IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
        jail_id: "missing".to_string(),
        banned_at: 1000,
        expires_at: Some(2000),
        done: Some(done_tx),
    })
    .await
    .unwrap();

    let error = tokio::time::timeout(std::time::Duration::from_secs(2), done_rx)
        .await
        .expect("timeout")
        .expect("done channel dropped")
        .expect_err("manual ban without a backend must fail");
    assert!(error.to_string().contains("no backend registered"));

    cancel.cancel();
    handle.await.unwrap();
}

/// (b) Reconciliation re-applies a ban that `is_banned` reports missing.
#[tokio::test]
async fn test_reconcile_reapplies_missing_ban() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert(
        "sshd".to_string(),
        Box::new(MissingBanMock {
            calls: Arc::clone(&calls),
        }),
    );
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, handle) = spawn_executor(rx, backends, cancel.clone());

    let now = chrono::Utc::now().timestamp();
    let ip = IpAddr::V4(Ipv4Addr::new(6, 6, 6, 6));
    tx.send(FirewallCmd::Reconcile {
        bans: vec![BanRecord {
            ip,
            jail_id: "sshd".to_string(),
            banned_at: now,
            expires_at: Some(now + 3600),
        }],
    })
    .await
    .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    cancel.cancel();
    handle.await.unwrap();

    let calls = calls.lock().expect("lock");
    assert!(
        calls.iter().any(|c| c == "is_banned:6.6.6.6:sshd"),
        "reconcile should check is_banned: {calls:?}"
    );
    assert!(
        calls.iter().any(|c| c == "ban:6.6.6.6:sshd"),
        "reconcile should re-apply the missing ban: {calls:?}"
    );
}

/// L3: a ban whose jail has no registered backend is skipped (logged) without
/// stopping the rest of the batch from being reconciled.
#[tokio::test]
async fn test_reconcile_skips_jail_without_backend_and_continues() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert(
        "sshd".to_string(),
        Box::new(MissingBanMock {
            calls: Arc::clone(&calls),
        }),
    );
    let now = chrono::Utc::now().timestamp();
    let record = |last: u8, jail: &str| BanRecord {
        ip: IpAddr::V4(Ipv4Addr::new(6, 6, 7, last)),
        jail_id: jail.to_string(),
        banned_at: now,
        expires_at: None,
    };

    reconcile_bans(&backends, vec![record(1, "ghost"), record(2, "sshd")]).await;

    let calls = calls.lock().expect("lock");
    assert_eq!(
        calls.as_slice(),
        ["is_banned:6.6.7.2:sshd", "ban:6.6.7.2:sshd"]
    );
}

#[tokio::test]
async fn test_executor_channel_closed_stops() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let backends = mock_backends(Arc::clone(&calls));
    let (tx, rx) = mpsc::channel::<FirewallCmd>(16);
    let cancel = CancellationToken::new();

    let (_tracker_rx, handle) = spawn_executor(rx, backends, cancel);

    // Drop sender to close channel.
    drop(tx);

    // Executor should exit cleanly.
    tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .expect("timeout")
        .expect("join error");
}

#[tokio::test]
async fn test_two_jails_different_backends_dispatch_correctly() {
    let sshd_calls = Arc::new(Mutex::new(Vec::new()));
    let nginx_calls = Arc::new(Mutex::new(Vec::new()));

    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert(
        "sshd".to_string(),
        Box::new(MockBackend {
            calls: Arc::clone(&sshd_calls),
        }),
    );
    backends.insert(
        "nginx".to_string(),
        Box::new(MockBackend {
            calls: Arc::clone(&nginx_calls),
        }),
    );

    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();

    let (_tracker_rx, handle) = spawn_executor(rx, backends, cancel.clone());

    let ip1 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));

    tx.send(FirewallCmd::Ban {
        ip: ip1,
        jail_id: "sshd".to_string(),
        banned_at: 1000,
        expires_at: Some(2000),
        done: None,
    })
    .await
    .unwrap();

    tx.send(FirewallCmd::Ban {
        ip: ip2,
        jail_id: "nginx".to_string(),
        banned_at: 1000,
        expires_at: Some(2000),
        done: None,
    })
    .await
    .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    cancel.cancel();
    handle.await.unwrap();

    let sshd = sshd_calls.lock().expect("lock");
    assert_eq!(sshd.len(), 1);
    assert_eq!(sshd[0], "ban:1.1.1.1:sshd");

    let nginx = nginx_calls.lock().expect("lock");
    assert_eq!(nginx.len(), 1);
    assert_eq!(nginx[0], "ban:2.2.2.2:nginx");
}

/// Cancelling the token must exit the executor loop promptly, even with
/// commands never sent — the loop must not be stuck waiting on `rx.recv()`.
#[tokio::test]
async fn test_cancellation_exits_the_loop_promptly() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let backends = mock_backends(Arc::clone(&calls));
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, handle) = spawn_executor(rx, backends, cancel.clone());

    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("executor must exit promptly once cancelled")
        .expect("join error");

    // The sender is still open; dropping it after the loop has already
    // exited must not panic (buffered channel with no reader left).
    drop(tx);
}

/// C2: reconcile travels on the ordered command channel, so a batch listing
/// an IP is always handled before a later `Unban` of it — the IP can never
/// be re-banned after the unban.
#[tokio::test]
async fn test_reconcile_then_unban_is_processed_in_order() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    let mock = MissingBanMock {
        calls: Arc::clone(&calls),
    };
    backends.insert("sshd".to_string(), Box::new(mock));
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let ip = IpAddr::V4(Ipv4Addr::new(6, 6, 6, 9));
    let ban = BanRecord {
        ip,
        jail_id: "sshd".to_string(),
        banned_at: 1,
        expires_at: None,
    };
    // Queue both before the executor starts so it sees them back to back.
    tx.send(FirewallCmd::Reconcile { bans: vec![ban] })
        .await
        .unwrap();
    tx.send(FirewallCmd::Unban {
        ip,
        jail_id: "sshd".to_string(),
        done: None,
    })
    .await
    .unwrap();
    drop(tx);
    let (_tracker_rx, handle) = spawn_executor(rx, backends, cancel);
    handle.await.unwrap();

    let calls = calls.lock().expect("lock");
    assert_eq!(
        calls.last().map(String::as_str),
        Some("unban:6.6.6.9:sshd"),
        "unban must run after the reconcile re-ban: {calls:?}"
    );
}
