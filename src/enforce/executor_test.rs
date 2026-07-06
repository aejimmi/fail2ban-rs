use super::*;

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::enforce::test_support::{FailingInitMockBackend, FailingMockBackend, MockBackend};

fn mock_backends(calls: Arc<Mutex<Vec<String>>>) -> HashMap<String, Box<dyn FirewallBackend>> {
    let mut map: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    map.insert(
        "sshd".to_string(),
        Box::new(MockBackend {
            calls: Arc::clone(&calls),
        }),
    );
    map
}

/// Spawn the executor with a dummy (unused) reconcile channel and a
/// tracker channel whose receiver is returned for assertion.
fn spawn_executor(
    rx: mpsc::Receiver<FirewallCmd>,
    backends: HashMap<String, Box<dyn FirewallBackend>>,
    cancel: CancellationToken,
) -> (
    mpsc::Receiver<crate::track::TrackerCmd>,
    mpsc::Sender<crate::enforce::ReconcileRequest>,
    tokio::task::JoinHandle<()>,
) {
    let (reconcile_tx, reconcile_rx) = mpsc::channel(16);
    let (tracker_tx, tracker_rx) = mpsc::channel(16);
    let handle = tokio::spawn(async move {
        crate::enforce::run(rx, reconcile_rx, backends, tracker_tx, cancel).await;
    });
    (tracker_rx, reconcile_tx, handle)
}

#[tokio::test]
async fn ban_and_unban_order() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let backends = mock_backends(Arc::clone(&calls));
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();

    let (_tracker_rx, _reconcile_tx, handle) = spawn_executor(rx, backends, cancel.clone());

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
    async fn unban(&self, _ip: &IpAddr, _jail: &str) -> Result<()> {
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
async fn automatic_ban_failure_notifies_tracker() {
    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert("sshd".to_string(), Box::new(FailingMockBackend));
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (mut tracker_rx, _reconcile_tx, handle) = spawn_executor(rx, backends, cancel.clone());

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
        } => {
            assert_eq!(got_ip, ip);
            assert_eq!(jail_id, "sshd");
        }
        _ => panic!("expected BanApplyFailed"),
    }

    cancel.cancel();
    handle.await.unwrap();
}

/// (c) A manual ban (`done: Some`) whose backend errors must return the error
/// via the done channel and must NOT notify the tracker.
#[tokio::test]
async fn manual_ban_failure_returns_error_via_done() {
    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert("sshd".to_string(), Box::new(FailingMockBackend));
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (mut tracker_rx, _reconcile_tx, handle) = spawn_executor(rx, backends, cancel.clone());

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

/// (b) Reconciliation re-applies a ban that `is_banned` reports missing.
#[tokio::test]
async fn reconcile_reapplies_missing_ban() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert(
        "sshd".to_string(),
        Box::new(MissingBanMock {
            calls: Arc::clone(&calls),
        }),
    );
    let (_tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, reconcile_tx, handle) = spawn_executor(rx, backends, cancel.clone());

    let now = chrono::Utc::now().timestamp();
    let ip = IpAddr::V4(Ipv4Addr::new(6, 6, 6, 6));
    reconcile_tx
        .send(crate::enforce::ReconcileRequest {
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

#[tokio::test]
async fn executor_channel_closed_stops() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let backends = mock_backends(Arc::clone(&calls));
    let (tx, rx) = mpsc::channel::<FirewallCmd>(16);
    let cancel = CancellationToken::new();

    let (_tracker_rx, _reconcile_tx, handle) = spawn_executor(rx, backends, cancel);

    // Drop sender to close channel.
    drop(tx);

    // Executor should exit cleanly.
    tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .expect("timeout")
        .expect("join error");
}

#[tokio::test]
async fn two_jails_different_backends_dispatch_correctly() {
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

    let (_tracker_rx, _reconcile_tx, handle) = spawn_executor(rx, backends, cancel.clone());

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

/// `InitJail` for an already-registered backend must invoke that backend's
/// `init` and ack `Ok(())` on `done`.
#[tokio::test]
async fn init_jail_success_invokes_backend_init_and_acks_ok() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let backends = mock_backends(Arc::clone(&calls));
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, _reconcile_tx, handle) = spawn_executor(rx, backends, cancel.clone());

    let (done_tx, done_rx) = oneshot::channel();
    tx.send(FirewallCmd::InitJail {
        jail_id: "sshd".to_string(),
        ports: vec!["22".to_string()],
        protocol: "tcp".to_string(),
        done: done_tx,
    })
    .await
    .unwrap();

    let result = tokio::time::timeout(Duration::from_secs(2), done_rx)
        .await
        .expect("timeout")
        .expect("done channel dropped");
    assert!(result.is_ok(), "init should succeed: {result:?}");

    cancel.cancel();
    handle.await.unwrap();

    let calls = calls.lock().expect("lock");
    assert!(calls.contains(&"init:sshd".to_string()), "calls: {calls:?}");
}

/// `InitJail` for a jail with no registered backend must skip silently and
/// still ack `Ok(())` — there is nothing to initialize.
#[tokio::test]
async fn init_jail_missing_backend_acks_ok_without_a_backend_call() {
    let backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, _reconcile_tx, handle) = spawn_executor(rx, backends, cancel.clone());

    let (done_tx, done_rx) = oneshot::channel();
    tx.send(FirewallCmd::InitJail {
        jail_id: "ghost".to_string(),
        ports: vec![],
        protocol: "tcp".to_string(),
        done: done_tx,
    })
    .await
    .unwrap();

    let result = tokio::time::timeout(Duration::from_secs(2), done_rx)
        .await
        .expect("timeout")
        .expect("done channel dropped");
    assert!(
        result.is_ok(),
        "init for an unregistered jail must not be an error: {result:?}"
    );

    cancel.cancel();
    handle.await.unwrap();
}

/// `InitJail` propagates a backend's `init` failure back through `done`.
#[tokio::test]
async fn init_jail_backend_failure_propagates_via_done() {
    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert("sshd".to_string(), Box::new(FailingInitMockBackend));
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, _reconcile_tx, handle) = spawn_executor(rx, backends, cancel.clone());

    let (done_tx, done_rx) = oneshot::channel();
    tx.send(FirewallCmd::InitJail {
        jail_id: "sshd".to_string(),
        ports: vec![],
        protocol: "tcp".to_string(),
        done: done_tx,
    })
    .await
    .unwrap();

    let result = tokio::time::timeout(Duration::from_secs(2), done_rx)
        .await
        .expect("timeout")
        .expect("done channel dropped");
    assert!(result.is_err(), "backend init failure must surface as Err");

    cancel.cancel();
    handle.await.unwrap();
}

/// `TeardownJail` (partial) must call the backend's `teardown`, not
/// `teardown_full`, and must leave the backend registered (it is not the
/// jail's deregistration path — that's `RemoveJail`).
#[tokio::test]
async fn teardown_jail_partial_invokes_teardown_not_full_and_keeps_backend_registered() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let backends = mock_backends(Arc::clone(&calls));
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, _reconcile_tx, handle) = spawn_executor(rx, backends, cancel.clone());

    let (done_tx, done_rx) = oneshot::channel();
    tx.send(FirewallCmd::TeardownJail {
        jail_id: "sshd".to_string(),
        done: done_tx,
    })
    .await
    .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), done_rx)
        .await
        .expect("timeout")
        .expect("done channel dropped");
    assert!(result.is_ok(), "teardown should succeed: {result:?}");

    // The backend must still be registered: a follow-up ban must actually
    // reach it rather than skip on "no backend".
    let (ban_done_tx, ban_done_rx) = oneshot::channel();
    let ip = IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5));
    tx.send(FirewallCmd::Ban {
        ip,
        jail_id: "sshd".to_string(),
        banned_at: 1000,
        expires_at: None,
        done: Some(ban_done_tx),
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(2), ban_done_rx)
        .await
        .expect("timeout")
        .expect("done channel dropped")
        .expect("ban should still reach the registered backend");

    cancel.cancel();
    handle.await.unwrap();

    let calls = calls.lock().expect("lock");
    assert!(
        calls.contains(&"teardown:sshd".to_string()),
        "calls: {calls:?}"
    );
    assert!(
        !calls.contains(&"teardown_full:sshd".to_string()),
        "partial teardown must not call teardown_full: {calls:?}"
    );
}

/// `TeardownJailFull` must call the backend's `teardown_full`, not the
/// partial `teardown`.
#[tokio::test]
async fn teardown_jail_full_invokes_teardown_full_not_partial() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let backends = mock_backends(Arc::clone(&calls));
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, _reconcile_tx, handle) = spawn_executor(rx, backends, cancel.clone());

    let (done_tx, done_rx) = oneshot::channel();
    tx.send(FirewallCmd::TeardownJailFull {
        jail_id: "sshd".to_string(),
        done: done_tx,
    })
    .await
    .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), done_rx)
        .await
        .expect("timeout")
        .expect("done channel dropped");
    assert!(result.is_ok(), "full teardown should succeed: {result:?}");

    cancel.cancel();
    handle.await.unwrap();

    let calls = calls.lock().expect("lock");
    assert!(
        calls.contains(&"teardown_full:sshd".to_string()),
        "calls: {calls:?}"
    );
    assert!(
        !calls.contains(&"teardown:sshd".to_string()),
        "full teardown must not call the partial teardown: {calls:?}"
    );
}

/// `TeardownJail`/`TeardownJailFull` for a jail with no registered backend
/// must ack `Ok(())` — nothing to tear down.
#[tokio::test]
async fn teardown_jail_missing_backend_acks_ok() {
    let backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, _reconcile_tx, handle) = spawn_executor(rx, backends, cancel.clone());

    let (done_tx, done_rx) = oneshot::channel();
    tx.send(FirewallCmd::TeardownJail {
        jail_id: "ghost".to_string(),
        done: done_tx,
    })
    .await
    .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), done_rx)
        .await
        .expect("timeout")
        .expect("done channel dropped");
    assert!(result.is_ok(), "missing backend must not be an error");

    cancel.cancel();
    handle.await.unwrap();
}

/// `AddJail` must register a working backend only once `init` succeeds — a
/// real `ScriptBackend`, whose `init` is a guaranteed no-op success, is used
/// so the test is portable (no root/firewall binary needed). Registration is
/// proven by a follow-up `Ban` actually running the script (observed via a
/// marker file it touches), not just skipping on "no backend".
#[tokio::test]
async fn add_jail_registers_backend_after_successful_init_and_it_becomes_functional() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("banned.marker");

    let backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, _reconcile_tx, handle) = spawn_executor(rx, backends, cancel.clone());

    let (add_done_tx, add_done_rx) = oneshot::channel();
    tx.send(FirewallCmd::AddJail {
        jail_id: "sshd".to_string(),
        backend: crate::config::Backend::Script {
            ban_cmd: format!("touch {}", marker.display()),
            unban_cmd: "true".to_string(),
        },
        ports: vec![],
        protocol: "tcp".to_string(),
        done: add_done_tx,
    })
    .await
    .unwrap();
    let add_result = tokio::time::timeout(Duration::from_secs(2), add_done_rx)
        .await
        .expect("timeout")
        .expect("done channel dropped");
    assert!(add_result.is_ok(), "AddJail should succeed: {add_result:?}");

    let (ban_done_tx, ban_done_rx) = oneshot::channel();
    let ip = IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3));
    tx.send(FirewallCmd::Ban {
        ip,
        jail_id: "sshd".to_string(),
        banned_at: 1000,
        expires_at: None,
        done: Some(ban_done_tx),
    })
    .await
    .unwrap();
    let ban_result = tokio::time::timeout(Duration::from_secs(2), ban_done_rx)
        .await
        .expect("timeout")
        .expect("done channel dropped");
    assert!(ban_result.is_ok(), "ban should succeed: {ban_result:?}");

    assert!(
        marker.exists(),
        "the newly-added jail's real script backend must have run the ban command"
    );

    cancel.cancel();
    handle.await.unwrap();
}

/// A failed `AddJail` must leave no backend registered for that jail. Since
/// building a real nftables backend requires resolving the `nft` binary and
/// then creating kernel objects (which needs `CAP_NET_ADMIN`), this
/// deterministically fails under an unprivileged test runner whether or not
/// `nft` happens to be installed — exactly the failure this test protects
/// against. If it were ever run privileged enough for the add to succeed, the
/// assertion below is skipped rather than asserting a false failure (and the
/// jail is torn down to avoid leaking real kernel state).
#[tokio::test]
async fn add_jail_backend_failure_leaves_no_backend_registered() {
    let backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, _reconcile_tx, handle) = spawn_executor(rx, backends, cancel.clone());

    let (add_done_tx, add_done_rx) = oneshot::channel();
    tx.send(FirewallCmd::AddJail {
        jail_id: "sshd".to_string(),
        backend: crate::config::Backend::Nftables,
        ports: vec![],
        protocol: "tcp".to_string(),
        done: add_done_tx,
    })
    .await
    .unwrap();
    let add_result = tokio::time::timeout(Duration::from_secs(5), add_done_rx)
        .await
        .expect("timeout")
        .expect("done channel dropped");

    if add_result.is_ok() {
        let (td_tx, td_rx) = oneshot::channel();
        let _ = tx
            .send(FirewallCmd::TeardownJailFull {
                jail_id: "sshd".to_string(),
                done: td_tx,
            })
            .await;
        let _ = td_rx.await;
        cancel.cancel();
        handle.await.unwrap();
        eprintln!(
            "skipping assertion: nftables AddJail unexpectedly succeeded \
             (privileged test runner?)"
        );
        return;
    }

    // A subsequent ban for the same jail_id must take the "no backend" skip
    // path (Ok) rather than attempting a real (and equally doomed) nft call.
    let (ban_done_tx, ban_done_rx) = oneshot::channel();
    tx.send(FirewallCmd::Ban {
        ip: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
        jail_id: "sshd".to_string(),
        banned_at: 1000,
        expires_at: None,
        done: Some(ban_done_tx),
    })
    .await
    .unwrap();
    let ban_result = tokio::time::timeout(Duration::from_secs(2), ban_done_rx)
        .await
        .expect("timeout")
        .expect("done channel dropped");
    assert!(
        ban_result.is_ok(),
        "ban for a jail whose AddJail failed must skip, not error: {ban_result:?}"
    );

    cancel.cancel();
    handle.await.unwrap();
}

/// `RemoveJail` must tear down the backend and deregister it: a follow-up
/// ban for the same jail must then take the "no backend" skip path.
#[tokio::test]
async fn remove_jail_tears_down_and_deregisters_backend() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let backends = mock_backends(Arc::clone(&calls));
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, _reconcile_tx, handle) = spawn_executor(rx, backends, cancel.clone());

    let (done_tx, done_rx) = oneshot::channel();
    tx.send(FirewallCmd::RemoveJail {
        jail_id: "sshd".to_string(),
        done: done_tx,
    })
    .await
    .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), done_rx)
        .await
        .expect("timeout")
        .expect("done channel dropped");
    assert!(result.is_ok(), "remove should succeed: {result:?}");

    // The backend is gone: a ban for "sshd" must now skip silently.
    let (ban_done_tx, ban_done_rx) = oneshot::channel();
    tx.send(FirewallCmd::Ban {
        ip: IpAddr::V4(Ipv4Addr::new(4, 4, 4, 4)),
        jail_id: "sshd".to_string(),
        banned_at: 1000,
        expires_at: None,
        done: Some(ban_done_tx),
    })
    .await
    .unwrap();
    let ban_result = tokio::time::timeout(Duration::from_secs(2), ban_done_rx)
        .await
        .expect("timeout")
        .expect("done channel dropped");
    assert!(
        ban_result.is_ok(),
        "ban after removal must skip, not error: {ban_result:?}"
    );

    cancel.cancel();
    handle.await.unwrap();

    let calls = calls.lock().expect("lock");
    assert!(
        calls.contains(&"teardown:sshd".to_string()),
        "calls: {calls:?}"
    );
    assert!(
        !calls.iter().any(|c| c.starts_with("ban:4.4.4.4")),
        "the deregistered backend must not have been asked to ban: {calls:?}"
    );
}

/// `RemoveJail` for a jail with no registered backend must ack `Ok(())`.
#[tokio::test]
async fn remove_jail_missing_backend_acks_ok() {
    let backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, _reconcile_tx, handle) = spawn_executor(rx, backends, cancel.clone());

    let (done_tx, done_rx) = oneshot::channel();
    tx.send(FirewallCmd::RemoveJail {
        jail_id: "ghost".to_string(),
        done: done_tx,
    })
    .await
    .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), done_rx)
        .await
        .expect("timeout")
        .expect("done channel dropped");
    assert!(result.is_ok(), "missing backend must not be an error");

    cancel.cancel();
    handle.await.unwrap();
}

/// Cancelling the token must exit the executor loop promptly, even with
/// commands never sent — the loop must not be stuck waiting on `rx.recv()`.
#[tokio::test]
async fn cancellation_exits_the_loop_promptly() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let backends = mock_backends(Arc::clone(&calls));
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, _reconcile_tx, handle) = spawn_executor(rx, backends, cancel.clone());

    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("executor must exit promptly once cancelled")
        .expect("join error");

    // The sender is still open; dropping it after the loop has already
    // exited must not panic (buffered channel with no reader left).
    drop(tx);
}
