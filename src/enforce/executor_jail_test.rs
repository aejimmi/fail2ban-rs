use super::*;

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::enforce::test_support::FailingInitMockBackend;

use super::executor_test::{mock_backends, spawn_executor};

/// `InitJail` for an already-registered backend must invoke that backend's
/// `init` and ack `Ok(())` on `done`.
#[tokio::test]
async fn test_init_jail_success_invokes_backend_init_and_acks_ok() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let backends = mock_backends(Arc::clone(&calls));
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, handle) = spawn_executor(rx, backends, cancel.clone());

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
async fn test_init_jail_missing_backend_acks_ok_without_a_backend_call() {
    let backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, handle) = spawn_executor(rx, backends, cancel.clone());

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
async fn test_init_jail_backend_failure_propagates_via_done() {
    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert("sshd".to_string(), Box::new(FailingInitMockBackend));
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, handle) = spawn_executor(rx, backends, cancel.clone());

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
async fn test_teardown_jail_partial_invokes_teardown_not_full_and_keeps_backend_registered() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let backends = mock_backends(Arc::clone(&calls));
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, handle) = spawn_executor(rx, backends, cancel.clone());

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
    let ip = BanTarget::V4(Ipv4Addr::new(5, 5, 5, 5));
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
async fn test_teardown_jail_full_invokes_teardown_full_not_partial() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let backends = mock_backends(Arc::clone(&calls));
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, handle) = spawn_executor(rx, backends, cancel.clone());

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
async fn test_teardown_jail_missing_backend_acks_ok() {
    let backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, handle) = spawn_executor(rx, backends, cancel.clone());

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
async fn test_add_jail_registers_backend_after_successful_init_and_it_becomes_functional() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("banned.marker");

    let backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, handle) = spawn_executor(rx, backends, cancel.clone());

    let (add_done_tx, add_done_rx) = oneshot::channel();
    tx.send(FirewallCmd::AddJail {
        jail_id: "sshd".to_string(),
        backend: crate::config::Backend::Script {
            ban_cmd: format!("touch {}", marker.display()),
            unban_cmd: "true".to_string(),
        },
        ports: vec![],
        protocol: "tcp".to_string(),
        active_bans: vec![],
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
    let ip = BanTarget::V4(Ipv4Addr::new(3, 3, 3, 3));
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
async fn test_add_jail_backend_failure_leaves_no_backend_registered() {
    let backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, handle) = spawn_executor(rx, backends, cancel.clone());

    let (add_done_tx, add_done_rx) = oneshot::channel();
    tx.send(FirewallCmd::AddJail {
        jail_id: "sshd".to_string(),
        backend: crate::config::Backend::Nftables,
        ports: vec![],
        protocol: "tcp".to_string(),
        active_bans: vec![],
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

    // A subsequent acknowledged ban for the same jail_id must report that no
    // backend was registered rather than claiming success.
    let (ban_done_tx, ban_done_rx) = oneshot::channel();
    tx.send(FirewallCmd::Ban {
        ip: BanTarget::V4(Ipv4Addr::new(9, 9, 9, 9)),
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
    let error = ban_result.expect_err("ban without a registered backend must fail");
    assert!(error.to_string().contains("no backend registered"));

    cancel.cancel();
    handle.await.unwrap();
}

/// `RemoveJail` must tear down the backend and deregister it: a follow-up
/// acknowledged ban for the same jail must report that no backend exists.
#[tokio::test]
async fn test_remove_jail_tears_down_and_deregisters_backend() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let backends = mock_backends(Arc::clone(&calls));
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, handle) = spawn_executor(rx, backends, cancel.clone());

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

    // The backend is gone: an acknowledged ban for "sshd" must now fail.
    let (ban_done_tx, ban_done_rx) = oneshot::channel();
    tx.send(FirewallCmd::Ban {
        ip: BanTarget::V4(Ipv4Addr::new(4, 4, 4, 4)),
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
    let error = ban_result.expect_err("ban after backend removal must fail");
    assert!(error.to_string().contains("no backend registered"));

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
async fn test_remove_jail_missing_backend_acks_ok() {
    let backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (_tracker_rx, handle) = spawn_executor(rx, backends, cancel.clone());

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
