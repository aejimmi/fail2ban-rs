use super::*;

use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::detect::watcher::Failure;
use crate::enforce::FirewallCmd;
use crate::error::Result;
use crate::track::test_support::{test_global_config, test_jail_config, test_store};

/// A real tracker task whose executor side is driven by the test.
struct Harness {
    failure_tx: mpsc::Sender<Failure>,
    executor_rx: mpsc::Receiver<FirewallCmd>,
    cmd_tx: mpsc::Sender<TrackerCmd>,
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

fn spawn_tracker() -> Harness {
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), test_jail_config());
    let (failure_tx, failure_rx) = mpsc::channel(64);
    let (executor_tx, executor_rx) = mpsc::channel(64);
    let (cmd_tx, cmd_rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move {
        crate::track::run(
            test_global_config(),
            jails,
            failure_rx,
            cmd_rx,
            executor_tx,
            false,
            vec![],
            HashMap::new(),
            test_store(),
            None,
            cancel_clone,
        )
        .await;
    });
    Harness {
        failure_tx,
        executor_rx,
        cmd_tx,
        cancel,
        handle,
    }
}

impl Harness {
    /// Send a manual ban and return its pending response receiver.
    async fn send_manual_ban(&self, ip: IpAddr) -> oneshot::Receiver<Result<()>> {
        let (respond, rx) = oneshot::channel();
        self.cmd_tx
            .send(TrackerCmd::ManualBan {
                ip,
                jail_id: "sshd".to_string(),
                ban_time: 3600,
                respond,
            })
            .await
            .unwrap();
        rx
    }

    /// Receive the next executor command.
    async fn next_cmd(&mut self) -> FirewallCmd {
        tokio::time::timeout(Duration::from_secs(30), self.executor_rx.recv())
            .await
            .expect("timeout waiting for executor command")
            .expect("executor channel closed")
    }

    /// Receive the manual ban's command and return its ack sender.
    async fn take_ban_ack(&mut self) -> oneshot::Sender<Result<()>> {
        match self.next_cmd().await {
            FirewallCmd::Ban { done: Some(d), .. } => d,
            other => panic!("expected acknowledged Ban, got {other:?}"),
        }
    }

    async fn stats(&self) -> Stats {
        let (respond, rx) = oneshot::channel();
        self.cmd_tx
            .send(TrackerCmd::GetStats { respond })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(30), rx)
            .await
            .expect("tracker must answer while a manual ban is pending")
            .unwrap()
    }

    async fn stop(self) {
        self.cancel.cancel();
        self.handle.await.unwrap();
    }
}

fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 51, 100, last))
}

/// H1: a hung firewall command must not stall the tracker — other commands
/// and failures are processed while the manual ban is still pending.
#[tokio::test]
async fn test_manual_ban_hung_firewall_keeps_tracker_responsive() {
    let mut h = spawn_tracker();
    let mut respond_rx = h.send_manual_ban(ip(1)).await;
    let _hung_ack = h.take_ban_ack().await; // never answered

    let stats = h.stats().await;
    assert_eq!(stats.active_bans, 1, "pending ban is recorded");

    let now = chrono::Utc::now().timestamp();
    for i in 0..3 {
        let failure = Failure {
            ip: ip(2),
            jail_id: "sshd".to_string(),
            timestamp: now + i,
        };
        h.failure_tx.send(failure).await.unwrap();
    }
    match h.next_cmd().await {
        FirewallCmd::Ban { ip: got, done, .. } => {
            assert_eq!(got, ip(2));
            assert!(done.is_none(), "automatic ban is fire-and-forget");
        }
        other => panic!("expected automatic Ban, got {other:?}"),
    }
    assert!(respond_rx.try_recv().is_err(), "manual ban still pending");
    h.stop().await;
}

/// H1: a manual ban whose firewall command never completes times out, rolls
/// back, reports an error, and queues an unban behind the hung command.
#[tokio::test]
async fn test_manual_ban_hung_firewall_times_out_and_rolls_back() {
    let mut h = spawn_tracker();
    let respond_rx = h.send_manual_ban(ip(3)).await;
    let _hung_ack = h.take_ban_ack().await;

    let result = respond_rx.await.expect("tracker must answer after timeout");
    let error = result.expect_err("timed-out manual ban must fail");
    assert!(error.to_string().contains("did not apply ban"), "{error}");

    match h.next_cmd().await {
        FirewallCmd::Unban { ip: got, .. } => assert_eq!(got, ip(3)),
        other => panic!("expected compensating Unban, got {other:?}"),
    }
    let stats = h.stats().await;
    assert_eq!(stats.active_bans, 0);
    assert_eq!(stats.total_bans, 0);
    h.stop().await;
}

/// A firewall error rolls the manual ban back and surfaces the error.
#[tokio::test]
async fn test_manual_ban_firewall_error_rolls_back() {
    let mut h = spawn_tracker();
    let respond_rx = h.send_manual_ban(ip(4)).await;
    let ack = h.take_ban_ack().await;
    ack.send(Err(crate::error::Error::firewall("boom")))
        .unwrap();

    let error = respond_rx.await.unwrap().expect_err("must fail");
    assert!(error.to_string().contains("boom"));
    let stats = h.stats().await;
    assert_eq!((stats.active_bans, stats.total_bans), (0, 0));

    // Rolled back: the same IP can be banned again.
    let respond_rx = h.send_manual_ban(ip(4)).await;
    h.take_ban_ack().await.send(Ok(())).unwrap();
    assert!(respond_rx.await.unwrap().is_ok());
    h.stop().await;
}

/// A dropped ack (executor gone mid-command) rolls the ban back.
#[tokio::test]
async fn test_manual_ban_dropped_ack_rolls_back() {
    let mut h = spawn_tracker();
    let respond_rx = h.send_manual_ban(ip(5)).await;
    drop(h.take_ban_ack().await);

    let error = respond_rx.await.unwrap().expect_err("must fail");
    assert!(matches!(error, crate::error::Error::ChannelClosed));
    assert_eq!(h.stats().await.active_bans, 0);
    h.stop().await;
}

/// A manual unban while the ban is pending wins: the late firewall failure
/// must not roll back (double-decrement) state that was already unbanned.
#[tokio::test]
async fn test_manual_ban_stale_outcome_after_unban_leaves_state() {
    let mut h = spawn_tracker();
    let respond_rx = h.send_manual_ban(ip(6)).await;
    let ack = h.take_ban_ack().await;

    let (unban_tx, unban_rx) = oneshot::channel();
    h.cmd_tx
        .send(TrackerCmd::ManualUnban {
            ip: ip(6),
            jail_id: "sshd".to_string(),
            respond: unban_tx,
        })
        .await
        .unwrap();
    let FirewallCmd::Unban {
        done: Some(done), ..
    } = h.next_cmd().await
    else {
        panic!("expected unban")
    };
    done.send(Ok(())).unwrap();
    assert!(unban_rx.await.unwrap().is_ok());

    ack.send(Err(crate::error::Error::firewall("late")))
        .unwrap();
    assert!(respond_rx.await.unwrap().is_err());
    let stats = h.stats().await;
    assert_eq!(stats.active_bans, 0);
    assert_eq!(stats.total_bans, 1, "stale outcome must not roll back");
    assert_eq!(stats.total_unbans, 1);
    h.stop().await;
}

/// A manual ban targeting an unconfigured jail is rejected immediately, with
/// no executor command and no state recorded.
#[tokio::test]
async fn test_manual_ban_unknown_jail_rejected() {
    let mut h = spawn_tracker();
    let (respond, rx) = oneshot::channel();
    h.cmd_tx
        .send(TrackerCmd::ManualBan {
            ip: ip(8),
            jail_id: "no-such-jail".to_string(),
            ban_time: 3600,
            respond,
        })
        .await
        .unwrap();
    let error = rx
        .await
        .unwrap()
        .expect_err("unknown jail must be rejected");
    assert!(error.to_string().contains("unknown jail"), "{error}");
    assert!(
        h.executor_rx.try_recv().is_err(),
        "no firewall command must be issued for an unknown jail"
    );
    assert_eq!(h.stats().await.active_bans, 0);
    h.stop().await;
}

/// A second manual ban for an already-banned IP+jail is rejected without
/// touching the firewall or the existing ban.
#[tokio::test]
async fn test_manual_ban_already_banned_rejected() {
    let mut h = spawn_tracker();
    let respond_rx = h.send_manual_ban(ip(9)).await;
    h.take_ban_ack().await.send(Ok(())).unwrap();
    assert!(respond_rx.await.unwrap().is_ok());
    assert_eq!(h.stats().await.active_bans, 1);

    let (respond, rx) = oneshot::channel();
    h.cmd_tx
        .send(TrackerCmd::ManualBan {
            ip: ip(9),
            jail_id: "sshd".to_string(),
            ban_time: 3600,
            respond,
        })
        .await
        .unwrap();
    let error = rx
        .await
        .unwrap()
        .expect_err("re-banning an already-banned IP must be rejected");
    assert!(matches!(error, crate::error::Error::AlreadyBanned { .. }));
    assert!(
        h.executor_rx.try_recv().is_err(),
        "no second ban command must be issued"
    );
    assert_eq!(h.stats().await.active_bans, 1, "original ban is untouched");
    h.stop().await;
}

/// With the executor gone, a manual ban fails immediately and leaves no ban.
#[tokio::test]
async fn test_manual_ban_executor_closed_rolls_back() {
    let mut h = spawn_tracker();
    h.executor_rx.close();
    let respond_rx = h.send_manual_ban(ip(7)).await;
    let error = respond_rx.await.unwrap().expect_err("must fail");
    assert!(matches!(error, crate::error::Error::ChannelClosed));
    let stats = h.stats().await;
    assert_eq!((stats.active_bans, stats.total_bans), (0, 0));
    h.stop().await;
}

/// L1: a manual ban that times out after its IP was unbanned and re-banned is
/// stale, so it must not queue a compensating `Unban` — that would strip the
/// newer, valid ban from the firewall.
#[tokio::test]
async fn test_manual_ban_stale_timeout_after_reban_sends_no_unban() {
    let mut h = spawn_tracker();
    let first_rx = h.send_manual_ban(ip(10)).await;
    let _hung_ack = h.take_ban_ack().await; // never answered -> times out

    let (unban_tx, unban_rx) = oneshot::channel();
    h.cmd_tx
        .send(TrackerCmd::ManualUnban {
            ip: ip(10),
            jail_id: "sshd".to_string(),
            respond: unban_tx,
        })
        .await
        .unwrap();
    let FirewallCmd::Unban {
        done: Some(done), ..
    } = h.next_cmd().await
    else {
        panic!("expected unban")
    };
    done.send(Ok(())).unwrap();
    assert!(unban_rx.await.unwrap().is_ok());

    let second_rx = h.send_manual_ban(ip(10)).await;
    h.take_ban_ack().await.send(Ok(())).unwrap();
    assert!(second_rx.await.unwrap().is_ok(), "re-ban applied");

    let error = first_rx.await.unwrap().expect_err("first ban timed out");
    assert!(error.to_string().contains("did not apply ban"), "{error}");
    assert_eq!(h.stats().await.active_bans, 1, "re-ban must survive");
    assert!(
        h.executor_rx.try_recv().is_err(),
        "stale timeout must not queue an Unban"
    );
    h.stop().await;
}
