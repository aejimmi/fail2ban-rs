use super::*;

use std::net::Ipv4Addr;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::track::test_support::{test_global_config, test_jail_config, test_store};

/// A tracker event loop driven directly, so its final state can be inspected.
struct LoopHarness {
    failure_tx: mpsc::Sender<Failure>,
    cmd_tx: mpsc::Sender<TrackerCmd>,
    cancel: CancellationToken,
    handle: JoinHandle<TrackerState>,
    _executor_rx: mpsc::Receiver<FirewallCmd>,
}

impl LoopHarness {
    /// Spawn `event_loop` for one `sshd` jail with a 1s find window.
    fn spawn() -> Self {
        let mut jail = test_jail_config();
        jail.max_retry = 2;
        jail.find_time = 1;
        let jails = HashMap::from([("sshd".to_string(), jail)]);
        let (failure_tx, failure_rx) = mpsc::channel(8);
        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        let (executor_tx, executor_rx) = mpsc::channel(8);
        let (resolve_tx, resolve_rx) = mpsc::channel(8);
        let (unban_outcome_tx, unban_rx) = mpsc::channel(8);
        let io = StateIo {
            executor_tx,
            reconcile: false,
            resolve_tx,
            unban_outcome_tx,
            store: test_store(),
            logger: None,
        };
        let state = init_state(&test_global_config(), &jails, io);
        let rx = TrackerRx {
            failure: failure_rx,
            cmd: cmd_rx,
            resolve: resolve_rx,
            unban: unban_rx,
        };
        let cancel = CancellationToken::new();
        let handle = tokio::spawn(event_loop(state, rx, cancel.clone()));
        Self {
            failure_tx,
            cmd_tx,
            cancel,
            handle,
            _executor_rx: executor_rx,
        }
    }

    /// Send a failure stamped two minutes in the past (outside the find window).
    async fn send_stale_failure(&self, octet: u8) {
        self.failure_tx
            .send(Failure {
                ip: Ipv4Addr::new(198, 51, 100, octet).into(),
                jail_id: "sshd".to_string(),
                timestamp: chrono::Utc::now().timestamp() - 120,
            })
            .await
            .unwrap();
    }

    /// Block until the tracker has consumed `expected` failures in total.
    async fn wait_for_failures(&self, expected: u64) {
        for _ in 0..100_000 {
            let (respond, ack) = oneshot::channel();
            self.cmd_tx
                .send(TrackerCmd::GetStats { respond })
                .await
                .unwrap();
            if ack.await.unwrap().total_failures >= expected {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("tracker never consumed {expected} failures");
    }

    /// Cancel the loop and return how many failure buffers it still held.
    async fn shutdown_failure_count(self) -> usize {
        self.cancel.cancel();
        self.handle.await.unwrap().failures.len()
    }
}

#[tokio::test(start_paused = true)]
async fn test_event_loop_continuous_failures_do_not_starve_sweep() {
    let h = LoopHarness::spawn();
    for octet in 1..=65u8 {
        h.send_stale_failure(octet).await;
        h.wait_for_failures(u64::from(octet)).await;
        // Each event re-arms the expiry sleep; only the fixed 60s sweep
        // interval can fire while time advances 1s per event.
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
    }
    let retained = h.shutdown_failure_count().await;
    // One sweep at t=60s prunes everything before it; at most the few
    // post-sweep entries remain.
    assert!(
        retained <= 6,
        "periodic sweep starved: {retained} stale failure buffers remain after 65s of continuous input"
    );
}

#[tokio::test(start_paused = true)]
async fn test_event_loop_idle_prunes_stale_failure() {
    let h = LoopHarness::spawn();
    h.send_stale_failure(1).await;
    h.wait_for_failures(1).await;
    tokio::time::advance(std::time::Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    // Round-trip a command so the sweep that fired is handled before shutdown.
    h.wait_for_failures(1).await;
    assert_eq!(h.shutdown_failure_count().await, 0);
}

#[tokio::test(start_paused = true)]
async fn test_event_loop_stale_failure_retained_before_sweep() {
    // Control for the tests above: without a sweep, the buffer is still held.
    let h = LoopHarness::spawn();
    h.send_stale_failure(1).await;
    h.wait_for_failures(1).await;
    assert_eq!(h.shutdown_failure_count().await, 1);
}
