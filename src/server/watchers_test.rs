use super::*;

use std::io::Write;
use std::path::Path;

use tempfile::TempDir;

use crate::server::reload::reload_config;
use crate::track::TrackerCmd;

/// Max wait for a watcher to surface an appended line (covers the 1s
/// missing-file retry plus the 250ms poll interval).
const RECV_TIMEOUT: Duration = Duration::from_secs(5);

/// Config with one enabled file-backed `sshd` jail tailing `log`.
fn file_jail_toml(log: &Path) -> String {
    format!(
        "[global]\n\n[jail.sshd]\nenabled = true\nfilter = ['from <HOST>']\n\
         log_path = \"{}\"\n",
        log.display()
    )
}

fn append_failure(log: &Path, last_octet: u8) {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .unwrap();
    writeln!(
        f,
        "Jan 15 10:30:00 host sshd[1]: Failed password for root from 10.9.8.{last_octet} port 22"
    )
    .unwrap();
    f.flush().unwrap();
}

/// IP of the priming lines [`spawn_live`] writes; ignored by the receivers
/// since a slow first poll can surface extra copies.
const PRIME_IP: &str = "10.9.8.1";

/// Receive the next non-priming failure or panic after [`RECV_TIMEOUT`].
async fn recv_ip(rx: &mut mpsc::Receiver<Failure>) -> String {
    loop {
        let failure = tokio::time::timeout(RECV_TIMEOUT, rx.recv())
            .await
            .expect("timed out waiting for failure")
            .expect("failure channel closed");
        let ip = failure.ip.to_string();
        if ip != PRIME_IP {
            return ip;
        }
    }
}

/// Collect every non-priming failure that arrives within `window` of the last.
async fn drain_for(rx: &mut mpsc::Receiver<Failure>, window: Duration) -> Vec<String> {
    let mut seen = Vec::new();
    while let Ok(Some(f)) = tokio::time::timeout(window, rx.recv()).await {
        let ip = f.ip.to_string();
        if ip != PRIME_IP {
            seen.push(ip);
        }
    }
    seen
}

/// Spawn watchers for `config`, then append priming lines until one is
/// observed — proof the watcher is live and tailing past its start point.
async fn spawn_live(
    config: &Config,
    log: &Path,
    failure_tx: &mpsc::Sender<Failure>,
    rx: &mut mpsc::Receiver<Failure>,
) -> Watchers {
    let plan = build_watcher_plan(config).unwrap();
    let watchers = Watchers::spawn(plan, failure_tx, "startup", HashMap::new());
    for _ in 0..20 {
        append_failure(log, 1);
        if let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(600), rx.recv()).await {
            return watchers;
        }
    }
    panic!("watcher never became live");
}

/// Tracker stub that acks a forwarded `ReplaceJail` — appending
/// `append_octet` to `log` first, i.e. while the reload is in flight — and
/// ignores everything else.
fn spawn_appending_tracker(
    mut rx: mpsc::Receiver<TrackerCmd>,
    log: std::path::PathBuf,
    append_octet: u8,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            if let TrackerCmd::UpdateConfig { respond, .. } = cmd {
                let _ = respond.send(());
                continue;
            }
            let TrackerCmd::ForwardFirewall { build, .. } = cmd else {
                continue;
            };
            append_failure(&log, append_octet);
            match build(Vec::new()) {
                crate::enforce::FirewallCmd::ReplaceJail { done, .. } => done.send(Ok(())).unwrap(),
                other => panic!("unexpected firewall command: {other:?}"),
            }
        }
    })
}

#[tokio::test]
async fn test_watchers_stop_default_is_empty() {
    let mut watchers = Watchers::default();
    assert!(watchers.stop().await.is_empty());
}

/// A watcher task that panics must not panic `stop()` itself, and its jail's
/// position is simply omitted so the replacement restarts from default.
#[tokio::test]
async fn test_watchers_stop_omits_position_when_watcher_panics() {
    let cancel = CancellationToken::new();
    let handle: JoinHandle<Option<ResumePoint>> = tokio::spawn(async {
        panic!("simulated watcher crash");
    });
    // Give the task a chance to actually panic before stop() joins it.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut watchers = Watchers {
        cancel,
        handles: vec![("crashed".to_string(), handle)],
    };
    let points = watchers.stop().await;
    assert!(
        points.is_empty(),
        "a panicked watcher must not report a resume point"
    );
}

/// A watcher that never returns any position (e.g. reader failed before
/// determining one) still lets `stop()` complete cleanly with no entry for
/// its jail.
#[tokio::test]
async fn test_watchers_stop_omits_position_when_watcher_returns_none() {
    let cancel = CancellationToken::new();
    let handle: JoinHandle<Option<ResumePoint>> = tokio::spawn(async { None });
    let mut watchers = Watchers {
        cancel,
        handles: vec![("no-position".to_string(), handle)],
    };
    let points = watchers.stop().await;
    assert!(points.is_empty());
}

#[tokio::test]
async fn test_watchers_stop_returns_file_resume_point() {
    let dir = TempDir::new().unwrap();
    let log = dir.path().join("auth.log");
    let config = Config::parse(&file_jail_toml(&log)).unwrap();
    let (failure_tx, mut rx) = mpsc::channel(16);
    let mut watchers = spawn_live(&config, &log, &failure_tx, &mut rx).await;

    let points = watchers.stop().await;
    assert!(
        points.contains_key("sshd"),
        "file jail must report a position"
    );
    assert!(watchers.stop().await.is_empty(), "handles are drained");
}

/// A line appended while no watcher is running (the handoff gap) is read
/// exactly once by the replacement, and already-read lines are not replayed.
#[tokio::test]
async fn test_watchers_handoff_gap_line_observed_once() {
    let dir = TempDir::new().unwrap();
    let log = dir.path().join("auth.log");
    let config = Config::parse(&file_jail_toml(&log)).unwrap();
    let (failure_tx, mut rx) = mpsc::channel(16);
    let mut watchers = spawn_live(&config, &log, &failure_tx, &mut rx).await;

    let resume = watchers.stop().await;
    append_failure(&log, 2);
    let plan = build_watcher_plan(&config).unwrap();
    let mut watchers = Watchers::spawn(plan, &failure_tx, "reload", resume);

    assert_eq!(recv_ip(&mut rx).await, "10.9.8.2");
    assert!(
        drain_for(&mut rx, Duration::from_millis(600))
            .await
            .is_empty()
    );
    watchers.stop().await;
}

/// Server-level: a failure appended while `reload_config` is in flight is
/// delivered exactly once — whichever of the old or new watcher reads it.
#[tokio::test]
async fn test_reload_config_failure_during_reload_observed_once() {
    let dir = TempDir::new().unwrap();
    let log = dir.path().join("auth.log");
    let config_path = dir.path().join("fail2ban-rs.toml");
    // A port change makes the reload replace the jail's firewall, which the
    // tracker stub sees mid-reload (before the watchers are swapped).
    let changed = format!("{}port = [\"2222\"]\n", file_jail_toml(&log));
    std::fs::write(&config_path, changed).unwrap();
    let mut config = Config::parse(&file_jail_toml(&log)).unwrap();
    let (failure_tx, mut rx) = mpsc::channel(16);
    let mut watchers = spawn_live(&config, &log, &failure_tx, &mut rx).await;

    let (executor_tx, _executor_rx) = mpsc::channel(4);
    let (tracker_tx, tracker_rx) = mpsc::channel(8);
    let tracker = spawn_appending_tracker(tracker_rx, log.clone(), 3);
    reload_config(
        &config_path,
        &executor_tx,
        &tracker_tx,
        &mut config,
        &mut watchers,
        &failure_tx,
        None,
    )
    .await
    .expect("reload should succeed");
    append_failure(&log, 4);

    let seen = drain_for(&mut rx, Duration::from_millis(1500)).await;
    assert_eq!(seen, ["10.9.8.3", "10.9.8.4"]);
    watchers.stop().await;
    drop(tracker_tx);
    tracker.await.unwrap();
}

/// A reload that fails before touching the watchers (bad config) leaves the
/// old watchers running.
#[tokio::test]
async fn test_reload_config_parse_error_keeps_watchers_running() {
    let dir = TempDir::new().unwrap();
    let log = dir.path().join("auth.log");
    let config_path = dir.path().join("fail2ban-rs.toml");
    std::fs::write(&config_path, "not = [valid toml").unwrap();
    let mut config = Config::parse(&file_jail_toml(&log)).unwrap();
    let (failure_tx, mut rx) = mpsc::channel(16);
    let mut watchers = spawn_live(&config, &log, &failure_tx, &mut rx).await;

    let (executor_tx, _executor_rx) = mpsc::channel(4);
    let (tracker_tx, _tracker_rx) = mpsc::channel(8);
    let result = reload_config(
        &config_path,
        &executor_tx,
        &tracker_tx,
        &mut config,
        &mut watchers,
        &failure_tx,
        None,
    )
    .await;
    assert!(result.is_err());

    append_failure(&log, 5);
    assert_eq!(recv_ip(&mut rx).await, "10.9.8.5");
    assert!(watchers.stop().await.contains_key("sshd"));
}
