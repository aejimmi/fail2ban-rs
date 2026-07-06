//! End-to-end tests exercising the tracker's public API directly: writing log
//! lines through a watcher, driving the tracker with real `TrackerCmd`s, and
//! reading the `FirewallCmd`s it emits from the executor channel. No firewall
//! backend is ever constructed here — the executor stage is replaced by the
//! test reading `FirewallCmd` values straight off the channel, so nothing
//! requires root permissions.

use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use etchdb::Store;
use tempfile::NamedTempFile;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use fail2ban_rs::config::{GlobalConfig, JailConfig};
use fail2ban_rs::detect::date::{DateFormat, DateParser};
use fail2ban_rs::detect::ignore::IgnoreList;
use fail2ban_rs::detect::matcher::JailMatcher;
use fail2ban_rs::detect::watcher::{self, Failure};
use fail2ban_rs::enforce::{self, FirewallBackend, FirewallCmd};
use fail2ban_rs::error::Result;
use fail2ban_rs::track::circular::CircularTimestamps;
use fail2ban_rs::track::persist::BanState;
use fail2ban_rs::track::state::BanRecord;
use fail2ban_rs::track::{self, TrackerCmd};

fn test_store() -> Arc<Store<BanState, etchdb::WalBackend<BanState>>> {
    let dir = tempfile::tempdir().expect("failed to create tempdir");
    let path = dir.path().to_path_buf();
    std::mem::forget(dir); // keep the tempdir alive
    let store = Store::<BanState, etchdb::WalBackend<BanState>>::open_wal(path)
        .expect("failed to open WAL store");
    Arc::new(store)
}

fn test_global_config() -> GlobalConfig {
    GlobalConfig::default()
}

/// Full pipeline: watcher → tracker → verify ban command.
#[tokio::test]
async fn watcher_to_tracker_ban() {
    let mut tmpfile = NamedTempFile::new().unwrap();
    let log_path = tmpfile.path().to_path_buf();

    // Channels.
    let (failure_tx, failure_rx) = mpsc::channel::<Failure>(64);
    let (executor_tx, mut executor_rx) = mpsc::channel::<FirewallCmd>(64);
    let cancel = CancellationToken::new();

    // Jail config: ban after 3 failures in 600s.
    let jail_config = JailConfig {
        enabled: true,
        log_path: log_path.clone(),
        date_format: DateFormat::Syslog,
        filter: vec![r"sshd\[\d+\]: Failed password for .* from <HOST>".to_string()],
        max_retry: 3,
        find_time: 600,
        ban_time: 60,
        port: vec![],
        protocol: "tcp".to_string(),
        bantime_increment: false,
        bantime_factor: 1.0,
        bantime_multipliers: vec![],
        bantime_maxtime: 604_800,
        backend: fail2ban_rs::config::Backend::Nftables,
        log_backend: fail2ban_rs::config::LogBackend::default(),
        journalmatch: vec![],
        ignoreregex: vec![],
        ignoreip: vec![],
        ignoreself: false,
        reban_on_restart: true,
        webhook: None,
        ..JailConfig::default()
    };

    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), jail_config.clone());

    // Spawn tracker.
    let (_cmd_tx, cmd_rx) = mpsc::channel::<TrackerCmd>(16);
    let tracker_cancel = cancel.child_token();
    tokio::spawn(async move {
        track::run(
            test_global_config(),
            jails,
            failure_rx,
            cmd_rx,
            executor_tx,
            None,
            vec![],
            std::collections::HashMap::new(),
            test_store(),
            None,
            tracker_cancel,
        )
        .await;
    });

    // Spawn watcher.
    let matcher = JailMatcher::new(&jail_config.filter).unwrap();
    let date_parser = DateParser::new(DateFormat::Syslog).unwrap();
    let ignore_list = IgnoreList::new(&[], false).unwrap();
    let watcher_cancel = cancel.child_token();

    tokio::spawn(async move {
        watcher::run(
            "sshd".to_string(),
            log_path,
            matcher,
            date_parser,
            ignore_list,
            failure_tx,
            watcher_cancel,
            "startup",
        )
        .await;
    });

    // Give watcher time to start.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Write 3 failure lines (enough to trigger ban).
    for i in 1..=3 {
        writeln!(
            tmpfile,
            "Jan 15 10:30:0{i} server sshd[123{i}]: Failed password for root from 192.168.1.100 port 22 ssh2"
        )
        .unwrap();
    }
    tmpfile.flush().unwrap();

    // Wait for ban command.
    let cmd = tokio::time::timeout(std::time::Duration::from_secs(5), executor_rx.recv())
        .await
        .expect("timeout waiting for ban command")
        .expect("channel closed");

    match cmd {
        FirewallCmd::Ban { ip, jail_id, .. } => {
            assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
            assert_eq!(jail_id, "sshd");
        }
        #[allow(clippy::panic)]
        other => panic!("expected Ban command, got: {other:?}"),
    }

    cancel.cancel();
}

/// Circular buffer threshold check.
#[test]
fn circular_threshold() {
    let mut buf = CircularTimestamps::new(5);
    for i in 0..5 {
        buf.push(1000 + i * 10);
    }
    assert!(buf.threshold_reached(600));
    assert!(!buf.threshold_reached(30));
}

/// Matcher extracts correct IP from SSH log.
#[test]
fn matcher_ssh_log() {
    let matcher = JailMatcher::new(&[
        r"sshd\[\d+\]: Failed password for .* from <HOST>".to_string(),
        r"sshd\[\d+\]: Invalid user .* from <HOST>".to_string(),
    ])
    .unwrap();

    let line = "Jan 15 10:30:01 server sshd[1235]: Failed password for root from 192.168.1.100 port 22 ssh2";
    let result = matcher.try_match(line).unwrap();
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
    assert_eq!(result.pattern_idx, 0);

    let line2 =
        "Jan 15 10:30:05 server sshd[1238]: Invalid user admin from 10.20.30.40 port 22 ssh2";
    let result2 = matcher.try_match(line2).unwrap();
    assert_eq!(result2.ip, IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)));
    assert_eq!(result2.pattern_idx, 1);
}

/// A [`FirewallBackend`] that records every call it receives, in order, for
/// assertion. Used to verify call *ordering* — something a firewall-command
/// enum alone (as read straight off the executor channel) cannot show for
/// calls that happen before the executor task even exists, e.g. startup
/// restore, which calls backend methods directly.
struct RecordingBackend {
    calls: Arc<Mutex<Vec<String>>>,
}

impl RecordingBackend {
    fn record(&self, entry: String) {
        self.calls
            .lock()
            .expect("recording backend mutex poisoned")
            .push(entry);
    }
}

#[async_trait::async_trait]
impl FirewallBackend for RecordingBackend {
    async fn init(&self, jail: &str, _ports: &[String], _protocol: &str) -> Result<()> {
        self.record(format!("init:{jail}"));
        Ok(())
    }

    async fn teardown(&self, jail: &str) -> Result<()> {
        self.record(format!("teardown:{jail}"));
        Ok(())
    }

    async fn ban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        self.record(format!("ban:{ip}:{jail}"));
        Ok(())
    }

    async fn unban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        self.record(format!("unban:{ip}:{jail}"));
        Ok(())
    }

    async fn is_banned(&self, _ip: &IpAddr, _jail: &str) -> Result<bool> {
        Ok(false)
    }

    fn name(&self) -> &'static str {
        "recording"
    }
}

/// A minimal enabled jail config accepting restored bans on restart.
fn restore_jail_config() -> JailConfig {
    JailConfig {
        enabled: true,
        filter: vec!["from <HOST>".to_string()],
        reban_on_restart: true,
        ..JailConfig::default()
    }
}

/// Regression test (worst bug found this session): on a clean restart, the
/// firewall backend for a jail MUST be initialized (chain/set created)
/// before any previously-persisted ban is re-applied against it. Ordered the
/// other way round, a restored ban silently targets a chain/set that does
/// not exist yet and is dropped by the kernel.
///
/// This drives the same public seam the daemon's startup path uses
/// (`enforce::init_and_restore`) against a real, external [`FirewallBackend`]
/// impl rather than a private in-crate mock, so it also guards against the
/// seam's ordering guarantee being weakened in a way that only breaks
/// external implementors.
#[tokio::test]
async fn restart_restore_inits_backend_before_reapplying_ban() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let backend: Box<dyn FirewallBackend> = Box::new(RecordingBackend {
        calls: Arc::clone(&calls),
    });
    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert("sshd".to_string(), backend);

    let mut jail_configs = HashMap::new();
    jail_configs.insert("sshd".to_string(), restore_jail_config());

    let now = chrono::Utc::now().timestamp();
    let persisted_bans = vec![BanRecord {
        ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
        jail_id: "sshd".to_string(),
        banned_at: now - 3600,
        expires_at: Some(now + 3600), // still active
    }];

    let restored = enforce::init_and_restore(&persisted_bans, &backends, now, &jail_configs)
        .await
        .expect("init_and_restore should succeed");
    assert_eq!(restored.len(), 1, "the unexpired ban must be restored");

    let calls = calls.lock().expect("recording backend mutex poisoned");
    let init_idx = calls
        .iter()
        .position(|c| c.starts_with("init:"))
        .expect("init must have been called");
    let ban_idx = calls
        .iter()
        .position(|c| c.starts_with("ban:"))
        .expect("ban must have been called");
    assert!(
        init_idx < ban_idx,
        "backend init must precede the restored ban being re-applied, got calls: {calls:?}"
    );
}

/// Await a `FirewallCmd` matching `pred` within `timeout`, discarding any
/// other commands seen along the way (mirrors polling loops elsewhere in the
/// test suite for expiry, since expiry is driven by the real wall clock and
/// cannot be fast-forwarded with `tokio::time::pause`).
async fn wait_for_cmd(
    executor_rx: &mut mpsc::Receiver<FirewallCmd>,
    timeout: std::time::Duration,
    mut pred: impl FnMut(&FirewallCmd) -> bool,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(std::time::Duration::from_millis(200), executor_rx.recv()).await
        {
            Ok(Some(cmd)) if pred(&cmd) => return true,
            Ok(Some(_)) => {} // not the command we're waiting for; keep polling
            Ok(None) => return false,
            Err(_) => {} // recv timed out this iteration; keep polling
        }
    }
    false
}

/// A manually-banned IP with a short ban time must still be unbanned
/// automatically once it expires — the periodic sweep does not distinguish
/// manual bans from automatic ones, but that path has coverage for automatic
/// bans only elsewhere; this exercises the manual-ban code path
/// (`TrackerCmd::ManualBan`) through the same expiry sweep.
#[tokio::test]
async fn manual_ban_with_short_ban_time_is_unbanned_after_expiry() {
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), restore_jail_config());

    let (_failure_tx, failure_rx) = mpsc::channel::<Failure>(16);
    let (executor_tx, mut executor_rx) = mpsc::channel::<FirewallCmd>(64);
    let (cmd_tx, cmd_rx) = mpsc::channel::<TrackerCmd>(16);
    let cancel = CancellationToken::new();

    let dir = tempfile::tempdir().unwrap();
    let store = Store::<BanState, etchdb::WalBackend<BanState>>::open_wal(dir.path().to_path_buf())
        .unwrap();

    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move {
        track::run(
            GlobalConfig::default(),
            jails,
            failure_rx,
            cmd_rx,
            executor_tx,
            None,
            vec![],
            HashMap::new(),
            Arc::new(store),
            None,
            cancel_clone,
        )
        .await;
    });

    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 88));
    let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrackerCmd::ManualBan {
            ip,
            jail_id: "sshd".to_string(),
            ban_time: 1, // seconds
            respond: respond_tx,
        })
        .await
        .unwrap();
    respond_rx
        .await
        .unwrap()
        .expect("manual ban should be accepted");

    let got_ban = wait_for_cmd(
        &mut executor_rx,
        std::time::Duration::from_secs(2),
        |cmd| matches!(cmd, FirewallCmd::Ban { jail_id, .. } if jail_id == "sshd"),
    )
    .await;
    assert!(got_ban, "manual ban must emit a FirewallCmd::Ban");

    let got_unban = wait_for_cmd(
        &mut executor_rx,
        std::time::Duration::from_secs(4),
        |cmd| matches!(cmd, FirewallCmd::Unban { ip: unbanned, jail_id } if *unbanned == ip && jail_id == "sshd"),
    )
    .await;
    assert!(
        got_unban,
        "a manually-banned IP with an expired ban_time must be unbanned by the sweep"
    );

    cancel.cancel();
    handle.await.unwrap();
}
