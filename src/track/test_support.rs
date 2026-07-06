//! Shared test helpers for the tracker integration tests.

use std::net::IpAddr;
use std::sync::Arc;

use etchdb::Store;
use tokio::sync::mpsc;

use crate::config::JailConfig;
use crate::enforce::FirewallCmd;
use crate::track::TrackerCmd;
use crate::track::persist::BanState;

/// A baseline jail config: 3 failures within 600s → 60s ban.
pub(crate) fn test_jail_config() -> JailConfig {
    JailConfig {
        enabled: true,
        log_path: "/tmp/test.log".into(),
        date_format: crate::detect::date::DateFormat::Syslog,
        filter: vec!["from <HOST>".to_string()],
        max_retry: 3,
        find_time: 600,
        ban_time: 60,
        ignoreself: false,
        maxmind: vec![
            crate::config::MaxmindField::Asn,
            crate::config::MaxmindField::Country,
            crate::config::MaxmindField::City,
        ],
        ..JailConfig::default()
    }
}

/// A WAL-backed store in a throwaway temp dir kept alive for the test's lifetime.
pub(crate) fn test_store() -> Arc<Store<BanState, etchdb::WalBackend<BanState>>> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    std::mem::forget(dir); // keep the tempdir alive
    let store = Store::<BanState, etchdb::WalBackend<BanState>>::open_wal(path).unwrap();
    Arc::new(store)
}

/// A global config pointing at the bundled MaxMind test fixtures.
pub(crate) fn test_global_config() -> crate::config::GlobalConfig {
    crate::config::GlobalConfig {
        state_dir: std::path::PathBuf::from("/tmp/state"),
        socket_path: std::path::PathBuf::from("/tmp/sock"),
        channel_size: 1024,
        ban_count_decay: 2_592_000,
        maxmind_asn: Some(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/GeoLite2-ASN-Test.mmdb"),
        ),
        maxmind_country: Some(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/GeoLite2-Country-Test.mmdb"),
        ),
        maxmind_city: Some(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/GeoLite2-City-Test.mmdb"),
        ),
    }
}

/// Send a `ManualBan` command for the `sshd` jail and assert it succeeds.
pub(crate) async fn manual_ban(cmd_tx: &mpsc::Sender<TrackerCmd>, ip: IpAddr, ban_time: i64) {
    let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrackerCmd::ManualBan {
            ip,
            jail_id: "sshd".to_string(),
            ban_time,
            respond: respond_tx,
        })
        .await
        .unwrap();
    assert!(respond_rx.await.unwrap().is_ok());
}

/// Send a `ManualUnban` command for the `sshd` jail and assert it succeeds.
pub(crate) async fn manual_unban(cmd_tx: &mpsc::Sender<TrackerCmd>, ip: IpAddr) {
    let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrackerCmd::ManualUnban {
            ip,
            jail_id: "sshd".to_string(),
            respond: respond_tx,
        })
        .await
        .unwrap();
    assert!(respond_rx.await.unwrap().is_ok());
}

/// Await a `Ban` command and return its `expires_at - banned_at` span.
pub(crate) async fn expect_ban(executor_rx: &mut mpsc::Receiver<FirewallCmd>) -> i64 {
    // Generous timeout: parallel test runs on a loaded machine can starve tasks.
    let cmd = tokio::time::timeout(std::time::Duration::from_secs(30), executor_rx.recv())
        .await
        .expect("timeout waiting for ban")
        .expect("channel closed");
    match cmd {
        FirewallCmd::Ban {
            banned_at,
            expires_at,
            ..
        } => expires_at.expect("expected a finite ban") - banned_at,
        other => panic!("expected Ban, got: {other:?}"),
    }
}
