//! Tests for the executor using a mock backend.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use std::net::Ipv6Addr;

use crate::error::{Error, Result};
use crate::executor::{self, FirewallBackend, FirewallCmd, create_backend};
use crate::state::{BanRecord, StateSnapshot};

/// Records all ban/unban calls for assertion.
struct MockBackend {
    calls: Arc<Mutex<Vec<String>>>,
}

impl MockBackend {
    fn new() -> (Self, Arc<Mutex<Vec<String>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                calls: Arc::clone(&calls),
            },
            calls,
        )
    }
}

#[async_trait::async_trait]
impl FirewallBackend for MockBackend {
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

    async fn is_banned(&self, _ip: &IpAddr, _jail: &str) -> Result<bool> {
        Ok(false)
    }

    fn name(&self) -> &str {
        "mock"
    }
}

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

#[tokio::test]
async fn ban_and_unban_order() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let backends = mock_backends(Arc::clone(&calls));
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();

    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("state.bin");

    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move {
        executor::run(rx, backends, state_path, cancel_clone).await;
    });

    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

    tx.send(FirewallCmd::Ban {
        ip,
        jail_id: "sshd".to_string(),
        banned_at: 1000,
        expires_at: Some(2000),
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

#[tokio::test]
async fn save_state_command() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let backends = mock_backends(Arc::clone(&calls));
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();

    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("state.bin");

    let cancel_clone = cancel.clone();
    let sp = state_path.clone();
    let handle = tokio::spawn(async move {
        executor::run(rx, backends, sp, cancel_clone).await;
    });

    let snapshot = StateSnapshot {
        bans: vec![],
        ban_counts: vec![],
        snapshot_time: 1000,
    };
    tx.send(FirewallCmd::SaveState { snapshot }).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    cancel.cancel();
    handle.await.unwrap();

    // Verify state file was written.
    assert!(state_path.exists());
}

/// Mock backend that always fails on ban.
struct FailingMockBackend;

#[async_trait::async_trait]
impl FirewallBackend for FailingMockBackend {
    async fn init(&self, _jail: &str, _ports: &[String], _protocol: &str) -> Result<()> {
        Ok(())
    }
    async fn teardown(&self, _jail: &str) -> Result<()> {
        Ok(())
    }
    async fn ban(&self, _ip: &IpAddr, _jail: &str) -> Result<()> {
        Err(Error::firewall("mock failure"))
    }
    async fn unban(&self, _ip: &IpAddr, _jail: &str) -> Result<()> {
        Err(Error::firewall("mock failure"))
    }
    async fn is_banned(&self, _ip: &IpAddr, _jail: &str) -> Result<bool> {
        Ok(false)
    }
    fn name(&self) -> &str {
        "failing-mock"
    }
}

#[tokio::test]
async fn restore_bans_skips_expired() {
    let (backend, calls) = MockBackend::new();
    let now = chrono::Utc::now().timestamp();

    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert("sshd".to_string(), Box::new(backend));

    let bans = vec![
        BanRecord {
            ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            jail_id: "sshd".to_string(),
            banned_at: now - 7200,
            expires_at: Some(now - 3600), // expired 1 hour ago
        },
        BanRecord {
            ip: IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            jail_id: "sshd".to_string(),
            banned_at: now - 1800,
            expires_at: Some(now + 1800), // still active
        },
    ];

    let restored = executor::restore_bans(&bans, &backends, now).await;

    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].ip, IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)));

    let calls = calls.lock().expect("lock");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0], "ban:2.2.2.2:sshd");
}

#[tokio::test]
async fn restore_bans_keeps_permanent() {
    let (backend, calls) = MockBackend::new();
    let now = chrono::Utc::now().timestamp();

    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert("sshd".to_string(), Box::new(backend));

    let bans = vec![BanRecord {
        ip: IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3)),
        jail_id: "sshd".to_string(),
        banned_at: now - 86400,
        expires_at: None, // permanent
    }];

    let restored = executor::restore_bans(&bans, &backends, now).await;
    assert_eq!(restored.len(), 1);

    let calls = calls.lock().expect("lock");
    assert_eq!(calls[0], "ban:3.3.3.3:sshd");
}

#[tokio::test]
async fn restore_bans_empty() {
    let backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    let now = chrono::Utc::now().timestamp();

    let restored = executor::restore_bans(&[], &backends, now).await;
    assert!(restored.is_empty());
}

#[tokio::test]
async fn restore_bans_skips_on_backend_error() {
    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert("sshd".to_string(), Box::new(FailingMockBackend));
    let now = chrono::Utc::now().timestamp();

    let bans = vec![BanRecord {
        ip: IpAddr::V4(Ipv4Addr::new(4, 4, 4, 4)),
        jail_id: "sshd".to_string(),
        banned_at: now,
        expires_at: Some(now + 3600),
    }];

    let restored = executor::restore_bans(&bans, &backends, now).await;
    assert!(restored.is_empty(), "should skip on backend error");
}

#[tokio::test]
async fn executor_channel_closed_stops() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let backends = mock_backends(Arc::clone(&calls));
    let (tx, rx) = mpsc::channel::<FirewallCmd>(16);
    let cancel = CancellationToken::new();

    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("state.bin");

    let handle = tokio::spawn(async move {
        executor::run(rx, backends, state_path, cancel).await;
    });

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
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("state.bin");

    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move {
        executor::run(rx, backends, state_path, cancel_clone).await;
    });

    let ip1 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));

    tx.send(FirewallCmd::Ban {
        ip: ip1,
        jail_id: "sshd".to_string(),
        banned_at: 1000,
        expires_at: Some(2000),
    })
    .await
    .unwrap();

    tx.send(FirewallCmd::Ban {
        ip: ip2,
        jail_id: "nginx".to_string(),
        banned_at: 1000,
        expires_at: Some(2000),
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

#[test]
fn create_backend_nftables() {
    match create_backend(&crate::config::Backend::Nftables) {
        Ok(backend) => assert_eq!(backend.name(), "nftables"),
        Err(_) => {
            // Binary not found on this system (e.g. macOS); skip.
        }
    }
}

#[test]
fn create_backend_iptables() {
    match create_backend(&crate::config::Backend::Iptables) {
        Ok(backend) => assert_eq!(backend.name(), "iptables"),
        Err(_) => {
            // Binaries not found on this system (e.g. macOS); skip.
        }
    }
}

#[test]
fn create_backend_script() {
    let backend = create_backend(&crate::config::Backend::Script {
        ban_cmd: "echo ban <IP>".to_string(),
        unban_cmd: "echo unban <IP>".to_string(),
    })
    .expect("script backend should always succeed");
    assert_eq!(backend.name(), "script");
}

#[test]
fn script_substitute() {
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let template = "echo ban <IP> in <JAIL>";
    let result = template
        .replace("<IP>", &ip.to_string())
        .replace("<JAIL>", "sshd");
    assert_eq!(result, "echo ban 1.2.3.4 in sshd");
}

#[test]
fn script_substitute_no_placeholders() {
    let template = "echo hello world";
    let result = template
        .replace("<IP>", "1.2.3.4")
        .replace("<JAIL>", "sshd");
    assert_eq!(result, "echo hello world");
}

#[test]
fn script_substitute_multiple_occurrences() {
    let template = "<IP> <IP> <JAIL> <JAIL>";
    let result = template
        .replace("<IP>", "10.0.0.1")
        .replace("<JAIL>", "ssh");
    assert_eq!(result, "10.0.0.1 10.0.0.1 ssh ssh");
}

#[test]
fn script_substitute_ipv6() {
    let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let template = "ban <IP> jail <JAIL>";
    let result = template
        .replace("<IP>", &ip.to_string())
        .replace("<JAIL>", "sshd");
    assert_eq!(result, "ban 2001:db8::1 jail sshd");
}
