use super::*;

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use crate::error::{Error, Result};

/// How the mock answers [`FirewallBackend::snapshot`].
#[derive(Clone)]
enum Snap {
    /// `Ok(Some(set))` with these IPs present.
    Set(Vec<IpAddr>),
    /// `Ok(None)` — snapshots unsupported.
    Unsupported,
    /// `Err(..)` — the query failed.
    Fail,
    /// Deterministically oversized firewall listing.
    OutputLimit,
}

/// Configurable backend recording every call it receives.
struct ReconcileMock {
    calls: Arc<Mutex<Vec<String>>>,
    verify: bool,
    snap: Snap,
    /// IPs `is_banned` reports as present.
    present: Vec<IpAddr>,
}

impl ReconcileMock {
    fn new(verify: bool, snap: Snap, present: Vec<IpAddr>) -> (Self, Arc<Mutex<Vec<String>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mock = Self {
            calls: Arc::clone(&calls),
            verify,
            snap,
            present,
        };
        (mock, calls)
    }

    fn log(&self, entry: String) {
        self.calls.lock().expect("lock").push(entry);
    }
}

#[async_trait::async_trait]
impl FirewallBackend for ReconcileMock {
    async fn init(&self, _jail: &str, _ports: &[String], _protocol: &str) -> Result<()> {
        Ok(())
    }
    async fn teardown(&self, _jail: &str) -> Result<()> {
        Ok(())
    }
    async fn ban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        self.log(format!("ban:{ip}:{jail}"));
        Ok(())
    }
    async fn unban(&self, _ip: &IpAddr, _jail: &str) -> Result<()> {
        Ok(())
    }
    async fn is_banned(&self, ip: &IpAddr, jail: &str) -> Result<bool> {
        self.log(format!("is_banned:{ip}:{jail}"));
        Ok(self.present.contains(ip))
    }
    fn can_verify(&self) -> bool {
        self.verify
    }
    async fn snapshot(&self, jail: &str) -> Result<Option<HashSet<IpAddr>>> {
        self.log(format!("snapshot:{jail}"));
        match &self.snap {
            Snap::Set(ips) => Ok(Some(ips.iter().copied().collect())),
            Snap::Unsupported => Ok(None),
            Snap::Fail => Err(Error::firewall("snapshot failed")),
            Snap::OutputLimit => Err(Error::FirewallOutputLimit {
                label: "listing".to_string(),
                stream: "stdout",
                max_bytes: 16 * 1024 * 1024,
            }),
        }
    }
    fn name(&self) -> &'static str {
        "reconcile-mock"
    }
}

fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
}

fn record(last: u8, jail: &str) -> BanRecord {
    BanRecord {
        ip: ip(last),
        jail_id: jail.to_string(),
        banned_at: 0,
        expires_at: None,
    }
}

fn single(mock: ReconcileMock) -> HashMap<String, Box<dyn FirewallBackend>> {
    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert("sshd".to_string(), Box::new(mock));
    backends
}

fn take(calls: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    calls.lock().expect("lock").clone()
}

#[tokio::test]
async fn test_reconcile_can_verify_false_never_rebans() {
    let (mock, calls) = ReconcileMock::new(false, Snap::Set(vec![]), vec![]);
    let backends = single(mock);
    for _ in 0..3 {
        reconcile_bans(&backends, vec![record(1, "sshd"), record(2, "sshd")]).await;
    }
    assert!(
        take(&calls).is_empty(),
        "script-like backend must be untouched"
    );
}

#[tokio::test]
async fn test_reconcile_snapshot_reapplies_only_missing() {
    let (mock, calls) = ReconcileMock::new(true, Snap::Set(vec![ip(1)]), vec![]);
    let backends = single(mock);
    reconcile_bans(&backends, vec![record(1, "sshd"), record(2, "sshd")]).await;
    assert_eq!(take(&calls), ["snapshot:sshd", "ban:10.0.0.2:sshd"]);
}

#[tokio::test]
async fn test_reconcile_snapshot_called_once_per_jail() {
    let (mock, calls) = ReconcileMock::new(true, Snap::Set(vec![ip(1), ip(2), ip(3)]), vec![]);
    let backends = single(mock);
    let batch = vec![record(1, "sshd"), record(2, "sshd"), record(3, "sshd")];
    reconcile_bans(&backends, batch).await;
    assert_eq!(take(&calls), ["snapshot:sshd"]);
}

#[tokio::test]
async fn test_reconcile_snapshot_unsupported_falls_back_to_is_banned() {
    let (mock, calls) = ReconcileMock::new(true, Snap::Unsupported, vec![ip(1)]);
    let backends = single(mock);
    reconcile_bans(&backends, vec![record(1, "sshd"), record(2, "sshd")]).await;
    assert_eq!(
        take(&calls),
        [
            "snapshot:sshd",
            "is_banned:10.0.0.1:sshd",
            "is_banned:10.0.0.2:sshd",
            "ban:10.0.0.2:sshd",
        ]
    );
}

#[tokio::test]
async fn test_reconcile_snapshot_error_falls_back_to_is_banned() {
    let (mock, calls) = ReconcileMock::new(true, Snap::Fail, vec![]);
    let backends = single(mock);
    reconcile_bans(&backends, vec![record(4, "sshd")]).await;
    assert_eq!(
        take(&calls),
        [
            "snapshot:sshd",
            "is_banned:10.0.0.4:sshd",
            "ban:10.0.0.4:sshd"
        ]
    );
}

#[tokio::test]
async fn test_reconcile_mixed_jails_each_use_own_backend() {
    let (script, script_calls) = ReconcileMock::new(false, Snap::Unsupported, vec![]);
    let (nft, nft_calls) = ReconcileMock::new(true, Snap::Set(vec![]), vec![]);
    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert("script".to_string(), Box::new(script));
    backends.insert("nft".to_string(), Box::new(nft));
    let batch = vec![record(1, "script"), record(2, "nft"), record(3, "script")];
    reconcile_bans(&backends, batch).await;
    assert!(take(&script_calls).is_empty());
    assert_eq!(take(&nft_calls), ["snapshot:nft", "ban:10.0.0.2:nft"]);
}

/// A failed per-IP `is_banned` check must be treated as "present" — no re-ban
/// storm from a flaky query.
#[tokio::test]
async fn test_reconcile_is_banned_error_treated_as_present_no_reban() {
    struct FailingIsBanned {
        calls: Arc<Mutex<Vec<String>>>,
    }
    #[async_trait::async_trait]
    impl FirewallBackend for FailingIsBanned {
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
            Err(Error::firewall("query failed"))
        }
        fn can_verify(&self) -> bool {
            true
        }
        async fn snapshot(&self, _jail: &str) -> Result<Option<HashSet<IpAddr>>> {
            Ok(None)
        }
        fn name(&self) -> &'static str {
            "failing-is-banned"
        }
    }

    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert(
        "sshd".to_string(),
        Box::new(FailingIsBanned {
            calls: Arc::clone(&calls),
        }),
    );
    reconcile_bans(&backends, vec![record(1, "sshd")]).await;
    assert_eq!(
        take(&calls),
        ["is_banned:10.0.0.1:sshd"],
        "a failed check must not trigger a re-ban"
    );
}

/// A jail with no registered backend is skipped entirely, not panicked on.
#[tokio::test]
async fn test_reconcile_missing_backend_skips_jail() {
    let backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    // Must not panic despite there being no backend for "sshd".
    reconcile_bans(&backends, vec![record(1, "sshd"), record(2, "sshd")]).await;
}

/// A failed re-application (`ban_with_timeout` errors) must not be counted as
/// reapplied and must not panic the reconcile pass.
#[tokio::test]
async fn test_reconcile_reapply_failure_is_swallowed() {
    struct FailingBan;
    #[async_trait::async_trait]
    impl FirewallBackend for FailingBan {
        async fn init(&self, _jail: &str, _ports: &[String], _protocol: &str) -> Result<()> {
            Ok(())
        }
        async fn teardown(&self, _jail: &str) -> Result<()> {
            Ok(())
        }
        async fn ban(&self, _ip: &IpAddr, _jail: &str) -> Result<()> {
            Ok(())
        }
        async fn unban(&self, _ip: &IpAddr, _jail: &str) -> Result<()> {
            Ok(())
        }
        async fn is_banned(&self, _ip: &IpAddr, _jail: &str) -> Result<bool> {
            Ok(false)
        }
        fn can_verify(&self) -> bool {
            true
        }
        async fn snapshot(&self, _jail: &str) -> Result<Option<HashSet<IpAddr>>> {
            Ok(Some(HashSet::new()))
        }
        async fn ban_with_timeout(
            &self,
            _ip: &IpAddr,
            _jail: &str,
            _expires_at: Option<i64>,
            _now: i64,
        ) -> Result<()> {
            Err(Error::firewall("reapply failed"))
        }
        fn name(&self) -> &'static str {
            "failing-ban"
        }
    }
    let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
    backends.insert("sshd".to_string(), Box::new(FailingBan));
    // Must complete without panicking even though re-application fails.
    reconcile_bans(&backends, vec![record(1, "sshd")]).await;
}

#[test]
fn test_group_by_jail_preserves_order() {
    let bans = vec![record(1, "a"), record(2, "b"), record(3, "a")];
    let groups = group_by_jail(&bans);
    let shape: Vec<(&str, Vec<IpAddr>)> = groups
        .iter()
        .map(|(j, g)| (*j, g.iter().map(|b| b.ip).collect()))
        .collect();
    assert_eq!(shape, vec![("a", vec![ip(1), ip(3)]), ("b", vec![ip(2)])]);
}

#[tokio::test]
async fn test_reconcile_output_limit_does_not_repeat_listing_per_ip() {
    let (mock, calls) = ReconcileMock::new(true, Snap::OutputLimit, vec![]);
    let backends = single(mock);
    let bans = (1..=250).map(|last| record(last, "sshd")).collect();
    reconcile_bans(&backends, bans).await;
    assert_eq!(take(&calls), vec!["snapshot:sshd"]);
}
