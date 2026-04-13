//! Enforcement — receives firewall commands and executes them.
//!
//! Owns the firewall backends (one per jail). Runs as a single tokio task,
//! reading commands from a bounded mpsc channel.

/// iptables firewall backend.
pub mod iptables;
/// nftables firewall backend.
pub mod nftables;
/// Script-based firewall backend.
pub mod script;

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::config::{Backend, JailConfig};
use crate::enforce::iptables::IptablesBackend;
use crate::enforce::nftables::NftablesBackend;
use crate::enforce::script::ScriptBackend;
use crate::error::{Error, Result};
use crate::track::state::BanRecord;

/// Commands sent to the executor task.
#[derive(Debug)]
pub enum FirewallCmd {
    /// Ban an IP in the firewall.
    Ban {
        ip: IpAddr,
        jail_id: String,
        banned_at: i64,
        expires_at: Option<i64>,
        done: Option<oneshot::Sender<Result<()>>>,
    },
    /// Unban an IP in the firewall.
    Unban { ip: IpAddr, jail_id: String },
    /// Initialize firewall rules for a jail.
    InitJail {
        jail_id: String,
        ports: Vec<String>,
        protocol: String,
        done: oneshot::Sender<Result<()>>,
    },
    /// Tear down firewall rules for a jail.
    TeardownJail {
        jail_id: String,
        done: oneshot::Sender<Result<()>>,
    },
}

/// Trait for firewall backend implementations.
#[async_trait::async_trait]
pub trait FirewallBackend: Send + Sync {
    /// Initialize firewall rules for a jail (create chains/sets).
    async fn init(&self, jail: &str, ports: &[String], protocol: &str) -> Result<()>;

    /// Tear down firewall rules for a jail (remove chains/sets).
    async fn teardown(&self, jail: &str) -> Result<()>;

    /// Ban an IP address.
    async fn ban(&self, ip: &IpAddr, jail: &str) -> Result<()>;

    /// Remove a ban for an IP address.
    async fn unban(&self, ip: &IpAddr, jail: &str) -> Result<()>;

    /// Check if an IP is currently banned in the firewall.
    async fn is_banned(&self, ip: &IpAddr, jail: &str) -> Result<bool>;

    /// Backend name for logging.
    fn name(&self) -> &'static str;
}

/// Known system directories to search for firewall binaries.
const SYSTEM_DIRS: &[&str] = &["/usr/sbin", "/sbin", "/usr/bin", "/bin"];

/// Resolve a binary name to an absolute path in known system directories.
///
/// Searches `/usr/sbin`, `/sbin`, `/usr/bin`, `/bin` in order, returning
/// the first path where the file exists. Fails early if the binary is not
/// found, preventing PATH-based resolution at runtime.
pub fn resolve_binary(name: &str) -> Result<PathBuf> {
    for dir in SYSTEM_DIRS {
        let path = Path::new(dir).join(name);
        if path.exists() {
            return Ok(path);
        }
    }
    Err(Error::firewall(format!(
        "binary '{name}' not found in {}",
        SYSTEM_DIRS.join(", ")
    )))
}

/// Create the appropriate firewall backend from config.
pub fn create_backend(backend: &Backend) -> Result<Box<dyn FirewallBackend>> {
    match backend {
        Backend::Nftables => {
            let nft_path = resolve_binary("nft")?;
            Ok(Box::new(NftablesBackend::new(nft_path)))
        }
        Backend::Iptables => {
            let iptables_path = resolve_binary("iptables")?;
            let ip6tables_path = resolve_binary("ip6tables")?;
            Ok(Box::new(IptablesBackend::new(
                iptables_path,
                ip6tables_path,
            )))
        }
        Backend::Script { ban_cmd, unban_cmd } => Ok(Box::new(ScriptBackend::new(
            ban_cmd.clone(),
            unban_cmd.clone(),
        ))),
    }
}

/// Create per-jail firewall backends from jail configurations.
pub fn create_backends<S: ::std::hash::BuildHasher>(
    jails: &HashMap<String, JailConfig, S>,
) -> Result<HashMap<String, Box<dyn FirewallBackend>>> {
    jails
        .iter()
        .filter(|(_, cfg)| cfg.enabled)
        .map(|(name, cfg)| Ok((name.clone(), create_backend(&cfg.backend)?)))
        .collect()
}

/// Run the executor task loop.
pub async fn run<S: ::std::hash::BuildHasher>(
    mut rx: mpsc::Receiver<FirewallCmd>,
    backends: HashMap<String, Box<dyn FirewallBackend>, S>,
    cancel: CancellationToken,
) {
    let names: Vec<_> = backends
        .iter()
        .map(|(k, v)| format!("{k}={}", v.name()))
        .collect();
    info!(backends = ?names, "executor started");

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                info!("executor shutting down");
                break;
            }
            cmd = rx.recv() => {
                match cmd {
                    Some(FirewallCmd::Ban { ip, jail_id, banned_at, expires_at, done }) => {
                        info!(%ip, jail = %jail_id, "banning");
                        let result = if let Some(backend) = backends.get(&jail_id) {
                            if let Err(e) = backend.ban(&ip, &jail_id).await {
                                error!(%ip, jail = %jail_id, error = %e, "ban failed");
                                Err(e)
                            } else {
                                Ok(())
                            }
                        } else {
                            warn!(%ip, jail = %jail_id, "no backend for jail");
                            Ok(())
                        };
                        if let Some(done) = done {
                            let _ = done.send(result);
                        }
                        let _ = (banned_at, expires_at);
                    }
                    Some(FirewallCmd::Unban { ip, jail_id }) => {
                        info!(%ip, jail = %jail_id, "unbanning");
                        if let Some(backend) = backends.get(&jail_id) {
                            if let Err(e) = backend.unban(&ip, &jail_id).await {
                                warn!(%ip, jail = %jail_id, error = %e, "unban failed");
                            }
                        } else {
                            warn!(%ip, jail = %jail_id, "no backend for jail");
                        }
                    }
                    Some(FirewallCmd::InitJail { jail_id, ports, protocol, done }) => {
                        info!(jail = %jail_id, "initializing firewall");
                        let result = if let Some(backend) = backends.get(&jail_id) {
                            backend.init(&jail_id, &ports, &protocol).await
                        } else {
                            warn!(jail = %jail_id, "no backend for jail init");
                            Ok(())
                        };
                        if let Err(ref e) = result {
                            error!(jail = %jail_id, error = %e, "firewall init failed");
                        }
                        let _ = done.send(result);
                    }
                    Some(FirewallCmd::TeardownJail { jail_id, done }) => {
                        info!(jail = %jail_id, "tearing down firewall");
                        let result = if let Some(backend) = backends.get(&jail_id) {
                            backend.teardown(&jail_id).await
                        } else {
                            Ok(())
                        };
                        if let Err(ref e) = result {
                            warn!(jail = %jail_id, error = %e, "firewall teardown failed");
                        }
                        let _ = done.send(result);
                    }
                    None => {
                        info!("executor channel closed");
                        break;
                    }
                }
            }
        }
    }
}

/// Restore previously saved bans by re-issuing ban commands.
///
/// Jails with `reban_on_restart = false` are skipped — their firewall state
/// persists independently (e.g. ipset).
pub async fn restore_bans<S: ::std::hash::BuildHasher, S2: ::std::hash::BuildHasher>(
    bans: &[BanRecord],
    backends: &HashMap<String, Box<dyn FirewallBackend>, S>,
    now: i64,
    jail_configs: &HashMap<String, JailConfig, S2>,
) -> Vec<BanRecord> {
    let mut restored = Vec::new();
    for ban in bans {
        // Skip jails that opted out of restore.
        if jail_configs
            .get(&ban.jail_id)
            .is_some_and(|j| !j.reban_on_restart)
        {
            continue;
        }
        // Skip expired bans.
        if let Some(expires) = ban.expires_at
            && expires <= now
        {
            continue;
        }
        let Some(backend) = backends.get(&ban.jail_id) else {
            warn!(ip = %ban.ip, jail = %ban.jail_id, "no backend for jail, skipping restore");
            continue;
        };
        if let Err(e) = backend.ban(&ban.ip, &ban.jail_id).await {
            warn!(ip = %ban.ip, jail = %ban.jail_id, error = %e, "failed to restore ban");
            continue;
        }
        restored.push(ban.clone());
    }
    restored
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};

    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use std::net::Ipv6Addr;

    use crate::config::JailConfig;
    use crate::enforce::{FirewallBackend, FirewallCmd, create_backend};
    use crate::error::{Error, Result};
    use crate::track::state::BanRecord;

    /// Build a default jail configs map with reban_on_restart enabled for "sshd".
    fn default_jail_configs() -> HashMap<String, JailConfig> {
        let mut m = HashMap::new();
        m.insert("sshd".to_string(), test_jail_config(true));
        m
    }

    fn test_jail_config(restore: bool) -> JailConfig {
        JailConfig {
            enabled: true,
            log_path: "/tmp/test.log".into(),
            date_format: crate::detect::date::DateFormat::Syslog,
            filter: vec!["from <HOST>".to_string()],
            max_retry: 3,
            find_time: 600,
            ban_time: 60,
            port: vec![],
            protocol: "tcp".to_string(),
            bantime_increment: false,
            bantime_factor: 1.0,
            bantime_multipliers: vec![],
            bantime_maxtime: 604_800,
            backend: crate::config::Backend::Nftables,
            log_backend: crate::config::LogBackend::default(),
            journalmatch: vec![],
            ignoreregex: vec![],
            ignoreip: vec![],
            ignoreself: false,
            reban_on_restart: restore,
            webhook: None,
            maxmind: vec![],
        }
    }

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

        fn name(&self) -> &'static str {
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

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            crate::enforce::run(rx, backends, cancel_clone).await;
        });

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
        fn name(&self) -> &'static str {
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

        let jail_configs = default_jail_configs();
        let restored = crate::enforce::restore_bans(&bans, &backends, now, &jail_configs).await;

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

        let jail_configs = default_jail_configs();
        let restored = crate::enforce::restore_bans(&bans, &backends, now, &jail_configs).await;
        assert_eq!(restored.len(), 1);

        let calls = calls.lock().expect("lock");
        assert_eq!(calls[0], "ban:3.3.3.3:sshd");
    }

    #[tokio::test]
    async fn restore_bans_empty() {
        let backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
        let now = chrono::Utc::now().timestamp();

        let jail_configs = default_jail_configs();
        let restored = crate::enforce::restore_bans(&[], &backends, now, &jail_configs).await;
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

        let jail_configs = default_jail_configs();
        let restored = crate::enforce::restore_bans(&bans, &backends, now, &jail_configs).await;
        assert!(restored.is_empty(), "should skip on backend error");
    }

    #[tokio::test]
    async fn restore_bans_skips_jail_with_restore_disabled() {
        let (backend, calls) = MockBackend::new();
        let now = chrono::Utc::now().timestamp();

        let mut backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::new();
        backends.insert("sshd".to_string(), Box::new(backend));

        let bans = vec![BanRecord {
            ip: IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5)),
            jail_id: "sshd".to_string(),
            banned_at: now - 60,
            expires_at: Some(now + 3600),
        }];

        // Jail has reban_on_restart = false.
        let mut jail_configs = HashMap::new();
        jail_configs.insert("sshd".to_string(), test_jail_config(false));

        let restored = crate::enforce::restore_bans(&bans, &backends, now, &jail_configs).await;
        assert!(
            restored.is_empty(),
            "should skip jail with reban_on_restart=false"
        );

        let calls = calls.lock().expect("lock");
        assert!(calls.is_empty(), "ban command should not be called");
    }

    #[tokio::test]
    async fn restore_bans_mixed_jails() {
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

        let now = chrono::Utc::now().timestamp();
        let bans = vec![
            BanRecord {
                ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                jail_id: "sshd".to_string(),
                banned_at: now - 60,
                expires_at: Some(now + 3600),
            },
            BanRecord {
                ip: IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
                jail_id: "nginx".to_string(),
                banned_at: now - 60,
                expires_at: Some(now + 3600),
            },
        ];

        // sshd: reban_on_restart=false, nginx: reban_on_restart=true
        let mut jail_configs = HashMap::new();
        jail_configs.insert("sshd".to_string(), test_jail_config(false));
        jail_configs.insert("nginx".to_string(), test_jail_config(true));

        let restored = crate::enforce::restore_bans(&bans, &backends, now, &jail_configs).await;
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].ip, IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)));

        let sshd = sshd_calls.lock().expect("lock");
        assert!(sshd.is_empty(), "sshd should be skipped");

        let nginx = nginx_calls.lock().expect("lock");
        assert_eq!(nginx.len(), 1);
        assert_eq!(nginx[0], "ban:2.2.2.2:nginx");
    }

    #[tokio::test]
    async fn executor_channel_closed_stops() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let backends = mock_backends(Arc::clone(&calls));
        let (tx, rx) = mpsc::channel::<FirewallCmd>(16);
        let cancel = CancellationToken::new();

        let handle = tokio::spawn(async move {
            crate::enforce::run(rx, backends, cancel).await;
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

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            crate::enforce::run(rx, backends, cancel_clone).await;
        });

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

    #[test]
    fn create_backend_nftables() {
        if let Ok(backend) = create_backend(&crate::config::Backend::Nftables) {
            assert_eq!(backend.name(), "nftables");
        }
        // Binary not found on this system (e.g. macOS); skip.
    }

    #[test]
    fn create_backend_iptables() {
        if let Ok(backend) = create_backend(&crate::config::Backend::Iptables) {
            assert_eq!(backend.name(), "iptables");
        }
        // Binaries not found on this system (e.g. macOS); skip.
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
}
