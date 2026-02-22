//! Executor task — receives firewall commands and executes them.
//!
//! Owns the firewall backends (one per jail) and state persistence. Runs as a
//! single tokio task, reading commands from a bounded mpsc channel.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::config::{Backend, JailConfig};
use crate::error::{Error, Result};
use crate::executor_iptables::IptablesBackend;
use crate::executor_nftables::NftablesBackend;
use crate::executor_script::ScriptBackend;
use crate::state::{self, BanRecord, StateSnapshot};

/// Commands sent to the executor task.
#[derive(Debug)]
pub enum FirewallCmd {
    /// Ban an IP in the firewall.
    Ban {
        ip: IpAddr,
        jail_id: String,
        banned_at: i64,
        expires_at: Option<i64>,
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
    /// Persist the current ban state to disk.
    SaveState { snapshot: StateSnapshot },
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
    fn name(&self) -> &str;
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
pub fn create_backends(
    jails: &HashMap<String, JailConfig>,
) -> Result<HashMap<String, Box<dyn FirewallBackend>>> {
    jails
        .iter()
        .filter(|(_, cfg)| cfg.enabled)
        .map(|(name, cfg)| Ok((name.clone(), create_backend(&cfg.backend)?)))
        .collect()
}

/// Run the executor task loop.
pub async fn run(
    mut rx: mpsc::Receiver<FirewallCmd>,
    backends: HashMap<String, Box<dyn FirewallBackend>>,
    state_path: PathBuf,
    cancel: CancellationToken,
) {
    let names: Vec<_> = backends
        .iter()
        .map(|(k, v)| format!("{k}={}", v.name()))
        .collect();
    info!(backends = ?names, "executor started");

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("executor shutting down");
                break;
            }
            cmd = rx.recv() => {
                match cmd {
                    Some(FirewallCmd::Ban { ip, jail_id, banned_at, expires_at }) => {
                        info!(%ip, jail = %jail_id, "banning");
                        if let Some(backend) = backends.get(&jail_id) {
                            if let Err(e) = backend.ban(&ip, &jail_id).await {
                                error!(%ip, jail = %jail_id, error = %e, "ban failed");
                            }
                        } else {
                            warn!(%ip, jail = %jail_id, "no backend for jail");
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
                    Some(FirewallCmd::SaveState { snapshot }) => {
                        let ban_count = snapshot.bans.len();
                        if let Err(e) = state::save(&state_path, &snapshot) {
                            error!(error = %e, "state save failed");
                        } else {
                            info!(bans = ban_count, "state saved");
                        }
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
pub async fn restore_bans(
    bans: &[BanRecord],
    backends: &HashMap<String, Box<dyn FirewallBackend>>,
    now: i64,
) -> Vec<BanRecord> {
    let mut restored = Vec::new();
    for ban in bans {
        // Skip expired bans.
        if let Some(expires) = ban.expires_at
            && expires <= now
        {
            continue;
        }
        let backend = match backends.get(&ban.jail_id) {
            Some(b) => b,
            None => {
                warn!(ip = %ban.ip, jail = %ban.jail_id, "no backend for jail, skipping restore");
                continue;
            }
        };
        if let Err(e) = backend.ban(&ban.ip, &ban.jail_id).await {
            warn!(ip = %ban.ip, jail = %ban.jail_id, error = %e, "failed to restore ban");
            continue;
        }
        restored.push(ban.clone());
    }
    restored
}
