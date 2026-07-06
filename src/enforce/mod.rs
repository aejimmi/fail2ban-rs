//! Enforcement — receives firewall commands and executes them.
//!
//! Owns the firewall backends (one per jail). Runs as a single tokio task,
//! reading commands from a bounded mpsc channel.

/// Executor task loop and per-command firewall handlers.
mod executor;
/// iptables firewall backend.
pub mod iptables;
/// nftables firewall backend.
pub mod nftables;
/// Startup restore of persisted bans.
mod restore;
/// Script-based firewall backend.
pub mod script;

pub use executor::run;
pub use restore::{init_and_restore, init_backends, restore_bans};

#[cfg(test)]
mod test_support;

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use tokio::sync::oneshot;

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
    /// Fully tear down a jail on daemon shutdown (removes shared state too).
    TeardownJailFull {
        jail_id: String,
        done: oneshot::Sender<Result<()>>,
    },
    /// Register a newly added jail's backend and initialize its firewall rules.
    ///
    /// Used on config reload when a jail is added (or its backend type changed).
    /// The executor builds the backend from `backend`, initializes its kernel
    /// state, then inserts it into the backend map — so bans can be applied to a
    /// set/chain that already exists. This never touches other jails' state.
    AddJail {
        jail_id: String,
        backend: Backend,
        ports: Vec<String>,
        protocol: String,
        done: oneshot::Sender<Result<()>>,
    },
    /// Tear down a removed jail's firewall rules and deregister its backend.
    ///
    /// Used on config reload when a jail is removed (or its backend type
    /// changed). The teardown drops the jail's kernel state (chain/set and every
    /// banned element); the backend object is then removed from the map.
    RemoveJail {
        jail_id: String,
        done: oneshot::Sender<Result<()>>,
    },
}

/// Request from the tracker to reconcile active bans against firewall state.
///
/// The executor verifies each ban with [`FirewallBackend::is_banned`] and
/// re-applies any the kernel is missing (e.g. a ban that failed to apply, or
/// was cleared out-of-band). Shipped as a bounded batch so the tracker's event
/// loop stays responsive — the per-IP shell-outs happen on the executor task.
#[derive(Debug)]
pub struct ReconcileRequest {
    /// Active bans to verify; the tracker caps the batch size per tick.
    pub bans: Vec<BanRecord>,
}

/// Trait for firewall backend implementations.
#[async_trait::async_trait]
pub trait FirewallBackend: Send + Sync {
    /// Initialize firewall rules for a jail (create chains/sets).
    async fn init(&self, jail: &str, ports: &[String], protocol: &str) -> Result<()>;

    /// Tear down firewall rules for a jail (remove chains/sets).
    ///
    /// This is used on config reload — it removes only the jail's own state
    /// and leaves any shared infrastructure (e.g. the nftables table) in place.
    async fn teardown(&self, jail: &str) -> Result<()>;

    /// Fully tear down a jail on daemon shutdown.
    ///
    /// Unlike [`teardown`](Self::teardown), backends that own shared
    /// infrastructure should remove it here so nothing leaks after exit.
    /// The default delegates to [`teardown`](Self::teardown).
    async fn teardown_full(&self, jail: &str) -> Result<()> {
        self.teardown(jail).await
    }

    /// Ban an IP address.
    async fn ban(&self, ip: &IpAddr, jail: &str) -> Result<()>;

    /// Ban an IP address with an optional kernel-side expiry backstop.
    ///
    /// Backends that support per-element timeouts (nftables) use `expires_at`
    /// so bans self-clear even if the tracker dies. `now` is the current unix
    /// timestamp used to compute the remaining duration. The default ignores
    /// the expiry and delegates to [`ban`](Self::ban).
    async fn ban_with_timeout(
        &self,
        ip: &IpAddr,
        jail: &str,
        expires_at: Option<i64>,
        now: i64,
    ) -> Result<()> {
        let _ = (expires_at, now);
        self.ban(ip, jail).await
    }

    /// Remove a ban for an IP address.
    ///
    /// Removing a ban that is already absent (e.g. expired via a kernel
    /// timeout) must not be a hard error.
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

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
mod mod_test;
