//! Enforcement — receives firewall commands and executes them.
//!
//! Owns the firewall backends (one per jail). Runs as a single tokio task,
//! reading commands from a bounded mpsc channel.

/// Shared subprocess runner with timeout and kill-on-drop.
mod cmd;
/// Executor task loop and per-command firewall handlers.
mod executor;
/// ipset firewall backend.
pub mod ipset;
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
mod fake_bin_test_support;
#[cfg(test)]
mod test_support;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use tokio::sync::oneshot;

use crate::config::{Backend, JailConfig};
use crate::enforce::ipset::IpsetBackend;
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
    Unban {
        ip: IpAddr,
        jail_id: String,
        done: Option<tokio::sync::oneshot::Sender<crate::error::Result<()>>>,
    },
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
    /// Used on config reload when a jail is newly added.
    /// The executor builds the backend from `backend`, initializes its kernel
    /// state, then inserts it into the backend map — so bans can be applied to a
    /// set/chain that already exists. This never touches other jails' state.
    /// The jail's `active_bans` (stored bans from an earlier life of the jail)
    /// are then reapplied; per-ban failures are logged, never fatal.
    AddJail {
        jail_id: String,
        backend: Backend,
        ports: Vec<String>,
        protocol: String,
        active_bans: Vec<BanRecord>,
        done: oneshot::Sender<Result<()>>,
    },
    /// Transactionally replace an existing jail's backend during reload.
    ///
    /// The executor retains ownership of the old backend until the replacement
    /// is initialized and all active bans have been restored. If either step
    /// fails, it reinitializes the old backend and reapplies the same bans
    /// before acknowledging the reload failure.
    ReplaceJail {
        jail_id: String,
        backend: Backend,
        old_ports: Vec<String>,
        old_protocol: String,
        new_ports: Vec<String>,
        new_protocol: String,
        active_bans: Vec<BanRecord>,
        done: oneshot::Sender<Result<()>>,
    },
    /// Tear down a removed jail's firewall rules and deregister its backend.
    ///
    /// Used on config reload when a jail is removed. The teardown drops the
    /// jail's kernel state (chain/set and every banned element); the backend
    /// object is then removed from the map.
    RemoveJail {
        jail_id: String,
        done: oneshot::Sender<Result<()>>,
    },
    /// Reconcile active bans against firewall state (sent by the tracker).
    ///
    /// The executor verifies each jail's bans with one
    /// [`FirewallBackend::snapshot`] (falling back to per-IP
    /// [`FirewallBackend::is_banned`]), skips backends that cannot verify
    /// state, and re-applies any ban the kernel is missing (e.g. a ban that
    /// failed to apply, or was cleared out-of-band). Shipped as a bounded
    /// batch so the tracker's event loop stays responsive — the shell-outs
    /// happen on the executor task.
    ///
    /// Carried on the same ordered channel as `Ban`/`Unban`, so a batch that
    /// lists an IP is always processed before any later `Unban` of it.
    Reconcile {
        /// Active bans to verify; the tracker caps the batch size per tick.
        bans: Vec<BanRecord>,
    },
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

    /// Whether [`is_banned`](Self::is_banned) reflects real firewall state.
    ///
    /// Backends that cannot query the firewall (e.g. the script backend)
    /// return `false`; reconcile must then skip them instead of treating every
    /// ban as missing and re-applying it each tick. Defaults to `true`.
    fn can_verify(&self) -> bool {
        true
    }

    /// Read every IP currently banned for `jail` in one pass.
    ///
    /// Lets reconcile verify a whole batch with one or two shell-outs instead
    /// of one [`is_banned`](Self::is_banned) call per IP. `Ok(None)` means the
    /// backend does not support snapshots and callers should fall back to
    /// per-IP checks. Errors mean the query itself failed — callers must not
    /// read that as "nothing is banned".
    async fn snapshot(&self, jail: &str) -> Result<Option<HashSet<IpAddr>>> {
        let _ = jail;
        Ok(None)
    }

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
        Backend::Ipset { maxelem, chain } => {
            let ipset_path = resolve_binary("ipset")?;
            let iptables_path = resolve_binary("iptables")?;
            let ip6tables_path = resolve_binary("ip6tables")?;
            Ok(Box::new(IpsetBackend::new(
                ipset_path,
                iptables_path,
                ip6tables_path,
                *maxelem,
                chain.clone(),
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
