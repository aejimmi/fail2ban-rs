//! Iptables firewall backend.
//!
//! Each jail owns chain `f2b-<jail>` in both `iptables` and `ip6tables`,
//! reached from `INPUT` by one jump rule (scoped with `-m multiport` when the
//! jail has ports). Bans are `-s <ip> -j DROP` rules inside the jail chain.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use tracing::{debug, warn};

use crate::enforce::{FirewallBackend, cmd};
use crate::error::{Error, Result};
use crate::text::lossy;

/// Port/protocol inputs a jail was initialized with.
///
/// Retained so `teardown` can rebuild a `-D INPUT` rule byte-identical to the
/// `-I INPUT` rule `init` inserted — iptables only deletes an exact match, and
/// the trait's `teardown` receives nothing but the jail name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RuleSpec {
    /// Destination ports the jump is scoped to; empty means all traffic.
    ports: Vec<String>,
    /// Protocol for the multiport match (unused when `ports` is empty).
    protocol: String,
}

/// Name of a jail's chain.
fn chain_name(jail: &str) -> String {
    format!("f2b-{jail}")
}

/// Argv for the `INPUT` jump rule, shared by `-C`, `-I`, and `-D` so every
/// operation targets exactly the same rule.
fn jump_args(flag: &str, chain: &str, spec: &RuleSpec) -> Vec<String> {
    let mut args: Vec<String> = vec![flag.into(), "INPUT".into()];
    if !spec.ports.is_empty() {
        args.extend([
            "-p".into(),
            spec.protocol.clone(),
            "-m".into(),
            "multiport".into(),
            "--dports".into(),
            spec.ports.join(","),
        ]);
    }
    args.extend(["-j".into(), chain.into()]);
    args
}

/// Parse banned source addresses out of `iptables -L <chain> -n` output.
///
/// Host sources may print bare or with a `/32` / `/128` suffix; wildcard
/// columns (`0.0.0.0/0`, `::/0`) never parse and are skipped.
fn parse_listing(listing: &str) -> HashSet<IpAddr> {
    listing
        .split_whitespace()
        .filter_map(|token| {
            let host = token
                .strip_suffix("/32")
                .or_else(|| token.strip_suffix("/128"))
                .unwrap_or(token);
            host.parse().ok()
        })
        .collect()
}

/// Iptables backend — uses `iptables`/`ip6tables` resolved at startup.
pub struct IptablesBackend {
    iptables_path: PathBuf,
    ip6tables_path: PathBuf,
    /// Per-jail rule inputs from the last `init`, replayed by `teardown`.
    rules: Mutex<HashMap<String, RuleSpec>>,
}

impl IptablesBackend {
    /// Build a backend from resolved `iptables` and `ip6tables` paths.
    pub fn new(iptables_path: PathBuf, ip6tables_path: PathBuf) -> Self {
        Self {
            iptables_path,
            ip6tables_path,
            rules: Mutex::new(HashMap::new()),
        }
    }

    /// Binary and label for an address family.
    fn family(&self, ip: &IpAddr) -> (&Path, &'static str) {
        match ip {
            IpAddr::V4(_) => (&self.iptables_path, "iptables"),
            IpAddr::V6(_) => (&self.ip6tables_path, "ip6tables"),
        }
    }

    /// The `(binary, label, is_v6)` triples, IPv4 first.
    fn families(&self) -> [(&Path, &'static str, bool); 2] {
        [
            (self.iptables_path.as_path(), "iptables", false),
            (self.ip6tables_path.as_path(), "ip6tables", true),
        ]
    }

    /// Record `spec` for `jail`, returning the previously stored spec.
    ///
    /// The guard never crosses an `.await`. A poisoned lock still yields the
    /// map — losing a spec would leave a stale jump rule behind on teardown.
    fn replace_rule_spec(&self, jail: &str, spec: RuleSpec) -> Option<RuleSpec> {
        self.rules
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(jail.to_string(), spec)
    }

    /// Remove and return the stored spec (portless default if never set).
    fn take_rule_spec(&self, jail: &str) -> RuleSpec {
        self.rules
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(jail)
            .unwrap_or_default()
    }

    /// Delete every copy of the `INPUT` jump for `spec` from both families
    /// (best effort). Older releases could leave duplicates behind, so this
    /// repeats `-D` while `-C` still matches.
    async fn delete_jumps(&self, chain: &str, spec: &RuleSpec) {
        let (check, delete) = (jump_args("-C", chain, spec), jump_args("-D", chain, spec));
        for (cmd, label, _) in self.families() {
            match cmd::delete_all_rules(cmd, label, &check, &delete).await {
                Ok(0) => debug!(%label, %chain, "INPUT jump absent; nothing to delete"),
                Ok(copies) => debug!(%label, %chain, copies, "INPUT jump deleted"),
                Err(e) => debug!(%label, %chain, error = %e, "INPUT jump delete failed"),
            }
        }
    }

    /// Flush and delete a chain in one family (best effort).
    async fn remove_chain(cmd: &Path, label: &str, chain: &str) {
        for flag in ["-F", "-X"] {
            if let Err(e) = cmd::xtables_run(cmd, label, &[flag, chain]).await {
                debug!(%label, %chain, flag, error = %e, "chain cleanup step failed");
            }
        }
    }

    /// Create the chain and the `INPUT` jump for one family.
    ///
    /// Chain creation and the trailing `RETURN` are best-effort (the chain
    /// may already exist; a user chain returns implicitly anyway). The jump
    /// is what makes bans effective, so its failure is returned.
    async fn init_family(cmd: &Path, label: &str, chain: &str, spec: &RuleSpec) -> Result<()> {
        if let Err(e) = cmd::xtables_run(cmd, label, &["-N", chain]).await {
            debug!(%label, %chain, error = %e, "chain creation failed (may already exist)");
        }
        let ret = |flag: &str| {
            vec![
                flag.to_string(),
                chain.to_string(),
                "-j".into(),
                "RETURN".into(),
            ]
        };
        if let Err(e) = cmd::ensure_rule(cmd, label, &ret("-C"), &ret("-A")).await {
            debug!(%label, %chain, error = %e, "RETURN rule failed");
        }
        cmd::ensure_rule(
            cmd,
            label,
            &jump_args("-C", chain, spec),
            &jump_args("-I", chain, spec),
        )
        .await
    }

    /// List a family's jail chain and parse the banned addresses.
    async fn list_chain(cmd: &Path, label: &str, chain: &str) -> Result<HashSet<IpAddr>> {
        let output = cmd::xtables_output(cmd, label, &["-L", chain, "-n"]).await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::firewall(format!(
                "{label} list failed for {chain}: {}",
                stderr.trim()
            )));
        }
        Ok(parse_listing(&lossy(&output.stdout)))
    }
}

#[async_trait::async_trait]
impl FirewallBackend for IptablesBackend {
    async fn init(&self, jail: &str, ports: &[String], protocol: &str) -> Result<()> {
        let chain = chain_name(jail);
        let spec = RuleSpec {
            ports: ports.to_vec(),
            protocol: protocol.to_string(),
        };
        // Re-init with different ports must not leave the old jump active.
        if let Some(old) = self.replace_rule_spec(jail, spec.clone())
            && old != spec
        {
            self.delete_jumps(&chain, &old).await;
        }
        for (cmd, label, v6) in self.families() {
            let Err(e) = Self::init_family(cmd, label, &chain, &spec).await else {
                continue;
            };
            // IPv6 stays best-effort: hosts without IPv6 (no ip6tables
            // modules) must still start and enforce IPv4 bans.
            if v6 {
                warn!(jail = %jail, error = %e, "failed to insert ip6tables INPUT jump; IPv6 bans will have no effect");
                continue;
            }
            // Without the IPv4 jump every ban would silently do nothing.
            Self::remove_chain(cmd, label, &chain).await;
            return Err(e);
        }
        Ok(())
    }

    async fn teardown(&self, jail: &str) -> Result<()> {
        let chain = chain_name(jail);
        let spec = self.take_rule_spec(jail);
        // The jump goes first: iptables refuses to delete a referenced chain.
        self.delete_jumps(&chain, &spec).await;
        for (cmd, label, _) in self.families() {
            Self::remove_chain(cmd, label, &chain).await;
        }
        Ok(())
    }

    /// Insert the DROP rule unless an identical one is already present, so
    /// a re-ban (restore, reconcile, reload seeding) never stacks copies.
    async fn ban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        let (cmd, label) = self.family(ip);
        let (chain, ip_str) = (chain_name(jail), ip.to_string());
        let rule = |op| [op, chain.as_str(), "-s", ip_str.as_str(), "-j", "DROP"];
        cmd::ensure_rule(cmd, label, &rule("-C"), &rule("-I")).await
    }

    /// Delete every copy of the DROP rule (older versions could stack
    /// duplicates, and deleting only one would leave the IP blocked). An
    /// already-absent rule is not an error.
    async fn unban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        let (cmd, label) = self.family(ip);
        let (chain, ip_str) = (chain_name(jail), ip.to_string());
        let rule = |op| [op, chain.as_str(), "-s", ip_str.as_str(), "-j", "DROP"];
        let deleted = cmd::delete_all_rules(cmd, label, &rule("-C"), &rule("-D")).await?;
        if deleted == 0 {
            debug!(%ip, jail = %jail, "iptables unban: rule absent");
        }
        Ok(())
    }

    async fn is_banned(&self, ip: &IpAddr, jail: &str) -> Result<bool> {
        let (cmd, label) = self.family(ip);
        Ok(Self::list_chain(cmd, label, &chain_name(jail))
            .await?
            .contains(ip))
    }

    async fn snapshot(&self, jail: &str) -> Result<Option<HashSet<IpAddr>>> {
        let chain = chain_name(jail);
        let mut all = HashSet::new();
        for (cmd, label, _) in self.families() {
            all.extend(Self::list_chain(cmd, label, &chain).await?);
        }
        Ok(Some(all))
    }

    fn name(&self) -> &'static str {
        "iptables"
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
#[path = "iptables_test.rs"]
mod iptables_test;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
#[path = "iptables_ops_test.rs"]
mod iptables_ops_test;
