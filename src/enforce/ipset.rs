//! ipset firewall backend.
//!
//! Owns one `hash:ip` set per address family per jail (`f2b-<jail>` for inet,
//! `f2b-<jail>6` for inet6) plus one `-m set` DROP rule per family in the
//! configured iptables chain. Bans become O(1) kernel hash lookups instead of a
//! linear chain walk, and each entry carries a kernel-side timeout so it
//! self-clears if the daemon dies.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::Mutex;

use tracing::{debug, warn};

use crate::enforce::{FirewallBackend, cmd};
use crate::error::{Error, Result};
use crate::text::lossy;

/// ipset's hard kernel ceiling for a per-entry timeout, in seconds (~24.85
/// days). Exceeding it is a syntax error, not a saturating value.
const MAX_TIMEOUT_SECS: i64 = 2_147_483;

/// Substring ipset prints when a tested entry is simply absent, as opposed to
/// the query itself failing.
const NOT_IN_SET: &str = "is NOT in set";

/// Port/protocol inputs a jail was initialized with.
///
/// Retained so `teardown` can reconstruct a `-D` rule byte-identical to the
/// `-I` rule `init` inserted — iptables only deletes an exact match, and the
/// trait's `teardown` receives nothing but the jail name.
#[derive(Debug, Clone, Default)]
struct RuleSpec {
    /// Destination ports the rule is scoped to; empty means all traffic.
    ports: Vec<String>,
    /// Protocol for the multiport match (unused when `ports` is empty).
    protocol: String,
}

/// Suffix that distinguishes a jail's inet6 set from its inet set.
///
/// Jail `foo6`'s inet set would be `f2b-foo6` — jail `foo`'s inet6 set — so
/// config validation rejects ipset jail names ending in this suffix.
pub(crate) const V6_SET_SUFFIX: &str = "6";

/// Name of a jail's set for one address family.
fn set_name(jail: &str, v6: bool) -> String {
    if v6 {
        format!("f2b-{jail}{V6_SET_SUFFIX}")
    } else {
        format!("f2b-{jail}")
    }
}

/// Argv for creating one family's set.
///
/// `timeout 0` is mandatory: it enables the set's timeout extension (without
/// it the kernel rejects per-entry timeouts) while leaving the *default* entry
/// timeout permanent.
fn create_args(set: &str, family: &str, maxelem: u32) -> Vec<String> {
    vec![
        "-exist".into(),
        "create".into(),
        set.into(),
        "hash:ip".into(),
        "family".into(),
        family.into(),
        "timeout".into(),
        "0".into(),
        "maxelem".into(),
        maxelem.to_string(),
    ]
}

/// Argv for the `-m set` DROP rule, shared by the `-C` probe, `init` (`-I`),
/// and `teardown` (`-D`) so every operation targets exactly the same rule.
fn match_rule_args(flag: &str, chain: &str, set: &str, spec: &RuleSpec) -> Vec<String> {
    let mut args: Vec<String> = vec![flag.into(), chain.into()];
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
    args.extend([
        "-m".into(),
        "set".into(),
        "--match-set".into(),
        set.into(),
        "src".into(),
        "-j".into(),
        "DROP".into(),
    ]);
    args
}

/// Kernel-side timeout in seconds for a ban.
///
/// A past or near expiry clamps up to 1 — ipset reads 0 as *permanent*. The
/// upper clamp is ipset's kernel ceiling. `None` (permanent ban) is an explicit
/// 0, which matters because `-exist add` on an existing entry updates its
/// timeout.
fn timeout_secs(expires_at: Option<i64>, now: i64) -> i64 {
    match expires_at {
        Some(exp) => exp.saturating_sub(now).clamp(1, MAX_TIMEOUT_SECS),
        None => 0,
    }
}

/// Spawn a firewall command (under the shared timeout) and capture its output.
async fn capture(cmd: &Path, label: &str, args: &[String]) -> Result<Output> {
    cmd::output(cmd, label, args).await
}

/// Run a firewall command, mapping a nonzero exit to an error carrying stderr.
async fn run(cmd: &Path, label: &str, args: &[String]) -> Result<()> {
    cmd::run(cmd, label, args).await
}

/// Parse the addresses listed after `Members:` in `ipset list` output.
///
/// Each member line is `<ip> [timeout N]`; only the leading address counts.
fn parse_members(listing: &str) -> HashSet<IpAddr> {
    listing
        .lines()
        .skip_while(|line| !line.starts_with("Members:"))
        .skip(1)
        .filter_map(|line| line.split_whitespace().next()?.parse().ok())
        .collect()
}

/// ipset backend — uses `ipset`, `iptables`, and `ip6tables` resolved at
/// startup.
pub struct IpsetBackend {
    /// Absolute path to `ipset`.
    ipset_path: PathBuf,
    /// Absolute path to `iptables`.
    iptables_path: PathBuf,
    /// Absolute path to `ip6tables`.
    ip6tables_path: PathBuf,
    /// Maximum entries per set.
    maxelem: u32,
    /// iptables chain the match rules are inserted into.
    chain: String,
    /// Ports/protocol captured by the last `init`, replayed by `teardown`.
    rule: Mutex<RuleSpec>,
}

impl IpsetBackend {
    /// Build a backend from resolved binary paths and validated settings.
    pub fn new(
        ipset_path: PathBuf,
        iptables_path: PathBuf,
        ip6tables_path: PathBuf,
        maxelem: u32,
        chain: String,
    ) -> Self {
        Self {
            ipset_path,
            iptables_path,
            ip6tables_path,
            maxelem,
            chain,
            rule: Mutex::new(RuleSpec::default()),
        }
    }

    /// The two `(binary, label, is_v6)` triples, in v4-then-v6 order.
    fn iptables_cmds(&self) -> [(&Path, &'static str, bool); 2] {
        [
            (self.iptables_path.as_path(), "iptables", false),
            (self.ip6tables_path.as_path(), "ip6tables", true),
        ]
    }

    /// Record the rule inputs `init` was given.
    ///
    /// The guard never crosses an `.await`: it is taken and dropped inside this
    /// synchronous helper. A poisoned lock still yields the stored value —
    /// losing the rule spec would leave a stale DROP rule behind on teardown.
    fn store_rule_spec(&self, ports: &[String], protocol: &str) {
        let mut guard = self
            .rule
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = RuleSpec {
            ports: ports.to_vec(),
            protocol: protocol.to_string(),
        };
    }

    /// Clone out the recorded rule inputs (see [`Self::store_rule_spec`]).
    fn rule_spec(&self) -> RuleSpec {
        self.rule
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Run `ipset` with the given argv.
    async fn run_ipset(&self, args: &[String]) -> Result<()> {
        run(&self.ipset_path, "ipset", args).await
    }

    /// Create both family sets. A failure here is fatal — `-exist create` is
    /// idempotent, so an error means the sets are unusable and every later ban
    /// would fail silently.
    async fn create_sets(&self, jail: &str) -> Result<()> {
        for (v6, family) in [(false, "inet"), (true, "inet6")] {
            let set = set_name(jail, v6);
            self.run_ipset(&create_args(&set, family, self.maxelem))
                .await?;
        }
        Ok(())
    }

    /// Flush and destroy both family sets (best effort — a set may be absent
    /// or still referenced by a stray rule; flushing first still clears bans).
    async fn destroy_sets(&self, jail: &str) {
        for v6 in [false, true] {
            let set = set_name(jail, v6);
            for verb in ["flush", "destroy"] {
                if let Err(e) = self.run_ipset(&[verb.into(), set.clone()]).await {
                    debug!(backend = "ipset", set = %set, verb, error = %e, "ipset cleanup step failed");
                }
            }
        }
    }

    /// List one set's members. A nonzero exit is an error, never "empty".
    async fn list_members(&self, set: String) -> Result<HashSet<IpAddr>> {
        let args = ["list".to_string(), set.clone()];
        let output = capture(&self.ipset_path, "ipset", &args).await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::firewall(format!(
                "ipset list failed for {set}: {}",
                stderr.trim()
            )));
        }
        Ok(parse_members(&lossy(&output.stdout)))
    }
}

#[async_trait::async_trait]
impl FirewallBackend for IpsetBackend {
    async fn init(&self, jail: &str, ports: &[String], protocol: &str) -> Result<()> {
        self.store_rule_spec(ports, protocol);
        self.create_sets(jail).await?;

        let spec = self.rule_spec();
        for (cmd, label, v6) in self.iptables_cmds() {
            let set = set_name(jail, v6);
            let check = match_rule_args("-C", &self.chain, &set, &spec);
            let insert = match_rule_args("-I", &self.chain, &set, &spec);
            let Err(e) = cmd::ensure_rule(cmd, label, &check, &insert).await else {
                continue;
            };
            // IPv6 stays best-effort: hosts without IPv6 (no ip6tables or no
            // inet6 xt_set support) must still start and enforce IPv4 bans.
            if v6 {
                warn!(backend = "ipset", jail = %jail, set = %set, chain = %self.chain, error = %e, "failed to insert ip6tables match rule; IPv6 bans will have no effect");
                continue;
            }
            // Without the IPv4 rule every ban would silently do nothing
            // (#21): undo the sets init created and fail loudly.
            self.destroy_sets(jail).await;
            return Err(e);
        }
        Ok(())
    }

    async fn teardown(&self, jail: &str) -> Result<()> {
        // Rules first: ipset refuses to destroy a set a netfilter rule still
        // references. Flush before destroy so a lingering reference (e.g. a
        // duplicate rule from an unclean shutdown) still leaves no stale bans.
        let spec = self.rule_spec();
        for (cmd, label, v6) in self.iptables_cmds() {
            let set = set_name(jail, v6);
            let check = match_rule_args("-C", &self.chain, &set, &spec);
            let delete = match_rule_args("-D", &self.chain, &set, &spec);
            // Older releases stacked duplicate rules on re-init: remove all.
            if let Err(e) = cmd::delete_all_rules(cmd, label, &check, &delete).await {
                debug!(backend = "ipset", jail = %jail, error = %e, "match rule delete failed");
            }
        }
        self.destroy_sets(jail).await;
        Ok(())
    }

    async fn ban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        self.ban_with_timeout(ip, jail, None, 0).await
    }

    async fn ban_with_timeout(
        &self,
        ip: &IpAddr,
        jail: &str,
        expires_at: Option<i64>,
        now: i64,
    ) -> Result<()> {
        let set = set_name(jail, ip.is_ipv6());
        let secs = timeout_secs(expires_at, now);
        if let Some(exp) = expires_at
            && exp.saturating_sub(now) > MAX_TIMEOUT_SECS
        {
            // The WAL expiry stays authoritative and reconcile re-adds any ban
            // the kernel drops early, so the cap is a backstop, not a bug.
            debug!(
                backend = "ipset", jail = %jail, %ip,
                requested = exp.saturating_sub(now), applied = secs,
                "ban timeout clamped to ipset kernel ceiling"
            );
        }
        self.run_ipset(&[
            "-exist".into(),
            "add".into(),
            set,
            ip.to_string(),
            "timeout".into(),
            secs.to_string(),
        ])
        .await
    }

    async fn unban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        let set = set_name(jail, ip.is_ipv6());
        // `-exist` already ignores an entry that expired out from under us;
        // any remaining failure must still not be fatal per the trait contract.
        if let Err(e) = self
            .run_ipset(&["-exist".into(), "del".into(), set, ip.to_string()])
            .await
        {
            debug!(backend = "ipset", %ip, jail = %jail, error = %e, "ipset unban: entry absent or already expired");
        }
        Ok(())
    }

    async fn is_banned(&self, ip: &IpAddr, jail: &str) -> Result<bool> {
        let set = set_name(jail, ip.is_ipv6());
        let args = vec!["test".into(), set, ip.to_string()];
        let output = capture(&self.ipset_path, "ipset", &args).await?;
        if output.status.success() {
            return Ok(true);
        }
        // A nonzero exit means "absent" only when ipset says so. A missing set
        // or a permission failure exits nonzero too, and reporting those as
        // "not banned" would make reconcile re-apply every ban each tick.
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stdout.contains(NOT_IN_SET) || stderr.contains(NOT_IN_SET) {
            return Ok(false);
        }
        Err(Error::firewall(format!(
            "ipset test failed for {ip}: {}",
            stderr.trim()
        )))
    }

    async fn snapshot(&self, jail: &str) -> Result<Option<HashSet<IpAddr>>> {
        let mut all = self.list_members(set_name(jail, false)).await?;
        all.extend(self.list_members(set_name(jail, true)).await?);
        Ok(Some(all))
    }

    fn name(&self) -> &'static str {
        "ipset"
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
#[path = "ipset_test.rs"]
mod ipset_test;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
#[path = "ipset_ops_test.rs"]
mod ipset_ops_test;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
#[path = "ipset_init_test.rs"]
mod ipset_init_test;
