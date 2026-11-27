//! ipset firewall backend.
//!
//! Owns one `hash:ip` set per address family per jail (`f2b-<jail>` for inet,
//! `f2b-<jail>6` for inet6) and a `hash:net` set for IPv6 prefixes, with one `-m set` DROP rule per set in the
//! configured iptables chain. Entries carry kernel-side timeouts so they clear
//! if the daemon dies.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::Mutex;

use tracing::{debug, warn};

use crate::ban_target::BanTarget;
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

fn prefix_set_name(jail: &str) -> String {
    format!("f2b6-{jail}")
}

fn target_set_name(jail: &str, target: BanTarget) -> String {
    if target.is_prefix() {
        prefix_set_name(jail)
    } else {
        set_name(jail, target.is_ipv6())
    }
}

/// Argv for creating one set.
///
/// `timeout 0` is mandatory: it enables the set's timeout extension (without
/// it the kernel rejects per-entry timeouts) while leaving the *default* entry
/// timeout permanent.
fn create_args(set: &str, kind: &str, family: &str, maxelem: u32) -> Vec<String> {
    vec![
        "-exist".into(),
        "create".into(),
        set.into(),
        kind.into(),
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
fn parse_members(listing: &str) -> HashSet<BanTarget> {
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
    fn iptables_cmds(&self, jail: &str) -> [(&Path, &'static str, String); 3] {
        [
            (
                self.iptables_path.as_path(),
                "iptables",
                set_name(jail, false),
            ),
            (
                self.ip6tables_path.as_path(),
                "ip6tables",
                set_name(jail, true),
            ),
            (
                self.ip6tables_path.as_path(),
                "ip6tables",
                prefix_set_name(jail),
            ),
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

    /// Create host and prefix sets. A failure here is fatal — `-exist create` is
    /// idempotent, so an error means the sets are unusable and every later ban
    /// would fail silently.
    async fn create_sets(&self, jail: &str) -> Result<()> {
        for (set, kind, family) in [
            (set_name(jail, false), "hash:ip", "inet"),
            (set_name(jail, true), "hash:ip", "inet6"),
            (prefix_set_name(jail), "hash:net", "inet6"),
        ] {
            self.run_ipset(&create_args(&set, kind, family, self.maxelem))
                .await?;
        }
        Ok(())
    }

    /// Flush and destroy the jail sets (best effort — a set may be absent
    /// or still referenced by a stray rule; flushing first still clears bans).
    async fn destroy_sets(&self, jail: &str) {
        for (_, _, set) in self.iptables_cmds(jail) {
            for verb in ["flush", "destroy"] {
                if let Err(e) = self.run_ipset(&[verb.into(), set.clone()]).await {
                    debug!(backend = "ipset", set = %set, verb, error = %e, "ipset cleanup step failed");
                }
            }
        }
    }

    /// List one set's members. A nonzero exit is an error, never "empty".
    async fn list_members(&self, set: String) -> Result<HashSet<BanTarget>> {
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
        for (cmd, label, set) in self.iptables_cmds(jail) {
            let check = match_rule_args("-C", &self.chain, &set, &spec);
            let insert = match_rule_args("-I", &self.chain, &set, &spec);
            let Err(e) = cmd::ensure_rule(cmd, label, &check, &insert).await else {
                continue;
            };
            // IPv6 stays best-effort: hosts without IPv6 (no ip6tables or no
            // inet6 xt_set support) must still start and enforce IPv4 bans.
            if label == "ip6tables" {
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
        for (cmd, label, set) in self.iptables_cmds(jail) {
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

    async fn ban(&self, ip: &BanTarget, jail: &str) -> Result<()> {
        self.ban_with_timeout(ip, jail, None, 0).await
    }

    async fn ban_with_timeout(
        &self,
        ip: &BanTarget,
        jail: &str,
        expires_at: Option<i64>,
        now: i64,
    ) -> Result<()> {
        let set = target_set_name(jail, *ip);
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

    async fn unban(&self, ip: &BanTarget, jail: &str) -> Result<()> {
        let set = target_set_name(jail, *ip);
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

    async fn is_banned(&self, ip: &BanTarget, jail: &str) -> Result<bool> {
        let set = target_set_name(jail, *ip);
        if ip.is_prefix() {
            return Ok(self.list_members(set).await?.contains(ip));
        }
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

    async fn snapshot(&self, jail: &str) -> Result<Option<HashSet<BanTarget>>> {
        let mut all = HashSet::new();
        for (_, _, set) in self.iptables_cmds(jail) {
            all.extend(self.list_members(set).await?);
        }
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
