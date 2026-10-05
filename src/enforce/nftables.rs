//! Nftables firewall backend.
//!
//! All state lives in table `inet fail2ban-rs`. Each jail owns one base chain
//! `f2b-<jail>` (hooked on input) plus two sets, `f2b-<jail>` (IPv4) and
//! `f2b-<jail>-v6` (IPv6). Chains and sets live in separate nft namespaces,
//! so the shared `f2b-<jail>` name is unambiguous. Because a jail's rules are
//! confined to its own chain, teardown drops them all by deleting the chain —
//! which in turn releases the sets so they can be deleted too.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;

use tracing::debug;

use crate::enforce::{FirewallBackend, cmd};
use crate::error::{Error, Result};
use crate::text::lossy;

/// Address family of the fail2ban-rs table.
const FAMILY: &str = "inet";

/// Name of the table holding every jail's chain and sets.
const TABLE: &str = "fail2ban-rs";

/// Base-chain definition for a jail chain. Priority -1 runs just ahead of the
/// default filter chains; `policy accept` means only the explicit reject
/// rules affect traffic.
const CHAIN_SPEC: &str = "{ type filter hook input priority -1; policy accept; }";

/// Shared chain used by releases before per-jail chains. Removed on init so
/// rules left behind by an unclean shutdown of an old version stop matching.
const LEGACY_CHAIN: &str = "f2b-chain";

/// Jail name whose base chain would be [`LEGACY_CHAIN`]. Every other jail's
/// init deletes that chain, so config validation rejects this name for
/// nftables jails.
pub(crate) const LEGACY_JAIL_NAME: &str = "chain";

/// Suffix that distinguishes a jail's IPv6 set from its IPv4 set.
///
/// Jail `foo-v6`'s IPv4 set would be `f2b-foo-v6` — jail `foo`'s IPv6 set —
/// so config validation rejects nftables jail names ending in this suffix.
pub(crate) const V6_SET_SUFFIX: &str = "-v6";

/// Build the set-definition fragment for a jail set.
///
/// The `timeout` flag is required so elements can carry a kernel-side expiry,
/// giving bans a backstop that self-clears even if the tracker dies.
fn set_block(elem_type: &str) -> String {
    format!("{{ type {elem_type}; flags timeout; }}")
}

/// Build the `nft` element fragment for an IP, with a `timeout Ns` clause when
/// `expires_at` is set. A past/near expiry is clamped to a minimum of 1s.
fn element_spec(ip: &IpAddr, expires_at: Option<i64>, now: i64) -> String {
    match expires_at {
        Some(exp) => {
            let secs = (exp - now).max(1);
            format!("{{ {ip} timeout {secs}s }}")
        }
        None => format!("{{ {ip} }}"),
    }
}

/// Name of a jail's base chain.
fn chain_name(jail: &str) -> String {
    format!("f2b-{jail}")
}

/// Names of a jail's IPv4 and IPv6 sets, in that order.
fn set_names(jail: &str) -> [String; 2] {
    [format!("f2b-{jail}"), format!("f2b-{jail}{V6_SET_SUFFIX}")]
}

/// Return the family-specific nftables set for a jail.
///
/// Each jail has separate `ipv4_addr` and `ipv6_addr` sets, so element
/// operations must use the set matching the address family.
fn set_name_for_ip(jail: &str, ip: &IpAddr) -> String {
    let [v4, v6] = set_names(jail);
    if ip.is_ipv6() { v6 } else { v4 }
}

/// Build the two reject rules (IPv4, IPv6) for a jail.
///
/// With no ports every packet from a banned source is rejected; otherwise the
/// rules are scoped to `<protocol> dport { <ports> }`.
fn rule_exprs(jail: &str, ports: &[String], protocol: &str) -> [String; 2] {
    let [v4, v6] = set_names(jail);
    let scope = if ports.is_empty() {
        String::new()
    } else {
        format!("{protocol} dport {{ {} }} ", ports.join(","))
    };
    [
        format!("{scope}ip saddr @{v4} reject"),
        format!("{scope}ip6 saddr @{v6} reject"),
    ]
}

/// Parse every IP element out of `nft list set` text output.
///
/// nft prints `elements = { 1.2.3.4, 5.6.7.8 timeout 60s expires 59s }`, so
/// a plain whitespace split yields `1.2.3.4,` for every non-final element.
/// Split on whitespace and `,{}=` instead and keep only tokens that parse as
/// an address (timeouts like `60s` never do).
fn parse_set_elements(listing: &str) -> HashSet<IpAddr> {
    let Some(start) = listing.find("elements") else {
        return HashSet::new();
    };
    listing
        .get(start..)
        .unwrap_or_default()
        .split(|c: char| c.is_whitespace() || matches!(c, ',' | '{' | '}' | '='))
        .filter_map(|token| token.parse().ok())
        .collect()
}

/// Nftables backend — uses `nft` command resolved at startup.
pub struct NftablesBackend {
    nft_path: PathBuf,
}

impl NftablesBackend {
    /// Build a backend from the resolved `nft` binary path.
    pub fn new(nft_path: PathBuf) -> Self {
        Self { nft_path }
    }

    /// Run `nft` under the command timeout, mapping a nonzero exit to an error.
    async fn run_nft(&self, args: &[&str]) -> Result<()> {
        cmd::run(&self.nft_path, "nft", args).await
    }

    /// Run `nft`, logging (not propagating) a failure. Used for cleanup steps
    /// whose target may legitimately be absent.
    async fn run_best_effort(&self, args: &[&str]) {
        if let Err(e) = self.run_nft(args).await {
            debug!(?args, error = %e, "nft cleanup step failed (target may be absent)");
        }
    }

    /// Flush and delete the pre-per-jail shared chain if an old install left
    /// it behind. Its rules reference jail sets, so leaving it would keep
    /// stale port rules active and block set deletion.
    async fn remove_legacy_chain(&self) {
        self.run_best_effort(&["flush", "chain", FAMILY, TABLE, LEGACY_CHAIN])
            .await;
        self.run_best_effort(&["delete", "chain", FAMILY, TABLE, LEGACY_CHAIN])
            .await;
    }

    /// Create both family sets (idempotent: `add set` tolerates existing ones).
    async fn add_sets(&self, jail: &str) -> Result<()> {
        let [v4, v6] = set_names(jail);
        self.run_nft(&["add", "set", FAMILY, TABLE, &v4, &set_block("ipv4_addr")])
            .await?;
        self.run_nft(&["add", "set", FAMILY, TABLE, &v6, &set_block("ipv6_addr")])
            .await
    }

    /// List one set and parse its elements. A nonzero exit (missing set,
    /// permission failure) is an error, never "empty".
    async fn list_set(&self, set: &str) -> Result<HashSet<IpAddr>> {
        let args = ["list", "set", FAMILY, TABLE, set];
        let output = cmd::output(&self.nft_path, "nft", &args).await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::firewall(format!(
                "nft list set failed for {set}: {}",
                stderr.trim()
            )));
        }
        Ok(parse_set_elements(&lossy(&output.stdout)))
    }
}

#[async_trait::async_trait]
impl FirewallBackend for NftablesBackend {
    async fn init(&self, jail: &str, ports: &[String], protocol: &str) -> Result<()> {
        let chain = chain_name(jail);
        self.run_nft(&["add", "table", FAMILY, TABLE]).await?;
        self.remove_legacy_chain().await;
        self.run_nft(&["add", "chain", FAMILY, TABLE, &chain, CHAIN_SPEC])
            .await?;
        // Flushing makes re-init idempotent: rules from an earlier init (maybe
        // with other ports) are dropped instead of accumulating. Sets — and so
        // active bans — are untouched.
        self.run_nft(&["flush", "chain", FAMILY, TABLE, &chain])
            .await?;
        self.add_sets(jail).await?;
        for rule in rule_exprs(jail, ports, protocol) {
            self.run_nft(&["add", "rule", FAMILY, TABLE, &chain, &rule])
                .await?;
        }
        Ok(())
    }

    async fn teardown(&self, jail: &str) -> Result<()> {
        // The chain goes first: nft refuses to delete a set that a rule still
        // references (EBUSY). Every rule referencing this jail's sets lives in
        // the jail's own chain, so deleting it releases both sets.
        let chain = chain_name(jail);
        self.run_best_effort(&["flush", "chain", FAMILY, TABLE, &chain])
            .await;
        self.run_best_effort(&["delete", "chain", FAMILY, TABLE, &chain])
            .await;
        for set in set_names(jail) {
            self.run_best_effort(&["flush", "set", FAMILY, TABLE, &set])
                .await;
            self.run_best_effort(&["delete", "set", FAMILY, TABLE, &set])
                .await;
        }
        Ok(())
    }

    async fn teardown_full(&self, _jail: &str) -> Result<()> {
        // Deleting the table removes every jail's chain, sets, and rules —
        // including a legacy shared `f2b-chain` — so nothing leaks after exit.
        self.run_best_effort(&["delete", "table", FAMILY, TABLE])
            .await;
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
        let set_name = set_name_for_ip(jail, ip);
        let elem = element_spec(ip, expires_at, now);
        self.run_nft(&["add", "element", FAMILY, TABLE, &set_name, &elem])
            .await
    }

    async fn unban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        let set_name = set_name_for_ip(jail, ip);
        let elem = format!("{{ {ip} }}");
        // An element may already be gone (kernel timeout expired it, or it was
        // never present). Treat that as success rather than a hard error.
        if let Err(e) = self
            .run_nft(&["delete", "element", FAMILY, TABLE, &set_name, &elem])
            .await
        {
            debug!(%ip, jail = %jail, error = %e, "nft unban: element absent or already expired");
        }
        Ok(())
    }

    async fn is_banned(&self, ip: &IpAddr, jail: &str) -> Result<bool> {
        let set_name = set_name_for_ip(jail, ip);
        Ok(self.list_set(&set_name).await?.contains(ip))
    }

    async fn snapshot(&self, jail: &str) -> Result<Option<HashSet<IpAddr>>> {
        let mut all = HashSet::new();
        for set in set_names(jail) {
            all.extend(self.list_set(&set).await?);
        }
        Ok(Some(all))
    }

    fn name(&self) -> &'static str {
        "nftables"
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
#[path = "nftables_test.rs"]
mod nftables_test;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
#[path = "nftables_ops_test.rs"]
mod nftables_ops_test;
