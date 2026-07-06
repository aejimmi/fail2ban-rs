//! Nftables firewall backend.

use std::net::IpAddr;
use std::path::PathBuf;

use tracing::debug;

use crate::enforce::FirewallBackend;
use crate::error::{Error, Result};

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

/// Nftables backend — uses `nft` command resolved at startup.
pub struct NftablesBackend {
    nft_path: PathBuf,
}

impl NftablesBackend {
    pub fn new(nft_path: PathBuf) -> Self {
        Self { nft_path }
    }

    async fn run_nft(&self, args: &[&str]) -> Result<()> {
        let output = tokio::process::Command::new(&self.nft_path)
            .args(args)
            .output()
            .await
            .map_err(|e| Error::firewall(format!("nft command failed: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::firewall(format!(
                "nft exit {}: {stderr}",
                output.status
            )));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl FirewallBackend for NftablesBackend {
    async fn init(&self, jail: &str, ports: &[String], protocol: &str) -> Result<()> {
        // Create table if it doesn't exist.
        self.run_nft(&["add", "table", "inet", "fail2ban-rs"])
            .await?;
        // Create base chain for filtering input.
        self.run_nft(&[
            "add",
            "chain",
            "inet",
            "fail2ban-rs",
            "f2b-chain",
            "{ type filter hook input priority -1; policy accept; }",
        ])
        .await
        .ok(); // ignore if already exists
        // Create IPv4 set.
        let set_name = format!("f2b-{jail}");
        self.run_nft(&[
            "add",
            "set",
            "inet",
            "fail2ban-rs",
            &set_name,
            &set_block("ipv4_addr"),
        ])
        .await?;
        // Create IPv6 set.
        let set_v6 = format!("f2b-{jail}-v6");
        self.run_nft(&[
            "add",
            "set",
            "inet",
            "fail2ban-rs",
            &set_v6,
            &set_block("ipv6_addr"),
        ])
        .await?;
        // Add rules matching ports + set -> reject.
        if ports.is_empty() {
            // No ports specified: match all traffic from banned IPs.
            let rule_v4 = format!("ip saddr @{set_name} reject");
            self.run_nft(&["add", "rule", "inet", "fail2ban-rs", "f2b-chain", &rule_v4])
                .await?;
            let rule_v6 = format!("ip6 saddr @{set_v6} reject");
            self.run_nft(&["add", "rule", "inet", "fail2ban-rs", "f2b-chain", &rule_v6])
                .await?;
        } else {
            let port_list = ports.join(",");
            let rule_v4 = format!("{protocol} dport {{ {port_list} }} ip saddr @{set_name} reject");
            self.run_nft(&["add", "rule", "inet", "fail2ban-rs", "f2b-chain", &rule_v4])
                .await?;
            let rule_v6 = format!("{protocol} dport {{ {port_list} }} ip6 saddr @{set_v6} reject");
            self.run_nft(&["add", "rule", "inet", "fail2ban-rs", "f2b-chain", &rule_v6])
                .await?;
        }
        Ok(())
    }

    async fn teardown(&self, jail: &str) -> Result<()> {
        let set_name = format!("f2b-{jail}");
        let set_v6 = format!("f2b-{jail}-v6");
        // Flush and delete sets (rules referencing them are removed by nft).
        self.run_nft(&["flush", "set", "inet", "fail2ban-rs", &set_name])
            .await
            .ok();
        self.run_nft(&["delete", "set", "inet", "fail2ban-rs", &set_name])
            .await
            .ok();
        self.run_nft(&["flush", "set", "inet", "fail2ban-rs", &set_v6])
            .await
            .ok();
        self.run_nft(&["delete", "set", "inet", "fail2ban-rs", &set_v6])
            .await
            .ok();
        Ok(())
    }

    async fn teardown_full(&self, _jail: &str) -> Result<()> {
        // Deleting the shared table removes every jail's sets, the base chain,
        // and all rules in one shot — nothing leaks after daemon shutdown.
        self.run_nft(&["delete", "table", "inet", "fail2ban-rs"])
            .await
            .ok();
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
        let set_name = format!("f2b-{jail}");
        let elem = element_spec(ip, expires_at, now);
        self.run_nft(&["add", "element", "inet", "fail2ban-rs", &set_name, &elem])
            .await
    }

    async fn unban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        let set_name = format!("f2b-{jail}");
        let elem = format!("{{ {ip} }}");
        // An element may already be gone (kernel timeout expired it, or it was
        // never present). Treat that as success rather than a hard error.
        if let Err(e) = self
            .run_nft(&["delete", "element", "inet", "fail2ban-rs", &set_name, &elem])
            .await
        {
            debug!(%ip, jail = %jail, error = %e, "nft unban: element absent or already expired");
        }
        Ok(())
    }

    async fn is_banned(&self, ip: &IpAddr, jail: &str) -> Result<bool> {
        let set_name = format!("f2b-{jail}");
        let output = tokio::process::Command::new(&self.nft_path)
            .args(["list", "set", "inet", "fail2ban-rs", &set_name])
            .output()
            .await
            .map_err(|e| Error::firewall(format!("nft command failed: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::firewall(format!(
                "nft list set failed for {set_name}: {}",
                stderr.trim()
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let ip_str = ip.to_string();
        Ok(stdout.split_whitespace().any(|token| token == ip_str))
    }

    fn name(&self) -> &'static str {
        "nftables"
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
#[path = "nftables_test.rs"]
mod nftables_test;
