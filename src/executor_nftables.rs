//! Nftables firewall backend.

use std::net::IpAddr;
use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::executor::FirewallBackend;

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
            "{ type ipv4_addr; flags interval; }",
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
            "{ type ipv6_addr; flags interval; }",
        ])
        .await?;
        // Add rules matching ports + set -> reject.
        if !ports.is_empty() {
            let port_list = ports.join(",");
            let rule_v4 = format!("{protocol} dport {{ {port_list} }} ip saddr @{set_name} reject");
            self.run_nft(&["add", "rule", "inet", "fail2ban-rs", "f2b-chain", &rule_v4])
                .await?;
            let rule_v6 = format!("{protocol} dport {{ {port_list} }} ip6 saddr @{set_v6} reject");
            self.run_nft(&["add", "rule", "inet", "fail2ban-rs", "f2b-chain", &rule_v6])
                .await?;
        } else {
            // No ports specified: match all traffic from banned IPs.
            let rule_v4 = format!("ip saddr @{set_name} reject");
            self.run_nft(&["add", "rule", "inet", "fail2ban-rs", "f2b-chain", &rule_v4])
                .await?;
            let rule_v6 = format!("ip6 saddr @{set_v6} reject");
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

    async fn ban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        let set_name = format!("f2b-{jail}");
        self.run_nft(&[
            "add",
            "element",
            "inet",
            "fail2ban-rs",
            &set_name,
            &format!("{{{ip}}}"),
        ])
        .await
    }

    async fn unban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        let set_name = format!("f2b-{jail}");
        self.run_nft(&[
            "delete",
            "element",
            "inet",
            "fail2ban-rs",
            &set_name,
            &format!("{{{ip}}}"),
        ])
        .await
    }

    async fn is_banned(&self, ip: &IpAddr, jail: &str) -> Result<bool> {
        let set_name = format!("f2b-{jail}");
        let output = tokio::process::Command::new(&self.nft_path)
            .args(["list", "set", "inet", "fail2ban-rs", &set_name])
            .output()
            .await
            .map_err(|e| Error::firewall(format!("nft command failed: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let ip_str = ip.to_string();
        Ok(stdout.split_whitespace().any(|token| token == ip_str))
    }

    fn name(&self) -> &str {
        "nftables"
    }
}
