//! Iptables firewall backend.

use std::net::IpAddr;

use crate::error::{Error, Result};
use crate::executor::FirewallBackend;

/// Iptables backend — uses `iptables`/`ip6tables` commands.
#[derive(Default)]
pub struct IptablesBackend;

impl IptablesBackend {
    pub fn new() -> Self {
        Self
    }

    fn cmd_name(ip: &IpAddr) -> &'static str {
        match ip {
            IpAddr::V4(_) => "iptables",
            IpAddr::V6(_) => "ip6tables",
        }
    }

    async fn run(cmd: &str, args: &[&str]) -> Result<()> {
        let output = tokio::process::Command::new(cmd)
            .args(args)
            .output()
            .await
            .map_err(|e| Error::firewall(format!("{cmd} command failed: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::firewall(format!(
                "{cmd} exit {}: {stderr}",
                output.status
            )));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl FirewallBackend for IptablesBackend {
    async fn init(&self, jail: &str, ports: &[String], protocol: &str) -> Result<()> {
        let chain = format!("f2b-{jail}");
        for cmd in &["iptables", "ip6tables"] {
            // Create chain with default RETURN.
            Self::run(cmd, &["-N", &chain]).await.ok();
            Self::run(cmd, &["-A", &chain, "-j", "RETURN"]).await.ok();
            // Insert jump rule in INPUT.
            if ports.is_empty() {
                Self::run(cmd, &["-I", "INPUT", "-j", &chain]).await.ok();
            } else {
                let port_list = ports.join(",");
                Self::run(cmd, &[
                    "-I", "INPUT", "-p", protocol,
                    "-m", "multiport", "--dports", &port_list,
                    "-j", &chain,
                ]).await.ok();
            }
        }
        Ok(())
    }

    async fn teardown(&self, jail: &str) -> Result<()> {
        let chain = format!("f2b-{jail}");
        for cmd in &["iptables", "ip6tables"] {
            // Delete INPUT jump rule (best effort).
            Self::run(cmd, &["-D", "INPUT", "-j", &chain]).await.ok();
            // Flush and delete chain.
            Self::run(cmd, &["-F", &chain]).await.ok();
            Self::run(cmd, &["-X", &chain]).await.ok();
        }
        Ok(())
    }

    async fn ban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        let cmd = Self::cmd_name(ip);
        let chain = format!("f2b-{jail}");
        let ip_str = ip.to_string();
        Self::run(cmd, &["-I", &chain, "-s", &ip_str, "-j", "DROP"]).await
    }

    async fn unban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        let cmd = Self::cmd_name(ip);
        let chain = format!("f2b-{jail}");
        let ip_str = ip.to_string();
        Self::run(cmd, &["-D", &chain, "-s", &ip_str, "-j", "DROP"]).await
    }

    async fn is_banned(&self, ip: &IpAddr, jail: &str) -> Result<bool> {
        let cmd = Self::cmd_name(ip);
        let chain = format!("f2b-{jail}");
        let output = tokio::process::Command::new(cmd)
            .args(["-L", &chain, "-n"])
            .output()
            .await
            .map_err(|e| Error::firewall(format!("{cmd} command failed: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.contains(&ip.to_string()))
    }

    fn name(&self) -> &str {
        "iptables"
    }
}
