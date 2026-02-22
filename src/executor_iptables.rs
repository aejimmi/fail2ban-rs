//! Iptables firewall backend.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use tracing::{debug, warn};

use crate::error::{Error, Result};
use crate::executor::FirewallBackend;

/// Iptables backend — uses `iptables`/`ip6tables` resolved at startup.
pub struct IptablesBackend {
    iptables_path: PathBuf,
    ip6tables_path: PathBuf,
}

impl IptablesBackend {
    pub fn new(iptables_path: PathBuf, ip6tables_path: PathBuf) -> Self {
        Self {
            iptables_path,
            ip6tables_path,
        }
    }

    fn cmd_path(&self, ip: &IpAddr) -> &Path {
        match ip {
            IpAddr::V4(_) => &self.iptables_path,
            IpAddr::V6(_) => &self.ip6tables_path,
        }
    }

    async fn run(cmd: &Path, args: &[&str]) -> Result<()> {
        let output = tokio::process::Command::new(cmd)
            .args(args)
            .output()
            .await
            .map_err(|e| Error::firewall(format!("{} command failed: {e}", cmd.display())))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::firewall(format!(
                "{} exit {}: {stderr}",
                cmd.display(),
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
        for cmd in [&self.iptables_path, &self.ip6tables_path] {
            // Create chain with default RETURN (may already exist).
            if let Err(e) = Self::run(cmd, &["-N", &chain]).await {
                debug!(cmd = %cmd.display(), jail = %jail, error = %e, "chain creation failed (may already exist)");
            }
            if let Err(e) = Self::run(cmd, &["-A", &chain, "-j", "RETURN"]).await {
                debug!(cmd = %cmd.display(), jail = %jail, error = %e, "RETURN rule failed (may already exist)");
            }
            // Insert jump rule in INPUT.
            if ports.is_empty() {
                if let Err(e) = Self::run(cmd, &["-I", "INPUT", "-j", &chain]).await {
                    warn!(cmd = %cmd.display(), jail = %jail, error = %e, "failed to insert INPUT jump rule");
                }
            } else {
                let port_list = ports.join(",");
                if let Err(e) = Self::run(
                    cmd,
                    &[
                        "-I",
                        "INPUT",
                        "-p",
                        protocol,
                        "-m",
                        "multiport",
                        "--dports",
                        &port_list,
                        "-j",
                        &chain,
                    ],
                )
                .await
                {
                    warn!(cmd = %cmd.display(), jail = %jail, error = %e, "failed to insert INPUT jump rule");
                }
            }
        }
        Ok(())
    }

    async fn teardown(&self, jail: &str) -> Result<()> {
        let chain = format!("f2b-{jail}");
        for cmd in [&self.iptables_path, &self.ip6tables_path] {
            // Delete INPUT jump rule (best effort).
            Self::run(cmd, &["-D", "INPUT", "-j", &chain]).await.ok();
            // Flush and delete chain.
            Self::run(cmd, &["-F", &chain]).await.ok();
            Self::run(cmd, &["-X", &chain]).await.ok();
        }
        Ok(())
    }

    async fn ban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        let cmd = self.cmd_path(ip);
        let chain = format!("f2b-{jail}");
        let ip_str = ip.to_string();
        Self::run(cmd, &["-I", &chain, "-s", &ip_str, "-j", "DROP"]).await
    }

    async fn unban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        let cmd = self.cmd_path(ip);
        let chain = format!("f2b-{jail}");
        let ip_str = ip.to_string();
        Self::run(cmd, &["-D", &chain, "-s", &ip_str, "-j", "DROP"]).await
    }

    async fn is_banned(&self, ip: &IpAddr, jail: &str) -> Result<bool> {
        let cmd = self.cmd_path(ip);
        let chain = format!("f2b-{jail}");
        let output = tokio::process::Command::new(cmd)
            .args(["-L", &chain, "-n"])
            .output()
            .await
            .map_err(|e| Error::firewall(format!("{} command failed: {e}", cmd.display())))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let ip_str = ip.to_string();
        Ok(stdout.split_whitespace().any(|token| token == ip_str))
    }

    fn name(&self) -> &str {
        "iptables"
    }
}
