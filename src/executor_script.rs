//! Custom script firewall backend.
//!
//! Runs user-defined ban/unban commands with `<IP>` and `<JAIL>` tag
//! substitution.

use std::net::IpAddr;

use crate::error::{Error, Result};
use crate::executor::FirewallBackend;

/// Script backend with configurable ban/unban commands.
pub struct ScriptBackend {
    ban_cmd: String,
    unban_cmd: String,
}

impl ScriptBackend {
    pub fn new(ban_cmd: String, unban_cmd: String) -> Self {
        Self { ban_cmd, unban_cmd }
    }

    fn substitute(template: &str, ip: &IpAddr, jail: &str) -> String {
        template
            .replace("<IP>", &ip.to_string())
            .replace("<JAIL>", jail)
    }

    async fn run_cmd(cmd_line: &str) -> Result<()> {
        let output = tokio::process::Command::new("sh")
            .args(["-c", cmd_line])
            .output()
            .await
            .map_err(|e| Error::firewall(format!("script command failed: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::firewall(format!(
                "script exit {}: {stderr}",
                output.status
            )));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl FirewallBackend for ScriptBackend {
    async fn init(&self, _jail: &str, _ports: &[String], _protocol: &str) -> Result<()> {
        Ok(())
    }

    async fn teardown(&self, _jail: &str) -> Result<()> {
        Ok(())
    }

    async fn ban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        let cmd = Self::substitute(&self.ban_cmd, ip, jail);
        Self::run_cmd(&cmd).await
    }

    async fn unban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        let cmd = Self::substitute(&self.unban_cmd, ip, jail);
        Self::run_cmd(&cmd).await
    }

    async fn is_banned(&self, _ip: &IpAddr, _jail: &str) -> Result<bool> {
        // Script backend can't check — always return false.
        Ok(false)
    }

    fn name(&self) -> &str {
        "script"
    }
}
