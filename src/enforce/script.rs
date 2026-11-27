//! Custom script firewall backend.
//!
//! Runs user-defined ban/unban commands with `<IP>` and `<JAIL>` tag
//! substitution.

use crate::ban_target::BanTarget;

use crate::enforce::{FirewallBackend, cmd};
use crate::error::{Error, Result};

/// Script backend with configurable ban/unban commands.
pub struct ScriptBackend {
    ban_cmd: String,
    unban_cmd: String,
}

impl ScriptBackend {
    /// Build a backend from ban/unban command templates.
    pub fn new(ban_cmd: String, unban_cmd: String) -> Self {
        Self { ban_cmd, unban_cmd }
    }

    /// Validate a jail name before it is substituted into a shell command.
    ///
    /// Defense-in-depth: even though jail names are meant to be validated at
    /// config load time, this backend runs templates through `sh -c`, so it
    /// re-checks here and refuses to run rather than trusting the caller. Only
    /// `[A-Za-z0-9_-]{1,64}` is permitted — anything that could carry shell
    /// metacharacters (`;`, `$( )`, backticks, spaces, quotes) is rejected.
    fn validate_jail_name(jail: &str) -> Result<()> {
        let ok = (1..=64).contains(&jail.len())
            && jail
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if !ok {
            return Err(Error::firewall(format!(
                "script backend: refusing unsafe jail name {jail:?}"
            )));
        }
        Ok(())
    }

    fn substitute(template: &str, ip: &BanTarget, jail: &str) -> String {
        template
            .replace("<IP>", &ip.to_string())
            .replace("<JAIL>", jail)
    }

    /// Run a command via `sh -c` under the shared command timeout, so a
    /// hung user script is killed instead of freezing the executor. This
    /// uses shell execution, but is safe because `ip` is a validated `BanTarget`
    /// (cannot contain shell metacharacters) and `jail` is validated by
    /// [`Self::validate_jail_name`] before substitution.
    async fn run_cmd(cmd_line: &str) -> Result<()> {
        cmd::run("sh", "script", &["-c", cmd_line]).await
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

    async fn ban(&self, ip: &BanTarget, jail: &str) -> Result<()> {
        Self::validate_jail_name(jail)?;
        let cmd = Self::substitute(&self.ban_cmd, ip, jail);
        Self::run_cmd(&cmd).await
    }

    async fn unban(&self, ip: &BanTarget, jail: &str) -> Result<()> {
        Self::validate_jail_name(jail)?;
        let cmd = Self::substitute(&self.unban_cmd, ip, jail);
        Self::run_cmd(&cmd).await
    }

    async fn is_banned(&self, _ip: &BanTarget, _jail: &str) -> Result<bool> {
        // Script backend can't check — always return false. `can_verify`
        // reports this so reconcile skips the backend instead of re-running
        // the ban script for every active ban each tick.
        Ok(false)
    }

    fn can_verify(&self) -> bool {
        false
    }

    fn name(&self) -> &'static str {
        "script"
    }
}

#[cfg(test)]
#[path = "script_test.rs"]
mod script_test;
