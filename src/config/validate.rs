//! Configuration validation: cross-field and semantic checks applied after the
//! typed deserialize.

use regex::Regex;

use super::types::{
    Backend, Config, GlobalConfig, JailConfig, LogBackend, LoggingConfig, MaxmindField,
};
use crate::detect::pattern;
use crate::error::{Error, Result};

impl Config {
    /// Validate all configuration values.
    pub(super) fn validate(&self) -> Result<()> {
        Self::validate_global(&self.global)?;
        Self::validate_logging(&self.logging)?;

        if self.jail.is_empty() {
            return Err(Error::config("no jails defined"));
        }

        let enabled_count = self.jail.values().filter(|j| j.enabled).count();
        if enabled_count == 0 {
            return Err(Error::config("no enabled jails"));
        }

        for (name, jail) in &self.jail {
            Self::validate_jail(name, jail, &self.global)?;
        }

        Ok(())
    }

    /// Validate global daemon settings.
    fn validate_global(global: &GlobalConfig) -> Result<()> {
        if global.channel_size < 1 {
            return Err(Error::config("global.channel_size must be >= 1"));
        }
        if global.ban_count_decay < 0 {
            return Err(Error::config(
                "global.ban_count_decay must be >= 0 (\"0\" disables decay)",
            ));
        }
        Ok(())
    }

    /// Validate the logging section, rejecting unknown enumerated strings so
    /// they fail loudly at load instead of silently degrading to defaults.
    fn validate_logging(logging: &LoggingConfig) -> Result<()> {
        if let Some(dest) = logging.destination.as_deref()
            && dest != "tell"
        {
            return Err(Error::config(format!(
                "logging.destination: unknown value '{dest}' (supported: tell)"
            )));
        }
        if let Some(level) = logging.level.as_deref()
            && !crate::logging::is_valid_level(level)
        {
            return Err(Error::config(format!(
                "logging.level: unknown value '{level}' (expected debug, info, warn, or error)"
            )));
        }
        if let Some(format) = logging.format.as_deref()
            && !crate::log_format::LogFormat::is_known(format)
        {
            return Err(Error::config(format!(
                "logging.format: unknown value '{format}' (expected logfmt or json)"
            )));
        }
        Ok(())
    }

    /// Validate a jail's name and, when enabled, all of its settings.
    fn validate_jail(name: &str, jail: &JailConfig, global: &GlobalConfig) -> Result<()> {
        Self::validate_jail_name(name)?;

        if !jail.enabled {
            return Ok(());
        }

        if jail.log_backend == LogBackend::File && jail.log_path.as_os_str().is_empty() {
            return Err(Error::config(format!(
                "jail '{name}': log_path is required when log_backend = \"file\""
            )));
        }

        Self::validate_jail_filters(name, jail)?;
        Self::validate_jail_timing(name, jail)?;
        Self::validate_jail_bantime(name, jail)?;
        Self::validate_jail_backend(name, jail)?;
        Self::validate_jail_network(name, jail)?;
        Self::validate_jail_maxmind(name, jail, global)
    }

    /// Jail names are interpolated into nft set names and script commands, so
    /// restrict them to `[A-Za-z0-9_-]{1,64}`.
    fn validate_jail_name(name: &str) -> Result<()> {
        if name.is_empty() || name.len() > 64 {
            return Err(Error::config(format!(
                "jail '{name}': name must be 1-64 characters"
            )));
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(Error::config(format!(
                "jail '{name}': name must contain only alphanumeric, hyphen, underscore"
            )));
        }
        Ok(())
    }

    /// Validate filter and ignoreregex patterns, compiling each through the
    /// same path the matcher uses so bad regexes fail at load, not at startup.
    fn validate_jail_filters(name: &str, jail: &JailConfig) -> Result<()> {
        if jail.filter.is_empty() {
            return Err(Error::config(format!("jail '{name}': no filter patterns")));
        }
        for pat in &jail.filter {
            let expanded = pattern::expand_host(pat)
                .map_err(|e| Error::config(format!("jail '{name}': {e}")))?;
            Regex::new(&expanded).map_err(|e| {
                Error::config(format!("jail '{name}': invalid filter regex '{pat}': {e}"))
            })?;
        }
        for (i, pat) in jail.ignoreregex.iter().enumerate() {
            Regex::new(pat).map_err(|e| {
                Error::config(format!(
                    "jail '{name}': invalid ignoreregex[{i}] '{pat}': {e}"
                ))
            })?;
        }
        Ok(())
    }

    /// Validate detection-window and ban-duration timing.
    fn validate_jail_timing(name: &str, jail: &JailConfig) -> Result<()> {
        if jail.max_retry == 0 {
            return Err(Error::config(format!(
                "jail '{name}': max_retry must be > 0"
            )));
        }
        if jail.find_time <= 0 {
            return Err(Error::config(format!(
                "jail '{name}': find_time must be > 0"
            )));
        }
        // -1 means permanent; 0 and values below -1 are meaningless.
        if jail.ban_time == 0 || jail.ban_time < -1 {
            return Err(Error::config(format!(
                "jail '{name}': ban_time must be > 0 or -1 for permanent"
            )));
        }
        Ok(())
    }

    /// Validate escalating-ban parameters.
    fn validate_jail_bantime(name: &str, jail: &JailConfig) -> Result<()> {
        if jail.bantime_maxtime <= 0 {
            return Err(Error::config(format!(
                "jail '{name}': bantime_maxtime must be > 0"
            )));
        }
        if jail.bantime_multipliers.contains(&0) {
            return Err(Error::config(format!(
                "jail '{name}': bantime_multipliers entries must all be > 0"
            )));
        }
        if !jail.bantime_factor.is_finite() || jail.bantime_factor <= 0.0 {
            return Err(Error::config(format!(
                "jail '{name}': bantime_factor must be finite and positive"
            )));
        }
        Ok(())
    }

    /// Validate the firewall backend selection.
    fn validate_jail_backend(name: &str, jail: &JailConfig) -> Result<()> {
        if let Backend::Script {
            ref ban_cmd,
            ref unban_cmd,
        } = jail.backend
        {
            if ban_cmd.trim().is_empty() {
                return Err(Error::config(format!(
                    "jail '{name}': script backend requires non-empty ban_cmd"
                )));
            }
            if unban_cmd.trim().is_empty() {
                return Err(Error::config(format!(
                    "jail '{name}': script backend requires non-empty unban_cmd"
                )));
            }
        }
        Ok(())
    }

    /// Validate ports, protocol, ignoreip entries, and the webhook URL.
    fn validate_jail_network(name: &str, jail: &JailConfig) -> Result<()> {
        for port in &jail.port {
            match port.parse::<u16>() {
                Ok(n) if n >= 1 => {}
                _ => {
                    return Err(Error::config(format!(
                        "jail '{name}': invalid port '{port}' (expected 1-65535)"
                    )));
                }
            }
        }
        if !["tcp", "udp", "sctp", "dccp"].contains(&jail.protocol.as_str()) {
            return Err(Error::config(format!(
                "jail '{name}': protocol must be tcp, udp, sctp, or dccp"
            )));
        }
        for entry in &jail.ignoreip {
            crate::detect::ignore::parse_entry(entry).map_err(|_| {
                Error::config(format!(
                    "jail '{name}': invalid ignoreip entry '{entry}' (expected IP or CIDR)"
                ))
            })?;
        }
        if let Some(url) = &jail.webhook
            && !url.starts_with("http://")
            && !url.starts_with("https://")
        {
            return Err(Error::config(format!(
                "jail '{name}': webhook URL must start with http:// or https://"
            )));
        }
        Ok(())
    }

    /// Ensure any per-jail MaxMind field has its global database path set.
    fn validate_jail_maxmind(name: &str, jail: &JailConfig, global: &GlobalConfig) -> Result<()> {
        for field in &jail.maxmind {
            let (present, which) = match field {
                MaxmindField::Asn => (global.maxmind_asn.is_some(), "maxmind_asn"),
                MaxmindField::Country => (global.maxmind_country.is_some(), "maxmind_country"),
                MaxmindField::City => (global.maxmind_city.is_some(), "maxmind_city"),
            };
            if !present {
                return Err(Error::config(format!(
                    "jail '{name}': maxmind requires global {which} database path to be set"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "validate_test.rs"]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
mod validate_test;
