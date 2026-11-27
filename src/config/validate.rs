//! Configuration validation: cross-field and semantic checks applied after the
//! typed deserialize.

use regex::Regex;

use super::types::{
    Backend, Config, GlobalConfig, JailConfig, LogBackend, LoggingConfig, MaxmindField,
};
use crate::detect::pattern;
use crate::enforce::{ipset, nftables};
use crate::error::{Error, Result};

/// Longest jail name the ipset backend can use.
///
/// ipset caps set names at `IPSET_MAXNAMELEN - 1` = 31 characters, and the
/// longest name generated per jail is `f2b-<jail>6` — four leading characters
/// plus one trailing.
const IPSET_MAX_JAIL_NAME: usize = 26;

/// Longest iptables chain name accepted for the ipset match rule.
const IPSET_MAX_CHAIN_LEN: usize = 28;

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
        self.validate_abuseipdb()?;
        self.validate_set_name_collisions()
    }

    fn validate_abuseipdb(&self) -> Result<()> {
        if let Some(config) = &self.global.abuseipdb
            && !config.api_key_file.is_absolute()
        {
            return Err(Error::config(
                "global.abuseipdb.api_key_file must be absolute",
            ));
        }
        for (name, jail) in self.enabled_jails() {
            let Some(report) = &jail.abuseipdb else {
                continue;
            };
            if self.global.abuseipdb.is_none() {
                return Err(Error::config(format!(
                    "jail '{name}' requires global.abuseipdb"
                )));
            }
            if matches!(jail.backend, Backend::Script { .. }) {
                return Err(Error::config(format!(
                    "jail '{name}': AbuseIPDB requires a native firewall backend"
                )));
            }
            if report.categories.is_empty()
                || report.categories.len() > 30
                || report.categories.iter().any(|id| !(1..=23).contains(id))
            {
                return Err(Error::config(format!(
                    "jail '{name}': invalid AbuseIPDB categories"
                )));
            }
            if report.description.trim().is_empty() || report.description.len() > 1024 {
                return Err(Error::config(format!(
                    "jail '{name}': invalid AbuseIPDB description"
                )));
            }
        }
        Ok(())
    }

    /// Reject pairs of enabled jails whose generated set names collide.
    ///
    /// A jail's IPv6 set is named after the jail plus a backend-specific
    /// suffix, so jail `foo` and jail `foo<suffix>` on the *same* backend
    /// would share a set (nftables: `foo` + `foo-v6`; ipset: `foo` +
    /// `foo6`). A name ending in the suffix is fine on its own (`smtp465`),
    /// and across backends the namespaces are separate.
    fn validate_set_name_collisions(&self) -> Result<()> {
        let enabled: Vec<(&str, &Backend)> = self
            .enabled_jails()
            .map(|(name, jail)| (name, &jail.backend))
            .collect();
        for &(name, backend) in &enabled {
            let Some((label, suffix)) = v6_set_suffix(backend) else {
                continue;
            };
            let twin = format!("{name}{suffix}");
            let clash = enabled
                .iter()
                .any(|&(other, b)| other == twin && v6_set_suffix(b) == Some((label, suffix)));
            if clash {
                return Err(Error::config(format!(
                    "jails '{name}' and '{twin}' collide on the {label} backend \
                     (the IPv4 set of '{twin}' would be the IPv6 set of '{name}', \
                     suffix '{suffix}'); rename one of them"
                )));
            }
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

    /// Validate the firewall backend selection and its per-backend settings.
    fn validate_jail_backend(name: &str, jail: &JailConfig) -> Result<()> {
        Self::validate_backend_jail_name(name, &jail.backend)?;
        match jail.backend {
            Backend::Script {
                ref ban_cmd,
                ref unban_cmd,
            } => Self::validate_script_backend(name, ban_cmd, unban_cmd),
            Backend::Ipset { maxelem, ref chain } => {
                Self::validate_ipset_backend(name, maxelem, chain)
            }
            Backend::Nftables | Backend::Iptables => Ok(()),
        }
    }

    /// Reject jail names reserved by a backend.
    ///
    /// nftables: jail `chain` owns chain `f2b-chain`, the legacy chain every
    /// jail's init deletes. Cross-jail set-name collisions are checked by
    /// `validate_set_name_collisions`.
    fn validate_backend_jail_name(name: &str, backend: &Backend) -> Result<()> {
        if matches!(backend, Backend::Nftables) && name == nftables::LEGACY_JAIL_NAME {
            return Err(Error::config(format!(
                "jail '{name}': name is reserved by the nftables backend \
                 (its chain would be the legacy chain that every jail's \
                 startup deletes, silently disabling this jail)"
            )));
        }
        Ok(())
    }

    /// Both script commands must be present — an empty one silently drops bans.
    fn validate_script_backend(name: &str, ban_cmd: &str, unban_cmd: &str) -> Result<()> {
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
        Ok(())
    }

    /// Validate ipset settings: name length, set capacity, and chain name.
    ///
    /// Every command is built as an argv vector, so the chain check is
    /// fail-fast UX — a typo surfaces at load instead of as a confusing
    /// `iptables` error at startup — not an injection control.
    fn validate_ipset_backend(name: &str, maxelem: u32, chain: &str) -> Result<()> {
        if name.len() > IPSET_MAX_JAIL_NAME {
            return Err(Error::config(format!(
                "jail '{name}': ipset backend requires a jail name of at most \
                 {IPSET_MAX_JAIL_NAME} characters (ipset set names are capped at 31)"
            )));
        }
        if maxelem == 0 {
            return Err(Error::config(format!(
                "jail '{name}': ipset maxelem must be >= 1"
            )));
        }
        // A leading hyphen (e.g. "-F") would reach iptables as something that
        // looks like a flag; iptables rejects it, but only at runtime where
        // rule insertion is non-fatal — so refuse it at load instead.
        let chain_ok = !chain.is_empty()
            && !chain.starts_with('-')
            && chain.len() <= IPSET_MAX_CHAIN_LEN
            && chain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if !chain_ok {
            return Err(Error::config(format!(
                "jail '{name}': ipset chain '{chain}' must be 1-{IPSET_MAX_CHAIN_LEN} \
                 characters of alphanumeric, hyphen, underscore, not starting \
                 with a hyphen"
            )));
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

/// The backend label and IPv6-set suffix for backends that name per-jail
/// sets; `None` for backends without named sets.
fn v6_set_suffix(backend: &Backend) -> Option<(&'static str, &'static str)> {
    match backend {
        Backend::Nftables => Some(("nftables", nftables::V6_SET_SUFFIX)),
        Backend::Ipset { .. } => Some(("ipset", ipset::V6_SET_SUFFIX)),
        Backend::Iptables | Backend::Script { .. } => None,
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

#[cfg(test)]
#[path = "validate_backend_test.rs"]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
mod validate_backend_test;
