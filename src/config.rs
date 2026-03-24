//! TOML configuration loading and validation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::date::DateFormat;
use crate::duration;
use crate::error::{Error, Result};

/// Top-level configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub global: GlobalConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub jail: HashMap<String, JailConfig>,
}

/// Remote logging configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Logging destination. Only "tell" is supported.
    pub destination: Option<String>,

    /// Collector endpoint (host:port).
    pub endpoint: Option<String>,

    /// Tell API key (32 hex chars).
    pub api_key: Option<String>,

    /// Minimum severity level (default: "info").
    pub level: Option<String>,

    /// Service name (default: "fail2ban-rs").
    pub service: Option<String>,
}

/// Global daemon settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// Directory to persist ban state across restarts (etch WAL).
    #[serde(default = "default_state_dir", alias = "state_file")]
    pub state_dir: PathBuf,

    /// Unix socket path for CLI communication.
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,

    /// Logging level.
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Bounded channel capacity.
    #[serde(default = "default_channel_size")]
    pub channel_size: usize,

    /// Optional path to MaxMind ASN database
    pub maxmind_asn: Option<PathBuf>,

    /// Optional path to MaxMind Country database
    pub maxmind_country: Option<PathBuf>,

    /// Optional path to MaxMind City database
    pub maxmind_city: Option<PathBuf>,
}

/// Per-jail configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JailConfig {
    /// Whether this jail is active.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Path to the log file to monitor.
    pub log_path: PathBuf,

    /// Date format preset for timestamp extraction.
    #[serde(default = "default_date_format")]
    pub date_format: DateFormat,

    /// Patterns with `<HOST>` placeholder.
    pub filter: Vec<String>,

    /// Number of failures before banning.
    #[serde(default = "default_max_retry")]
    pub max_retry: u32,

    /// Time window (seconds or duration string like "10m", "1h").
    #[serde(
        default = "default_find_time",
        deserialize_with = "duration::deserialize_duration"
    )]
    pub find_time: i64,

    /// Ban duration (seconds or duration string; -1 = permanent).
    #[serde(
        default = "default_ban_time",
        deserialize_with = "duration::deserialize_duration"
    )]
    pub ban_time: i64,

    /// Ports to block (e.g. ["22"] or ["80", "443"]).
    #[serde(default)]
    pub port: Vec<String>,

    /// Protocol for port matching (default "tcp").
    #[serde(default = "default_protocol")]
    pub protocol: String,

    /// Enable escalating ban times on repeat offenders.
    #[serde(default)]
    pub bantime_increment: bool,

    /// Multiplier applied to the base ban time (default 1.0).
    #[serde(default = "default_bantime_factor")]
    pub bantime_factor: f64,

    /// Explicit ban time multipliers (e.g. [1, 2, 4, 8, 16]).
    #[serde(default)]
    pub bantime_multipliers: Vec<u32>,

    /// Maximum ban time (seconds or duration string; default 1 week).
    #[serde(
        default = "default_bantime_maxtime",
        deserialize_with = "duration::deserialize_duration"
    )]
    pub bantime_maxtime: i64,

    /// Log source backend (file or systemd journal).
    #[serde(default)]
    pub log_backend: LogBackend,

    /// Systemd journal match filters (e.g. `["_SYSTEMD_UNIT=sshd.service"]`).
    #[serde(default)]
    pub journalmatch: Vec<String>,

    /// Firewall backend.
    #[serde(default)]
    pub backend: Backend,

    /// Regex patterns — lines matching these are ignored even if failregex hits.
    #[serde(default)]
    pub ignoreregex: Vec<String>,

    /// IPs/CIDRs to never ban.
    #[serde(default)]
    pub ignoreip: Vec<String>,

    /// Auto-detect and ignore this machine's own IPs.
    #[serde(default = "default_true")]
    pub ignoreself: bool,

    /// Re-issue ban commands on restart (default true).
    /// Set to false when the firewall state persists independently
    /// (e.g. ipset).
    #[serde(default = "default_true")]
    pub reban_on_restart: bool,

    /// Webhook URL — POST JSON on ban events.
    #[serde(default)]
    pub webhook: Option<String>,

    /// Which MaxMind databases to query for this jail (e.g. ["asn", "country"])
    #[serde(default)]
    pub maxmind: Vec<String>,
}

/// Firewall backend selection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    #[default]
    Nftables,
    Iptables,
    Script {
        ban_cmd: String,
        unban_cmd: String,
    },
}

/// Log source backend selection.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogBackend {
    /// Read from a log file (default).
    #[default]
    File,
    /// Read from the systemd journal (requires `systemd` feature).
    #[cfg(feature = "systemd")]
    Systemd,
}

// Defaults

fn default_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/fail2ban-rs/state")
}

fn default_socket_path() -> PathBuf {
    PathBuf::from("/var/run/fail2ban-rs/fail2ban-rs.sock")
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_channel_size() -> usize {
    1024
}

fn default_true() -> bool {
    true
}

fn default_date_format() -> DateFormat {
    DateFormat::Syslog
}

fn default_max_retry() -> u32 {
    5
}

fn default_find_time() -> i64 {
    600
}

fn default_ban_time() -> i64 {
    3600
}

fn default_protocol() -> String {
    "tcp".to_string()
}

fn default_bantime_factor() -> f64 {
    1.0
}

fn default_bantime_maxtime() -> i64 {
    604800 // 1 week
}

impl Config {
    /// Load and validate configuration from a TOML file.
    ///
    /// After reading the main file, merges any overlays found in a sibling
    /// `config.d/` directory (sorted alphabetically).
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::ConfigNotFound {
                    path: path.to_path_buf(),
                }
            } else {
                Error::io(format!("reading config: {}", path.display()), e)
            }
        })?;

        let mut base: toml::Value = content
            .parse()
            .map_err(|e| Error::config(format!("TOML parse error: {e}")))?;

        // Merge config.d/*.toml overlays if the directory exists.
        if let Some(dir) = path.parent() {
            let config_d = dir.join("config.d");
            if config_d.is_dir() {
                let mut entries: Vec<PathBuf> = std::fs::read_dir(&config_d)
                    .map_err(|e| Error::io(format!("reading {}", config_d.display()), e))?
                    .filter_map(|entry| entry.ok().map(|e| e.path()))
                    .filter(|p| p.extension().is_some_and(|ext| ext == "toml"))
                    .collect();
                entries.sort();

                for overlay_path in entries {
                    let overlay_content = std::fs::read_to_string(&overlay_path).map_err(|e| {
                        Error::io(format!("reading overlay: {}", overlay_path.display()), e)
                    })?;
                    let overlay: toml::Value = overlay_content.parse().map_err(|e| {
                        Error::config(format!(
                            "TOML parse error in {}: {e}",
                            overlay_path.display()
                        ))
                    })?;
                    deep_merge(&mut base, overlay);
                }
            }
        }

        let config: Config = base
            .try_into()
            .map_err(|e| Error::config(format!("config deserialization error: {e}")))?;
        config.validate()?;
        Ok(config)
    }

    /// Parse and validate configuration from a TOML string.
    pub fn parse(content: &str) -> Result<Self> {
        let config: Config =
            toml::from_str(content).map_err(|e| Error::config(format!("TOML parse error: {e}")))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate all configuration values.
    fn validate(&self) -> Result<()> {
        if self.jail.is_empty() {
            return Err(Error::config("no jails defined"));
        }

        let enabled_count = self.jail.values().filter(|j| j.enabled).count();
        if enabled_count == 0 {
            return Err(Error::config("no enabled jails"));
        }

        for (name, jail) in &self.jail {
            Self::validate_jail(name, jail)?;
        }

        Ok(())
    }

    fn validate_jail(name: &str, jail: &JailConfig) -> Result<()> {
        // Jail names: alphanumeric + hyphen + underscore only, max 64 chars.
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

        if !jail.enabled {
            return Ok(());
        }

        if jail.filter.is_empty() {
            return Err(Error::config(format!("jail '{name}': no filter patterns")));
        }

        for pattern in &jail.filter {
            if !pattern.contains("<HOST>") {
                return Err(Error::config(format!(
                    "jail '{name}': pattern missing <HOST>: {pattern}"
                )));
            }
        }

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

        if jail.ban_time == 0 {
            return Err(Error::config(format!(
                "jail '{name}': ban_time must be > 0 or -1 for permanent"
            )));
        }

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

        for port in &jail.port {
            if port.parse::<u16>().is_err() {
                return Err(Error::config(format!(
                    "jail '{name}': invalid port: {port}"
                )));
            }
        }

        if !["tcp", "udp", "sctp", "dccp"].contains(&jail.protocol.as_str()) {
            return Err(Error::config(format!(
                "jail '{name}': protocol must be tcp, udp, sctp, or dccp"
            )));
        }

        if !jail.bantime_factor.is_finite() || jail.bantime_factor <= 0.0 {
            return Err(Error::config(format!(
                "jail '{name}': bantime_factor must be finite and positive"
            )));
        }

        Ok(())
    }

    /// Return only the enabled jails.
    pub fn enabled_jails(&self) -> impl Iterator<Item = (&str, &JailConfig)> {
        self.jail
            .iter()
            .filter(|(_, j)| j.enabled)
            .map(|(name, jail)| (name.as_str(), jail))
    }
}

/// Recursively merge `overlay` into `base`. Tables merge recursively;
/// all other value types are overwritten by the overlay.
fn deep_merge(base: &mut toml::Value, overlay: toml::Value) {
    match overlay {
        toml::Value::Table(overlay_table) => {
            if let toml::Value::Table(base_table) = base {
                for (key, overlay_val) in overlay_table {
                    let entry = base_table
                        .entry(key)
                        .or_insert(toml::Value::Table(toml::map::Map::new()));
                    deep_merge(entry, overlay_val);
                }
            } else {
                *base = toml::Value::Table(overlay_table);
            }
        }
        other => {
            *base = other;
        }
    }
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            state_dir: default_state_dir(),
            socket_path: default_socket_path(),
            log_level: default_log_level(),
            channel_size: default_channel_size(),
            maxmind_asn: None,
            maxmind_country: None,
            maxmind_city: None,
        }
    }
}

impl Default for JailConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            log_path: PathBuf::new(),
            date_format: default_date_format(),
            filter: vec![],
            max_retry: default_max_retry(),
            find_time: default_find_time(),
            ban_time: default_ban_time(),
            port: vec![],
            protocol: default_protocol(),
            bantime_increment: false,
            bantime_factor: default_bantime_factor(),
            bantime_multipliers: vec![],
            bantime_maxtime: default_bantime_maxtime(),
            log_backend: LogBackend::default(),
            journalmatch: vec![],
            backend: Backend::default(),
            ignoreregex: vec![],
            ignoreip: vec![],
            ignoreself: default_true(),
            reban_on_restart: default_true(),
            webhook: None,
            maxmind: vec![],
        }
    }
}
