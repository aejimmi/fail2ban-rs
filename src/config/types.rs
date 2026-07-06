//! Configuration types, defaults, and their `Default` implementations.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::detect::date::DateFormat;
use crate::duration;

/// Top-level configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub global: GlobalConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub jail: HashMap<String, JailConfig>,
}

/// Remote logging configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

    /// Stderr output format: "logfmt" (default) or "json".
    ///
    /// Under systemd, each line is also prefixed with `<N>` so journald sets
    /// PRIORITY per-entry. Systemd strips the prefix before MESSAGE is stored.
    pub format: Option<String>,
}

/// Global daemon settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalConfig {
    /// Directory to persist ban state across restarts (etch WAL).
    #[serde(default = "default_state_dir", alias = "state_file")]
    pub state_dir: PathBuf,

    /// Unix socket path for CLI communication.
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,

    /// Bounded channel capacity.
    #[serde(default = "default_channel_size")]
    pub channel_size: usize,

    /// How long a per-IP escalation count survives without a new ban before it
    /// is reset (seconds or duration string like `"30d"`). `"0"` disables
    /// decay, keeping counts forever. Default 30 days.
    #[serde(
        default = "default_ban_count_decay",
        deserialize_with = "duration::deserialize_duration"
    )]
    pub ban_count_decay: i64,

    /// Optional path to MaxMind ASN database
    pub maxmind_asn: Option<PathBuf>,

    /// Optional path to MaxMind Country database
    pub maxmind_country: Option<PathBuf>,

    /// Optional path to MaxMind City database
    pub maxmind_city: Option<PathBuf>,
}

/// Per-jail configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailConfig {
    /// Whether this jail is active.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Path to the log file to monitor.
    #[serde(default)]
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

    /// Ports to block (e.g. `["22"]` or `["80", "443"]`).
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

    /// Which MaxMind databases to query for this jail (e.g. `["asn", "country"]`).
    #[serde(default)]
    pub maxmind: Vec<MaxmindField>,
}

/// MaxMind database type selector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MaxmindField {
    /// GeoLite2-ASN — autonomous system number and organization.
    Asn,
    /// GeoLite2-Country — country name.
    Country,
    /// GeoLite2-City — city name.
    City,
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
    /// Read from the systemd journal via `journalctl`.
    Systemd,
}

// Defaults

pub(super) fn default_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/fail2ban-rs/state")
}

pub(super) fn default_socket_path() -> PathBuf {
    PathBuf::from("/var/run/fail2ban-rs/fail2ban-rs.sock")
}

pub(super) fn default_channel_size() -> usize {
    1024
}

pub(super) fn default_ban_count_decay() -> i64 {
    2_592_000 // 30 days
}

pub(super) fn default_true() -> bool {
    true
}

pub(super) fn default_date_format() -> DateFormat {
    DateFormat::Syslog
}

pub(super) fn default_max_retry() -> u32 {
    5
}

pub(super) fn default_find_time() -> i64 {
    600
}

pub(super) fn default_ban_time() -> i64 {
    3600
}

pub(super) fn default_protocol() -> String {
    "tcp".to_string()
}

pub(super) fn default_bantime_factor() -> f64 {
    1.0
}

pub(super) fn default_bantime_maxtime() -> i64 {
    604_800 // 1 week
}

impl Config {
    /// Return only the enabled jails.
    pub fn enabled_jails(&self) -> impl Iterator<Item = (&str, &JailConfig)> {
        self.jail
            .iter()
            .filter(|(_, j)| j.enabled)
            .map(|(name, jail)| (name.as_str(), jail))
    }
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            state_dir: default_state_dir(),
            socket_path: default_socket_path(),
            channel_size: default_channel_size(),
            ban_count_decay: default_ban_count_decay(),
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

#[cfg(test)]
#[path = "types_test.rs"]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
mod types_test;
