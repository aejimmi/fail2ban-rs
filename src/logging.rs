//! Structured logging via the Tell SDK.
//!
//! Wraps the `tell` crate to send structured log entries with severity
//! levels. When the `tell` feature is disabled, all types exist as no-ops.

use std::net::IpAddr;

use crate::config::LoggingConfig;

#[cfg(feature = "tell")]
use tell::{Tell, TellConfig, TellConfigBuilder, props};
#[cfg(feature = "tell")]
use tracing::{info, warn};

/// Minimum severity level for log filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "tell")]
enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
}

#[cfg(feature = "tell")]
impl LogLevel {
    fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "debug" => Self::Debug,
            "warn" | "warning" => Self::Warning,
            "error" => Self::Error,
            _ => Self::Info,
        }
    }
}

/// Structured logger backed by the Tell SDK.
///
/// Clone is cheap — all clones share the same background worker.
/// When the `tell` feature is disabled, this is a no-op placeholder.
#[derive(Clone)]
pub struct Logger {
    #[cfg(feature = "tell")]
    client: Tell,
    #[cfg(feature = "tell")]
    service: String,
    #[cfg(feature = "tell")]
    min_level: LogLevel,
}

impl Logger {
    /// Initialize the logger from config.
    ///
    /// Returns `None` if `destination` is absent or not `"tell"`,
    /// if `api_key` is missing/invalid, or if the `tell` feature is disabled.
    #[cfg(feature = "tell")]
    pub fn init(config: &LoggingConfig) -> Option<Self> {
        let dest = config.destination.as_deref()?;
        if dest != "tell" {
            return None;
        }

        let api_key = config.api_key.as_deref()?;

        let mut builder: TellConfigBuilder = TellConfig::builder(api_key);
        if let Some(ref endpoint) = config.endpoint {
            builder = builder.endpoint(endpoint.clone());
        }
        builder = builder.on_error(|e| {
            warn!(error = %e, "tell SDK error");
        });

        match builder.build() {
            Ok(tell_config) => match Tell::new(tell_config) {
                Ok(client) => {
                    let service = config
                        .service
                        .clone()
                        .unwrap_or_else(|| "fail2ban-rs".to_string());
                    let min_level = LogLevel::parse(config.level.as_deref().unwrap_or("info"));
                    info!(service = %service, "remote logging enabled");
                    Some(Self {
                        client,
                        service,
                        min_level,
                    })
                }
                Err(e) => {
                    warn!(error = %e, "failed to create Tell client");
                    None
                }
            },
            Err(e) => {
                warn!(error = %e, "invalid Tell config");
                None
            }
        }
    }

    /// When the `tell` feature is disabled, always returns `None`.
    #[cfg(not(feature = "tell"))]
    pub fn init(_config: &LoggingConfig) -> Option<Self> {
        None
    }

    /// Log a ban event.
    #[cfg(feature = "tell")]
    pub fn log_ban(&self, ip: IpAddr, jail: &str, ban_time: i64, manual: bool) {
        if self.min_level > LogLevel::Info {
            return;
        }
        self.client.log_info(
            &format!("banned {ip} in {jail}"),
            Some(&self.service),
            props! {
                "component" => "tracker",
                "jail" => jail,
                "ip" => ip.to_string(),
                "ban_time" => ban_time,
                "manual" => manual
            },
        );
    }

    /// Log a ban event (no-op without tell).
    #[cfg(not(feature = "tell"))]
    #[allow(clippy::unused_self)]
    pub fn log_ban(&self, _ip: IpAddr, _jail: &str, _ban_time: i64, _manual: bool) {}

    /// Log an unban event.
    #[cfg(feature = "tell")]
    pub fn log_unban(&self, ip: IpAddr, jail: &str, manual: bool) {
        if self.min_level > LogLevel::Info {
            return;
        }
        self.client.log_info(
            &format!("unbanned {ip} from {jail}"),
            Some(&self.service),
            props! {
                "component" => "tracker",
                "jail" => jail,
                "ip" => ip.to_string(),
                "manual" => manual
            },
        );
    }

    /// Log an unban event (no-op without tell).
    #[cfg(not(feature = "tell"))]
    #[allow(clippy::unused_self)]
    pub fn log_unban(&self, _ip: IpAddr, _jail: &str, _manual: bool) {}

    /// Log daemon startup.
    #[cfg(feature = "tell")]
    pub fn log_startup(&self, jail_count: usize, restored_bans: usize) {
        if self.min_level > LogLevel::Info {
            return;
        }
        self.client.log_info(
            "daemon started",
            Some(&self.service),
            props! {
                "component" => "server",
                "jail_count" => jail_count,
                "restored_bans" => restored_bans
            },
        );
    }

    /// Log daemon startup (no-op without tell).
    #[cfg(not(feature = "tell"))]
    #[allow(clippy::unused_self)]
    pub fn log_startup(&self, _jail_count: usize, _restored_bans: usize) {}

    /// Log config reload.
    #[cfg(feature = "tell")]
    pub fn log_reload(&self, jail_count: usize) {
        if self.min_level > LogLevel::Info {
            return;
        }
        self.client.log_info(
            "config reloaded",
            Some(&self.service),
            props! {
                "component" => "server",
                "jail_count" => jail_count
            },
        );
    }

    /// Log config reload (no-op without tell).
    #[cfg(not(feature = "tell"))]
    #[allow(clippy::unused_self)]
    pub fn log_reload(&self, _jail_count: usize) {}

    /// Log a firewall error.
    #[cfg(feature = "tell")]
    pub fn log_error(&self, message: &str, ip: IpAddr, jail: &str) {
        self.client.log_error(
            message,
            Some(&self.service),
            props! {
                "component" => "executor",
                "jail" => jail,
                "ip" => ip.to_string()
            },
        );
    }

    /// Log a firewall error (no-op without tell).
    #[cfg(not(feature = "tell"))]
    #[allow(clippy::unused_self)]
    pub fn log_error(&self, _message: &str, _ip: IpAddr, _jail: &str) {}

    /// Gracefully close the Tell client on shutdown.
    #[cfg(feature = "tell")]
    pub async fn close(self) {
        if let Err(e) = self.client.close().await {
            warn!(error = %e, "error closing Tell client");
        }
    }

    /// Gracefully close (no-op without tell).
    #[cfg(not(feature = "tell"))]
    #[allow(clippy::unused_async)]
    pub async fn close(self) {}
}
