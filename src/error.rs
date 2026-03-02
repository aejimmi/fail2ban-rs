//! Error types for fail2ban-rs.

use std::net::IpAddr;
use std::path::PathBuf;

use thiserror::Error;

/// Convenience alias used throughout the library.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("config error: {message}")]
    Config { message: String },

    #[error("config file not found: {path}")]
    ConfigNotFound { path: PathBuf },

    #[error("io error: {context}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid regex pattern: {pattern}")]
    Regex {
        pattern: String,
        #[source]
        source: regex::Error,
    },

    #[error("firewall error: {message}")]
    Firewall { message: String },

    #[error("etch error: {0}")]
    Etch(#[from] etchdb::Error),

    #[error("protocol error: {message}")]
    Protocol { message: String },

    #[error("channel closed")]
    ChannelClosed,

    #[error("ip already banned: {ip} in jail {jail}")]
    AlreadyBanned { ip: IpAddr, jail: String },

    #[error("ip not banned: {ip} in jail {jail}")]
    NotBanned { ip: IpAddr, jail: String },
}

impl Error {
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config {
            message: message.into(),
        }
    }

    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    pub fn firewall(message: impl Into<String>) -> Self {
        Self::Firewall {
            message: message.into(),
        }
    }

    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol {
            message: message.into(),
        }
    }
}
