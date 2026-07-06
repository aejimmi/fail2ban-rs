//! Error types for fail2ban-rs.

use std::net::IpAddr;
use std::path::PathBuf;

use thiserror::Error;

/// Convenience alias used throughout the library.
pub type Result<T> = std::result::Result<T, Error>;

/// The library-wide error type covering every fallible subsystem.
#[derive(Debug, Error)]
pub enum Error {
    /// Configuration is invalid (bad value, missing field, parse failure).
    #[error("config error: {message}")]
    Config {
        /// Human-readable description of what was wrong with the config.
        message: String,
    },

    /// The requested config file does not exist on disk.
    #[error("config file not found: {path}")]
    ConfigNotFound {
        /// Path that was expected to hold the config file.
        path: PathBuf,
    },

    /// An I/O operation failed; `context` describes what was being attempted.
    #[error("io error: {context}")]
    Io {
        /// Description of the operation that failed (e.g. "reading file").
        context: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A regular expression failed to compile.
    #[error("invalid regex pattern: {pattern}")]
    Regex {
        /// The pattern that could not be compiled.
        pattern: String,
        /// The underlying regex compilation error.
        #[source]
        source: regex::Error,
    },

    /// A firewall backend operation failed.
    #[error("firewall error: {message}")]
    Firewall {
        /// Human-readable description of the firewall failure.
        message: String,
    },

    /// A persistence-layer operation failed.
    ///
    /// Owns no third-party types so a semver bump of the storage backend cannot
    /// break this crate's public API. The underlying error's detail is folded
    /// into `message` at the call site.
    #[error("persistence error: {message}")]
    Persistence {
        /// Context plus the underlying persistence error's `Display` output.
        message: String,
    },

    /// The persisted state's on-disk schema is incompatible with this build.
    #[error("incompatible state schema: {message}")]
    SchemaMismatch {
        /// Human-readable description of the schema incompatibility.
        message: String,
    },

    /// A control-protocol message was malformed or could not be handled.
    #[error("protocol error: {message}")]
    Protocol {
        /// Human-readable description of the protocol failure.
        message: String,
    },

    /// A channel used for inter-task communication was closed unexpectedly.
    #[error("channel closed")]
    ChannelClosed,

    /// A ban was requested for an IP that is already banned in the jail.
    #[error("ip already banned: {ip} in jail {jail}")]
    AlreadyBanned {
        /// The IP address that was already banned.
        ip: IpAddr,
        /// The jail the IP is banned in.
        jail: String,
    },

    /// An unban was requested for an IP that is not banned in the jail.
    #[error("ip not banned: {ip} in jail {jail}")]
    NotBanned {
        /// The IP address that was not banned.
        ip: IpAddr,
        /// The jail the IP was expected to be banned in.
        jail: String,
    },
}

impl Error {
    /// Construct a [`Error::Config`] from any string-like message.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config {
            message: message.into(),
        }
    }

    /// Construct a [`Error::Io`] wrapping `source` with a describing `context`.
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    /// Construct a [`Error::Firewall`] from any string-like message.
    pub fn firewall(message: impl Into<String>) -> Self {
        Self::Firewall {
            message: message.into(),
        }
    }

    /// Construct a [`Error::Protocol`] from any string-like message.
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol {
            message: message.into(),
        }
    }

    /// Construct a [`Error::Persistence`] from any string-like message.
    ///
    /// Callers fold the underlying backend error's `Display` into `message`
    /// (e.g. `format!("opening WAL: {e}")`) so detail is retained without
    /// leaking the backend's error type into this crate's public API.
    pub fn persistence(message: impl Into<String>) -> Self {
        Self::Persistence {
            message: message.into(),
        }
    }

    /// Construct a [`Error::SchemaMismatch`] from any string-like message.
    pub fn schema_mismatch(message: impl Into<String>) -> Self {
        Self::SchemaMismatch {
            message: message.into(),
        }
    }
}

#[cfg(test)]
#[path = "error_test.rs"]
mod error_test;
