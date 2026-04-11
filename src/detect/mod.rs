//! Detection pipeline — read logs, find attackers.
//!
//! Tails log files (or the systemd journal), matches lines against
//! per-jail filter patterns, and emits [`watcher::Failure`] events.

/// Log line timestamp parsing.
pub mod date;
/// Built-in filter templates for common services.
pub mod filters;
/// IP allowlist and local-address detection.
pub mod ignore;
/// Systemd journal log source.
pub mod journal;
/// Two-phase log matching engine.
pub mod matcher;
/// Pattern compilation and `<HOST>` expansion.
pub mod pattern;
/// Log file tailer with rotation detection.
pub mod watcher;
