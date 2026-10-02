//! fail2ban-rs — A pure-Rust replacement for fail2ban.
//!
//! Single static binary, fast two-phase matching, nftables/iptables firewall backends.

pub mod config;
pub mod control;
pub mod detect;
pub mod duration;
pub mod enforce;
pub mod error;
pub mod log_format;
pub mod logging;
pub mod regex_tool;
pub mod server;
pub mod text;
pub mod track;
pub mod webhook;

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
mod security_test;
