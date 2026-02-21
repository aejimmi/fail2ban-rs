//! fail2ban-rs — A pure-Rust replacement for fail2ban.
//!
//! Single static binary, fast two-phase matching, nftables/iptables firewall backends.

pub mod ban_calc;
pub mod circular;
pub mod config;
pub mod control;
pub mod date;
pub mod duration;
pub mod error;
pub mod executor;
pub mod executor_iptables;
pub mod executor_nftables;
pub mod executor_script;
pub mod filters;
pub mod ignore;
pub mod logging;
pub mod matcher;
pub mod pattern;
pub mod regex_tool;
pub mod server;
pub mod state;
pub mod tracker;
pub mod watcher;
#[cfg(feature = "systemd")]
pub mod watcher_journal;
pub mod webhook;

#[cfg(test)]
mod ban_calc_test;
#[cfg(test)]
mod circular_test;
#[cfg(test)]
mod config_test;
#[cfg(test)]
mod control_test;
#[cfg(test)]
mod date_test;
#[cfg(test)]
mod duration_test;
#[cfg(test)]
mod error_test;
#[cfg(test)]
mod executor_test;
#[cfg(test)]
mod filters_test;
#[cfg(test)]
mod ignore_test;
#[cfg(test)]
mod logging_test;
#[cfg(test)]
mod matcher_test;
#[cfg(test)]
mod pattern_test;
#[cfg(test)]
mod regex_tool_test;
#[cfg(test)]
mod server_test;
#[cfg(test)]
mod state_test;
#[cfg(test)]
mod tracker_test;
#[cfg(test)]
mod watcher_test;
#[cfg(test)]
mod webhook_test;
