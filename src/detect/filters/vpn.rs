//! Built-in filter definitions for VPN servers.

use super::FilterTemplate;

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "vpn_test.rs"]
mod vpn_test;

/// Filter templates for VPN servers.
pub const FILTERS: &[FilterTemplate] = &[
    FilterTemplate {
        name: "openvpn",
        description: "OpenVPN authentication failures",
        log_path: "/var/log/syslog",
        date_format: "syslog",
        patterns: &[
            r"ovpn-.* <HOST>:\d+ TLS Auth Error",
            r"ovpn-.* <HOST>:\d+.*AUTH_FAILED",
        ],
    },
    FilterTemplate {
        name: "softethervpn",
        description: "SoftEther VPN authentication failures",
        log_path: "/usr/local/vpnserver/security_log/DEFAULT/sec.log",
        date_format: "iso8601",
        patterns: &[r"User authentication failed.* from <HOST>"],
    },
];
