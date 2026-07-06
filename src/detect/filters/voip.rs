//! Built-in filter definitions for VoIP / telephony servers.

use super::FilterTemplate;

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "voip_test.rs"]
mod voip_test;

/// Filter templates for VoIP / telephony servers.
pub const FILTERS: &[FilterTemplate] = &[
    FilterTemplate {
        name: "asterisk",
        description: "Asterisk VoIP SIP registration failures",
        log_path: "/var/log/asterisk/messages",
        date_format: "iso8601",
        patterns: &[
            r"NOTICE.* <HOST> failed to authenticate",
            r#"SECURITY.* SecurityEvent="FailedACL".*RemoteAddress.*<HOST>"#,
        ],
    },
    FilterTemplate {
        name: "freeswitch",
        description: "FreeSWITCH VoIP SIP authentication failures",
        log_path: "/var/log/freeswitch/freeswitch.log",
        date_format: "iso8601",
        patterns: &[
            r"SIP auth (?:failure|challenge).* from ip <HOST>",
            r"Can.t find user .* from <HOST>",
        ],
    },
    FilterTemplate {
        name: "murmur",
        description: "Mumble/Murmur VoIP server authentication failures",
        log_path: "/var/log/mumble-server/mumble-server.log",
        date_format: "iso8601",
        patterns: &[
            r"Rejected connection from <HOST>:\d+: (?:Invalid server password|Wrong certificate)",
        ],
    },
];
