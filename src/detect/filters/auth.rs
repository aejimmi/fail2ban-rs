//! Built-in filter definitions for authentication / SSH.

use super::FilterTemplate;

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "auth_test.rs"]
mod auth_test;

/// Filter templates for authentication / SSH.
pub const FILTERS: &[FilterTemplate] = &[
    FilterTemplate {
        name: "dropbear",
        description: "Dropbear SSH authentication failures",
        log_path: "/var/log/auth.log",
        date_format: "syslog",
        patterns: &[
            r"dropbear\[\d+\].*[Bb]ad password attempt for .* from <HOST>:\d+",
            r"dropbear\[\d+\].*[Ll]ogin attempt for nonexistent user.*from <HOST>:\d+",
            r"dropbear\[\d+\].*[Ee]xit before auth.*from .?<HOST>:\d+",
        ],
    },
    FilterTemplate {
        name: "pam-generic",
        description: "Generic PAM authentication failures",
        log_path: "/var/log/auth.log",
        date_format: "syslog",
        patterns: &[r"pam_unix.*authentication failure;.* rhost=<HOST>"],
    },
    FilterTemplate {
        name: "selinux-ssh",
        description: "SELinux SSH access denials",
        log_path: "/var/log/audit/audit.log",
        date_format: "epoch",
        patterns: &[r"addr=<HOST>.*terminal=ssh.*res=failed"],
    },
    FilterTemplate {
        name: "sshd",
        description: "OpenSSH daemon — brute force and invalid user detection",
        log_path: "/var/log/auth.log",
        date_format: "syslog",
        patterns: &[
            r"sshd\[\d+\]: Failed password for .* from <HOST> port \d+",
            r"sshd\[\d+\]: Invalid user .* from <HOST> port \d+",
            r"sshd\[\d+\]: Connection closed by authenticating user .* <HOST> port \d+",
            r"sshd\[\d+\]: Disconnected from authenticating user .* <HOST> port \d+",
        ],
    },
];
