//! Built-in filter definitions for FTP servers.

use super::FilterTemplate;

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "ftp_test.rs"]
mod ftp_test;

/// Filter templates for FTP servers.
pub const FILTERS: &[FilterTemplate] = &[
    FilterTemplate {
        name: "gssftpd",
        description: "GSS-FTP (Kerberos FTP) authentication failures",
        log_path: "/var/log/auth.log",
        date_format: "syslog",
        patterns: &[r"ftpd\[\d+\]: repeated login failures from <HOST>"],
    },
    FilterTemplate {
        name: "proftpd",
        description: "ProFTPD FTP authentication failures",
        log_path: "/var/log/auth.log",
        date_format: "syslog",
        patterns: &[
            r"proftpd\[\d+\].*?\([^\[]+\[<HOST>\]\).*Login failed",
            r"proftpd\[\d+\].*?\([^\[]+\[<HOST>\]\).*no such user",
            r"proftpd\[\d+\].*?\([^\[]+\[<HOST>\]\).*Incorrect password",
            r"proftpd\[\d+\].*?\([^\[]+\[<HOST>\]\).*SECURITY VIOLATION",
            r"proftpd\[\d+\].*?\([^\[]+\[<HOST>\]\).*Maximum login attempts",
        ],
    },
    FilterTemplate {
        name: "pure-ftpd",
        description: "Pure-FTPd authentication failures",
        log_path: "/var/log/auth.log",
        date_format: "syslog",
        patterns: &[r"pure-ftpd: \(.+?@<HOST>\) \[WARNING\]"],
    },
    FilterTemplate {
        name: "vsftpd",
        description: "vsftpd FTP login failures",
        log_path: "/var/log/vsftpd.log",
        date_format: "syslog",
        patterns: &[r#"vsftpd.*FAIL LOGIN: Client "<HOST>""#],
    },
    FilterTemplate {
        name: "wuftpd",
        description: "WU-FTPD authentication failures",
        log_path: "/var/log/auth.log",
        date_format: "syslog",
        patterns: &[r"wu-ftpd\[\d+\]: failed login from .* \[<HOST>\]"],
    },
];
