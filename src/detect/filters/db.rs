//! Built-in filter definitions for database servers.

use super::FilterTemplate;

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "db_test.rs"]
mod db_test;

/// Filter templates for database servers.
pub const FILTERS: &[FilterTemplate] = &[
    FilterTemplate {
        name: "mssql-auth",
        description: "Microsoft SQL Server authentication failures",
        log_path: "/var/opt/mssql/log/errorlog",
        date_format: "iso8601",
        patterns: &[r"Login failed for user .*\[CLIENT: <HOST>\]"],
    },
    FilterTemplate {
        name: "mysqld",
        description: "MySQL/MariaDB authentication failures",
        log_path: "/var/log/mysql/error.log",
        date_format: "iso8601",
        patterns: &[
            r"Access denied for user .*@'<HOST>'",
            r"Access denied for user .* from '<HOST>'",
        ],
    },
];
