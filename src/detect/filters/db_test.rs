use super::*;
use crate::detect::filters::test_util::assert_filter_matches;

/// (filter_name, log_line, expected_ip) rows exercised against the live registry.
const MATCH_CASES: &[(&str, &str, &str)] = &[
    (
        "mssql-auth",
        "2020-02-24 16:05:21.00 Logon       Login failed for user 'Backend'. Reason: Could not find a login matching the name provided. [CLIENT: 192.0.2.1]",
        "192.0.2.1",
    ),
    (
        "mysqld",
        "130324  0:04:00 [Warning] Access denied for user 'root'@'192.168.1.35' (using password: NO)",
        "192.168.1.35",
    ),
];

#[test]
fn match_samples() {
    for &(name, line, ip) in MATCH_CASES {
        assert_filter_matches(name, line, ip);
    }
}

/// Every sample row targets a filter that lives in this category's table.
#[test]
fn cases_target_this_category() {
    let names: std::collections::HashSet<&str> = FILTERS.iter().map(|f| f.name).collect();
    for &(name, ..) in MATCH_CASES {
        assert!(
            names.contains(name),
            "match case for '{name}' is not in this category"
        );
    }
}
