use super::*;
use crate::detect::filters::test_util::assert_filter_matches;

/// (filter_name, log_line, expected_ip) rows exercised against the live registry.
const MATCH_CASES: &[(&str, &str, &str)] = &[
    (
        "openvpn",
        "Apr 25 11:19:22 ovpn-server[13821]: 192.0.2.254:64480 TLS Auth Error: Auth Username/Password verification failed for peer",
        "192.0.2.254",
    ),
    (
        "softethervpn",
        r#"2020-05-12 10:53:19.781 Connection "CID-72": User authentication failed. The user name that has been provided was "bob", from 80.10.11.12."#,
        "80.10.11.12",
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
