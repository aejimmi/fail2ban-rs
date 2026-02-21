//! Tests for the two-phase matching engine.

use std::net::{IpAddr, Ipv4Addr};

use crate::matcher::JailMatcher;

fn ssh_patterns() -> Vec<String> {
    vec![
        r"sshd\[\d+\]: Failed password for .* from <HOST>".to_string(),
        r"sshd\[\d+\]: Invalid user .* from <HOST>".to_string(),
    ]
}

#[test]
fn match_failed_password() {
    let m = JailMatcher::new(&ssh_patterns()).unwrap();
    let line = "Jan 15 10:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2";
    let result = m.try_match(line).unwrap();
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
    assert_eq!(result.pattern_idx, 0);
}

#[test]
fn match_invalid_user() {
    let m = JailMatcher::new(&ssh_patterns()).unwrap();
    let line = "Jan 15 10:30:00 server sshd[5678]: Invalid user admin from 10.0.0.50 port 22 ssh2";
    let result = m.try_match(line).unwrap();
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)));
    assert_eq!(result.pattern_idx, 1);
}

#[test]
fn no_match_normal_log() {
    let m = JailMatcher::new(&ssh_patterns()).unwrap();
    let line =
        "Jan 15 10:30:00 server sshd[1234]: Accepted password for user from 192.168.1.1 port 22";
    assert!(m.try_match(line).is_none());
}

#[test]
fn no_match_unrelated() {
    let m = JailMatcher::new(&ssh_patterns()).unwrap();
    let line = "Jan 15 10:30:00 server kernel: CPU0: Core temperature above threshold";
    assert!(m.try_match(line).is_none());
}

#[test]
fn match_ipv6() {
    let patterns = vec![r"from <HOST> port".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "from 2001:db8::1 port 22";
    let result = m.try_match(line).unwrap();
    let expected: IpAddr = "2001:db8::1".parse().unwrap();
    assert_eq!(result.ip, expected);
}

#[test]
fn multiple_patterns_first_wins() {
    let patterns = vec![
        r"Failed .* from <HOST>".to_string(),
        r"from <HOST>".to_string(),
    ];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "Failed login from 1.2.3.4";
    let result = m.try_match(line).unwrap();
    assert_eq!(result.pattern_idx, 0);
}

#[test]
fn empty_patterns_error() {
    assert!(JailMatcher::new(&[]).is_err());
}

#[test]
fn pattern_count() {
    let m = JailMatcher::new(&ssh_patterns()).unwrap();
    assert_eq!(m.pattern_count(), 2);
}

#[test]
fn various_ipv4() {
    let patterns = vec![r"from <HOST>".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();

    let ips = ["1.1.1.1", "255.255.255.255", "10.0.0.1", "172.16.0.1"];
    for ip_str in &ips {
        let line = format!("from {ip_str} something");
        let result = m.try_match(&line);
        assert!(result.is_some(), "failed to match IP: {ip_str}");
        assert_eq!(result.unwrap().ip, ip_str.parse::<IpAddr>().unwrap());
    }
}

#[test]
fn invalid_ip_returns_none() {
    // 999.999.999.999 matches the regex \d{1,3}... but fails IpAddr::parse.
    let patterns = vec![r"from <HOST> port".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "from 999.999.999.999 port 22";
    // The regex matches but the IP is unparseable — should return None.
    assert!(m.try_match(line).is_none());
}

#[test]
fn no_ac_prefix_still_matches() {
    // Pattern starts with regex metachar — no usable AC prefix.
    let patterns = vec![r"\d+ failures from <HOST>".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "5 failures from 10.0.0.1 end";
    let result = m.try_match(line).unwrap();
    assert_eq!(result.ip, "10.0.0.1".parse::<IpAddr>().unwrap());
}

#[test]
fn ac_passes_but_regex_fails() {
    // The literal prefix "from " appears but the full regex doesn't match.
    let patterns = vec![r"Failed .* from <HOST> port \d+".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    // "from " is present but "Failed" is not.
    let line = "Accepted from 1.2.3.4 port 22";
    assert!(m.try_match(line).is_none());
}

#[test]
fn empty_line() {
    let m = JailMatcher::new(&ssh_patterns()).unwrap();
    assert!(m.try_match("").is_none());
}

// ---------------------------------------------------------------------------
// ignoreregex tests
// ---------------------------------------------------------------------------

#[test]
fn ignoreregex_suppresses_match() {
    let patterns = vec![r"from <HOST> port".to_string()];
    let ignore = vec![r"Accepted".to_string()];
    let m = JailMatcher::with_ignoreregex(&patterns, &ignore).unwrap();

    // Line matches failregex but also matches ignoreregex.
    let line = "Accepted login from 1.2.3.4 port 22";
    assert!(m.try_match(line).is_none());
}

#[test]
fn ignoreregex_does_not_suppress_non_matching() {
    let patterns = vec![r"Failed .* from <HOST> port".to_string()];
    let ignore = vec![r"Accepted".to_string()];
    let m = JailMatcher::with_ignoreregex(&patterns, &ignore).unwrap();

    // Line matches failregex but NOT ignoreregex.
    let line = "Failed login from 1.2.3.4 port 22";
    let result = m.try_match(line).unwrap();
    assert_eq!(result.ip, "1.2.3.4".parse::<IpAddr>().unwrap());
}

#[test]
fn ignoreregex_empty_is_noop() {
    let patterns = vec![r"from <HOST> port".to_string()];
    let m = JailMatcher::with_ignoreregex(&patterns, &[]).unwrap();
    let line = "from 1.2.3.4 port 22";
    assert!(m.try_match(line).is_some());
}

#[test]
fn ignoreregex_multiple_patterns() {
    let patterns = vec![r"from <HOST> port".to_string()];
    let ignore = vec![r"Accepted".to_string(), r"internal".to_string()];
    let m = JailMatcher::with_ignoreregex(&patterns, &ignore).unwrap();

    // Matches second ignoreregex.
    let line = "internal from 1.2.3.4 port 22";
    assert!(m.try_match(line).is_none());

    // Doesn't match either ignoreregex.
    let line2 = "Failed from 1.2.3.4 port 22";
    assert!(m.try_match(line2).is_some());
}
