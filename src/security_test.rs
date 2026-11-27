//! Security-focused tests — malicious inputs, injection attempts, edge cases.

use std::net::IpAddr;

use crate::ban_target::BanTarget;

use crate::config::Config;
use crate::detect::matcher::JailMatcher;
use crate::duration::parse_duration;

// ---------------------------------------------------------------------------
// Matcher security tests
// ---------------------------------------------------------------------------

#[test]
fn crafted_username_with_embedded_ip() {
    // A username containing a valid IP shouldn't spoof the attacker address.
    // The real attacker is 10.0.0.1, embedded in the username is 192.168.1.99.
    let matcher = JailMatcher::new(&["Failed password for .* from <HOST>".into()]).unwrap();
    let line = "Failed password for 192.168.1.99 from 10.0.0.1 port 22";
    let result = matcher.try_match(line).unwrap();
    // The extracted IP should be the one after "from", not the embedded one.
    assert_eq!(result.ip, "10.0.0.1".parse::<IpAddr>().unwrap());
}

#[test]
fn extremely_long_line_no_panic() {
    let matcher = JailMatcher::new(&["Failed password for .* from <HOST>".into()]).unwrap();
    // 1 MB of 'A' — should not panic or OOM.
    let line = "A".repeat(1_000_000);
    let result = matcher.try_match(&line);
    assert!(result.is_none());
}

#[test]
fn null_bytes_in_line() {
    let matcher = JailMatcher::new(&["Failed password for .* from <HOST>".into()]).unwrap();
    let line = "Failed password for root from 10.0.0.1\0 port 22";
    // Should not crash — may or may not match depending on regex engine.
    let _ = matcher.try_match(line);
}

#[test]
fn unicode_in_log_line() {
    let matcher = JailMatcher::new(&["Failed password for .* from <HOST>".into()]).unwrap();
    let line = "Failed password for r\u{00f6}\u{00f6}t from 10.0.0.1 port 22";
    let result = matcher.try_match(line).unwrap();
    assert_eq!(result.ip, "10.0.0.1".parse::<IpAddr>().unwrap());
}

#[test]
fn ip_followed_by_unicode() {
    let matcher = JailMatcher::new(&["Failed password for .* from <HOST>".into()]).unwrap();
    // Non-ASCII right after the IP — the regex HOST group matches the IP
    // portion only (digits/dots/colons), so unicode after it is excluded
    // from the match span and the IP is still extracted correctly.
    let line = "Failed password for root from 10.0.0.1\u{2603} port 22";
    let result = matcher.try_match(line).unwrap();
    assert_eq!(result.ip, "10.0.0.1".parse::<IpAddr>().unwrap());
}

#[test]
fn invalid_ip_octets_rejected() {
    let matcher = JailMatcher::new(&["from <HOST>".into()]).unwrap();
    let line = "from 999.999.999.999";
    let result = matcher.try_match(line);
    assert!(result.is_none());
}

#[test]
fn ipv6_various_forms() {
    let matcher = JailMatcher::new(&["from <HOST>".into()]).unwrap();

    // Full form
    let line = "from 2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    let result = matcher.try_match(line).unwrap();
    assert!(result.ip.is_ipv6());

    // Compressed
    let line = "from ::1";
    let result = matcher.try_match(line).unwrap();
    assert_eq!(result.ip, "::1".parse::<IpAddr>().unwrap());

    // Mixed
    let line = "from 2001:db8::1";
    let result = matcher.try_match(line).unwrap();
    assert!(result.ip.is_ipv6());
}

// ---------------------------------------------------------------------------
// Config validation security tests
// ---------------------------------------------------------------------------

fn jail_toml(name: &str) -> String {
    format!(
        r#"
[global]

[jail.{name}]
log_path = "/var/log/auth.log"
filter = ['from <HOST>']
"#
    )
}

fn jail_toml_with_protocol(protocol: &str) -> String {
    format!(
        r#"
[global]

[jail.sshd]
log_path = "/var/log/auth.log"
filter = ['from <HOST>']
protocol = "{protocol}"
"#
    )
}

fn jail_toml_with_bantime_factor(factor: &str) -> String {
    format!(
        r#"
[global]

[jail.sshd]
log_path = "/var/log/auth.log"
filter = ['from <HOST>']
bantime_factor = {factor}
"#
    )
}

fn jail_toml_with_port(port: &str) -> String {
    format!(
        r#"
[global]

[jail.sshd]
log_path = "/var/log/auth.log"
filter = ['from <HOST>']
port = ["{port}"]
"#
    )
}

#[test]
fn jail_name_rejects_shell_metacharacters() {
    for bad in &["ssh;rm -rf /", "ssh|cat", "$(whoami)", "ssh`id`"] {
        let toml = jail_toml(bad);
        let err = Config::parse(&toml);
        assert!(err.is_err(), "should reject jail name: {bad}");
    }
}

#[test]
fn jail_name_rejects_path_traversal() {
    let toml = jail_toml("../etc/passwd");
    assert!(Config::parse(&toml).is_err());
}

#[test]
fn jail_name_rejects_empty() {
    // Empty jail name — TOML won't really produce this naturally, but
    // test the validator directly.
    let toml = r#"
[global]

[jail.""]
log_path = "/var/log/auth.log"
filter = ['from <HOST>']
"#;
    assert!(Config::parse(toml).is_err());
}

#[test]
fn jail_name_accepts_valid() {
    for name in &["sshd", "nginx-auth", "my_jail", "postfix2"] {
        let toml = jail_toml(name);
        assert!(
            Config::parse(&toml).is_ok(),
            "should accept jail name: {name}"
        );
    }
}

#[test]
fn port_validation_rejects_invalid() {
    for bad in &["abc", "99999", ""] {
        let toml = jail_toml_with_port(bad);
        let err = Config::parse(&toml);
        assert!(err.is_err(), "should reject port: {bad}");
    }
}

#[test]
fn port_validation_accepts_valid() {
    for port in &["22", "443", "8080"] {
        let toml = jail_toml_with_port(port);
        assert!(Config::parse(&toml).is_ok(), "should accept port: {port}");
    }
}

// ---------------------------------------------------------------------------
// Script backend — IP cannot inject shell commands
// ---------------------------------------------------------------------------

#[test]
fn script_ip_cannot_inject_shell() {
    // BanTarget::to_string() is safe — verify it never produces shell metacharacters.
    let ips: Vec<BanTarget> = vec![
        "127.0.0.1".parse().unwrap(),
        "::1".parse().unwrap(),
        "255.255.255.255".parse().unwrap(),
        "2001:db8::1234/64".parse().unwrap(),
        "2001:db8::1".parse().unwrap(),
        "fe80::1".parse().unwrap(),
    ];
    let dangerous = [
        ';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\'', '"', '\\', '\n',
    ];
    for ip in &ips {
        let s = ip.to_string();
        for ch in &dangerous {
            assert!(
                !s.contains(*ch),
                "IP {ip} serialized as '{s}' contains dangerous char '{ch}'"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Duration overflow tests
// ---------------------------------------------------------------------------

#[test]
fn duration_overflow_returns_error() {
    let result = parse_duration("999999999999999w");
    assert!(
        result.is_err(),
        "huge duration should return error, not panic"
    );
}

#[test]
fn duration_negative_returns_value() {
    let result = parse_duration("-3600");
    assert_eq!(result.unwrap(), -3600);
}

// ---------------------------------------------------------------------------
// Protocol validation tests
// ---------------------------------------------------------------------------

#[test]
fn protocol_rejects_invalid() {
    for bad in &["tcp; drop", "all", ""] {
        let toml = jail_toml_with_protocol(bad);
        let err = Config::parse(&toml);
        assert!(err.is_err(), "should reject protocol: {bad}");
    }
}

#[test]
fn protocol_accepts_valid() {
    for proto in &["tcp", "udp"] {
        let toml = jail_toml_with_protocol(proto);
        assert!(
            Config::parse(&toml).is_ok(),
            "should accept protocol: {proto}"
        );
    }
}

// ---------------------------------------------------------------------------
// bantime_factor validation tests
// ---------------------------------------------------------------------------

#[test]
fn bantime_factor_rejects_nan() {
    let toml = jail_toml_with_bantime_factor("nan");
    assert!(Config::parse(&toml).is_err(), "should reject NaN");
}

#[test]
fn bantime_factor_rejects_infinity() {
    let toml = jail_toml_with_bantime_factor("inf");
    assert!(Config::parse(&toml).is_err(), "should reject Infinity");
}

#[test]
fn bantime_factor_rejects_negative() {
    let toml = jail_toml_with_bantime_factor("-1.0");
    assert!(Config::parse(&toml).is_err(), "should reject negative");
}

#[test]
fn bantime_factor_accepts_valid() {
    for factor in &["1.0", "2.5"] {
        let toml = jail_toml_with_bantime_factor(factor);
        assert!(
            Config::parse(&toml).is_ok(),
            "should accept bantime_factor: {factor}"
        );
    }
}
