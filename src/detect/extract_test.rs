use super::*;
use std::net::Ipv4Addr;

// ---------------------------------------------------------------------------
// IP extraction without surrounding whitespace (issue #1)
// ---------------------------------------------------------------------------

#[test]
fn host_in_brackets_no_spaces() {
    // Exact reproduction from issue #1: postfix log with IP in brackets, no spaces.
    let patterns = vec![r"connect from .*\.internet-measurement\.com\[<HOST>\]".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "postfix/smtpd[327792]: connect from imperative.monitoring.internet-measurement.com[185.247.137.113]";
    let result = m
        .try_match(line)
        .expect("should match IP in brackets without spaces");
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(185, 247, 137, 113)));
}

#[test]
fn host_in_brackets_with_spaces_still_works() {
    // The original working case from issue #1 — must not regress.
    let patterns = vec![r"connect from .*\.internet-measurement\.com\[ <HOST> \]".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "postfix/smtpd[327792]: connect from imperative.monitoring.internet-measurement.com[ 185.247.137.113 ]";
    let result = m
        .try_match(line)
        .expect("should match IP in brackets with spaces");
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(185, 247, 137, 113)));
}

#[test]
fn host_in_parens_no_spaces() {
    let patterns = vec![r"blocked \(<HOST>\)".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "blocked (10.0.0.1)";
    let result = m.try_match(line).expect("should match IP in parens");
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
}

#[test]
fn host_ipv6_in_brackets_no_spaces() {
    let patterns = vec![r"from \[<HOST>\]".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "from [2001:db8::1]";
    let result = m.try_match(line).expect("should match IPv6 in brackets");
    assert_eq!(result.ip, "2001:db8::1".parse::<IpAddr>().unwrap());
}

// ---------------------------------------------------------------------------
// Issue #6: positional IP extraction — every extractor path + edge cases
// ---------------------------------------------------------------------------

// --- AtStart extractor: <HOST> at position 0 or after ^ ----------------------

#[test]
fn at_start_extracts_first_ip_ignoring_url_ip() {
    // Reporter's exact reproduction case from issue #6.
    let patterns = vec![r#"^<HOST> .* "(GET|POST) .* HTTP/\d\.\d" 444"#.to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = r#"14.225.18.20 - - [25/Mar/2026:09:37:18 +0000] "POST http://161.5.6.7/hello.world HTTP/1.1" 444 0"#;
    let result = m.try_match(line).expect("should match");
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(14, 225, 18, 20)));
}

#[test]
fn at_start_no_other_ips() {
    let patterns = vec![r#"^<HOST> .* "(GET|POST) .* HTTP/\d\.\d" 444"#.to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = r#"14.225.18.20 - - [25/Mar/2026:09:37:18 +0000] "GET /robots.txt HTTP/1.1" 444 0"#;
    let result = m.try_match(line).expect("should match");
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(14, 225, 18, 20)));
}

#[test]
fn at_start_ipv6() {
    let patterns = vec![r"^<HOST> denied".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "2001:db8::1 denied";
    let result = m.try_match(line).expect("should match");
    assert_eq!(result.ip, "2001:db8::1".parse::<IpAddr>().unwrap());
}

#[test]
fn at_start_without_caret() {
    // <HOST> at position 0, no ^ anchor — still AtStart.
    let patterns = vec![r"<HOST> - - \[".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "10.0.0.1 - - [25/Mar/2026:09:37:18 +0000]";
    let result = m.try_match(line).expect("should match");
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
}

#[test]
fn at_start_multiple_ips_in_url_and_header() {
    // Three IPs total: HOST at start, one in URL, one in referrer.
    let patterns = vec![r#"^<HOST> .* HTTP/\d\.\d" 444"#.to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = r#"14.225.18.20 - - [25/Mar/2026:09:37:18 +0000] "GET http://161.5.6.7/ref=10.10.10.10 HTTP/1.1" 444 0"#;
    let result = m.try_match(line).expect("should match");
    assert_eq!(
        result.ip,
        IpAddr::V4(Ipv4Addr::new(14, 225, 18, 20)),
        "must pick the HOST IP, not one of the IPs in the URL"
    );
}

// --- AfterLiteral extractor: literal before <HOST> ---------------------------

#[test]
fn after_literal_simple() {
    let patterns = vec![r"from <HOST> port".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "Failed login from 10.0.0.1 port 22";
    let result = m.try_match(line).expect("should match");
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
}

#[test]
fn after_literal_with_trailing_ip() {
    // <HOST> after "from ", but a second IP appears later in the match span.
    let patterns = vec![r"from <HOST> port \d+ .* to \d+\.\d+\.\d+\.\d+".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "Failed from 10.0.0.1 port 22 forwarded to 192.168.1.1";
    let result = m.try_match(line).expect("should match");
    assert_eq!(
        result.ip,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        "must extract the <HOST> IP, not the trailing IP"
    );
}

#[test]
fn after_literal_with_preceding_ip_in_line() {
    // An IP appears earlier in the line (outside the match), HOST in middle.
    let patterns = vec![r"sshd\[\d+\]: Failed .* from <HOST>".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "192.168.1.1 server sshd[1234]: Failed password for root from 10.0.0.50 port 22";
    let result = m.try_match(line).expect("should match");
    assert_eq!(
        result.ip,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)),
        "must not confuse the server IP at the start of the line with the HOST"
    );
}

#[test]
fn after_literal_ipv6() {
    let patterns = vec![r"from <HOST> port".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "from 2001:db8::ff port 22";
    let result = m.try_match(line).expect("should match");
    assert_eq!(result.ip, "2001:db8::ff".parse::<IpAddr>().unwrap());
}

#[test]
fn after_literal_encapsulated_in_brackets() {
    // IP in brackets with literal "from" resolved via AfterLiteral
    // because the escaped `\[` before HOST is a metachar boundary, leaving
    // only the text before that as a potential literal.
    let patterns = vec![r"connect from .*\[<HOST>\]".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "connect from evil.example.com[185.247.137.113]";
    let result = m.try_match(line).expect("should match");
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(185, 247, 137, 113)));
}

#[test]
fn after_literal_host_ip_same_as_trailing_ip() {
    // Both IPs in the line are identical — must still return one.
    let patterns = vec![r"from <HOST> proxy \d+\.\d+\.\d+\.\d+".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "from 10.0.0.1 proxy 10.0.0.1";
    let result = m.try_match(line).expect("should match");
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
}

#[test]
fn after_literal_literal_appears_twice_but_only_second_has_ip() {
    // "from " appears in the text before the match point but the
    // extract_ip_after_literal retry loop should skip the non-IP occurrence.
    let patterns = vec![r"rejected from <HOST> port".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    // The literal " from " appears after "rejected" which is the correct one.
    let line = "rejected from 10.0.0.1 port 22";
    let result = m.try_match(line).expect("should match");
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
}

// --- BeforeLiteral extractor: literal after <HOST> ---------------------------

#[test]
fn before_literal_conn_closed() {
    // The real sshd pattern that triggers BeforeLiteral: `user .* <HOST> port`
    // — only a single space before HOST (too short), but " port" after.
    let patterns =
        vec![r"sshd\[\d+\]: Connection closed by authenticating user .* <HOST> port".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line =
        "sshd[1234]: Connection closed by authenticating user root 103.174.103.249 port 58414";
    let result = m.try_match(line).expect("should match");
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(103, 174, 103, 249)));
}

#[test]
fn before_literal_with_earlier_ip_in_span() {
    // Match span contains an IP before HOST — BeforeLiteral must pick the
    // one closest (rightmost) to the literal, which is the HOST IP.
    let patterns =
        vec![r"sshd\[\d+\]: Connection closed by authenticating user .* <HOST> port".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    // 10.0.0.1 appears in the username field (unusual but valid); HOST is 5.6.7.8.
    let line = "sshd[1234]: Connection closed by authenticating user 10.0.0.1 5.6.7.8 port 22";
    let result = m.try_match(line).expect("should match");
    assert_eq!(
        result.ip,
        IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        "must pick the IP closest to ' port', not an earlier one"
    );
}

#[test]
fn before_literal_ipv6() {
    let patterns = vec![r"user .* <HOST> port".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "user root 2001:db8::1 port 22";
    let result = m.try_match(line).expect("should match");
    assert_eq!(result.ip, "2001:db8::1".parse::<IpAddr>().unwrap());
}

#[test]
fn before_literal_disconnected_pattern() {
    // Another real sshd pattern that lands on BeforeLiteral.
    let patterns =
        vec![r"sshd\[\d+\]: Disconnected from authenticating user .* <HOST> port".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "sshd[5678]: Disconnected from authenticating user admin 176.120.22.47 port 27094";
    let result = m.try_match(line).expect("should match");
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(176, 120, 22, 47)));
}

// --- Captures fallback -------------------------------------------------------

#[test]
fn captures_fallback_short_literals() {
    // Both before and after literals are < 2 chars — falls back to captures().
    // Pattern: `\d+ <HOST> \d+` — literal before = " " (1 char), after = " " (1 char).
    let patterns = vec![r"\d+ <HOST> \d+".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "42 10.0.0.1 99";
    let result = m
        .try_match(line)
        .expect("should match via captures fallback");
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
}

#[test]
fn captures_fallback_with_other_ips_in_line() {
    // Captures fallback must still extract the correct HOST IP when other
    // IPs are present.  Pattern uses `\(` and `\)` which are metachar
    // boundaries — no usable literal before or after HOST → Captures path.
    let patterns = vec![r"\(<HOST>\) .* \d+\.\d+\.\d+\.\d+".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "(10.0.0.1) gateway 192.168.1.1";
    let result = m
        .try_match(line)
        .expect("should match via captures fallback");
    assert_eq!(
        result.ip,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        "captures() must extract the exact <HOST> group, not the gateway IP"
    );
}

// --- Multi-IP stress tests (extractor-agnostic) ------------------------------

#[test]
fn three_ips_host_is_first() {
    // HOST is the first IP; two more follow.
    let patterns = vec![r"from <HOST> via \d+\.\d+\.\d+\.\d+ gw \d+\.\d+\.\d+\.\d+".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "from 1.1.1.1 via 2.2.2.2 gw 3.3.3.3";
    let result = m.try_match(line).expect("should match");
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
}

#[test]
fn three_ips_host_is_middle() {
    // HOST sandwiched between two other IPs.
    let patterns = vec![r"src \d+\.\d+\.\d+\.\d+ from <HOST> dst \d+\.\d+\.\d+\.\d+".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "src 1.1.1.1 from 2.2.2.2 dst 3.3.3.3";
    let result = m.try_match(line).expect("should match");
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)));
}

#[test]
fn two_ips_host_is_last() {
    // HOST is the second IP; the first is a literal in the pattern context.
    let patterns = vec![r"proxy \d+\.\d+\.\d+\.\d+ client <HOST>".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "proxy 10.0.0.1 client 5.6.7.8 end";
    let result = m.try_match(line).expect("should match");
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)));
}

#[test]
fn duplicate_ip_values_in_line() {
    // The same IP value appears for HOST and in another position —
    // must still return successfully.
    let patterns = vec![r"from <HOST> to \d+\.\d+\.\d+\.\d+".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "from 10.0.0.1 to 10.0.0.1";
    let result = m.try_match(line).expect("should match");
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
}

// --- IPv4-mapped IPv6 (::ffff:) normalization --------------------------------

#[test]
fn ipv4_mapped_in_brackets() {
    let patterns = vec![r"ip=\[<HOST>\]".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "ip=[::ffff:1.2.3.4]";
    let result = m
        .try_match(line)
        .expect("should match ::ffff: mapped address");
    assert_eq!(
        result.ip,
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        "::ffff: mapped address should normalize to IPv4"
    );
}

#[test]
fn ipv4_mapped_after_literal() {
    let patterns = vec![r"rhost=<HOST>".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "authentication failure; rhost=::ffff:192.168.1.1";
    let result = m
        .try_match(line)
        .expect("should match ::ffff: after literal");
    assert_eq!(
        result.ip,
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        "::ffff: mapped address should normalize to IPv4"
    );
}

#[test]
fn ipv4_mapped_uppercase_ffff() {
    let patterns = vec![r"from \[<HOST>\]".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "from [::FFFF:10.0.0.1]";
    let result = m.try_match(line).expect("should match ::FFFF: uppercase");
    assert_eq!(
        result.ip,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        "::FFFF: uppercase should normalize to IPv4"
    );
}

#[test]
fn plain_ipv6_not_normalized() {
    let patterns = vec![r"from <HOST> port".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "from 2001:db8::1 port 22";
    let result = m.try_match(line).expect("should match plain IPv6");
    assert_eq!(
        result.ip,
        "2001:db8::1".parse::<IpAddr>().unwrap(),
        "plain IPv6 should NOT be normalized to IPv4"
    );
}

// --- Encapsulated/delimited IPs ----------------------------------------------

#[test]
fn host_in_square_brackets() {
    let patterns = vec![r"client \[<HOST>\]".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "client [10.0.0.1] connected";
    let result = m.try_match(line).expect("should match");
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
}

#[test]
fn host_in_angle_brackets() {
    let patterns = vec![r"relay <HOST>>".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "relay 10.0.0.1>";
    let result = m.try_match(line).expect("should match");
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
}

#[test]
fn host_in_parens_with_other_ip_outside() {
    let patterns = vec![r"denied \(<HOST>\) gw \d+\.\d+\.\d+\.\d+".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "denied (5.6.7.8) gw 10.0.0.1";
    let result = m.try_match(line).expect("should match");
    assert_eq!(
        result.ip,
        IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        "must extract IP in parens, not the gateway IP"
    );
}

#[test]
fn host_colon_port_delimiter() {
    // IP followed by `:port` — the colon is an IP char for IPv6,
    // but the host regex \d{1,3}.\d{1,3}... stops before non-matching chars.
    let patterns = vec![r"client <HOST>:\d+ denied".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "client 10.0.0.1:8080 denied";
    let result = m.try_match(line).expect("should match");
    assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
}

#[test]
fn ipv6_in_brackets_with_trailing_ipv4() {
    let patterns = vec![r"from \[<HOST>\] to \d+\.\d+\.\d+\.\d+".to_string()];
    let m = JailMatcher::new(&patterns).unwrap();
    let line = "from [2001:db8::1] to 10.0.0.1";
    let result = m.try_match(line).expect("should match");
    assert_eq!(
        result.ip,
        "2001:db8::1".parse::<IpAddr>().unwrap(),
        "must extract the IPv6 HOST, not the trailing IPv4"
    );
}
