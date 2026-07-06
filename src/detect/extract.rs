//! IP extraction from regex match spans.
//!
//! Positional string operations locate the `<HOST>` IP inside a match span
//! without re-running the regex engine. Used by the [`matcher`](crate::detect::matcher)
//! fast path; the slow `captures()` path only calls [`normalize_mapped`].

use std::net::IpAddr;

/// Extract an IP from the start of a match span.
pub(crate) fn extract_ip_at_start(span: &str) -> Option<IpAddr> {
    let end = span
        .find(|c: char| !c.is_ascii_hexdigit() && c != '.' && c != ':')
        .unwrap_or(span.len());
    let token = span.get(..end).filter(|t| t.len() >= 2)?;
    try_parse_ip(token)
}

/// Extract an IP that follows `literal` in the match span.
///
/// If the literal appears multiple times, tries each occurrence until one
/// is followed by a valid IP address.
pub(crate) fn extract_ip_after_literal(span: &str, literal: &str) -> Option<IpAddr> {
    let mut pos = 0;
    while let Some(found) = span.get(pos..)?.find(literal) {
        let ip_start = pos + found + literal.len();
        if let Some(ip) = parse_ip_at(span, ip_start) {
            return Some(ip);
        }
        pos += found + 1;
    }
    None
}

/// Extract the rightmost IP token immediately before `literal` in the span.
pub(crate) fn extract_ip_before_literal(span: &str, literal: &str) -> Option<IpAddr> {
    let lit_pos = span.find(literal)?;
    let before = span.get(..lit_pos)?;
    // Scan right-to-left: the token closest to the literal is the HOST IP.
    for token in before.rsplit(|c: char| !c.is_ascii_hexdigit() && c != '.' && c != ':') {
        if token.len() >= 2
            && let Some(ip) = try_parse_ip(token)
        {
            return Some(ip);
        }
    }
    None
}

/// Parse an IP-like token starting at byte offset `start` in `span`.
fn parse_ip_at(span: &str, start: usize) -> Option<IpAddr> {
    let remaining = span.get(start..)?;
    let end = remaining
        .find(|c: char| !c.is_ascii_hexdigit() && c != '.' && c != ':')
        .unwrap_or(remaining.len());
    let token = remaining.get(..end).filter(|t| t.len() >= 2)?;
    try_parse_ip(token)
}

/// Try to parse an IP from a token that may include a trailing port
/// (e.g. `10.0.0.1:8080` or `2001:db8::1:443`).
///
/// The scan includes `:` to support IPv6, but this means `IPv4:port` tokens
/// are captured as one string. If the full token fails, split at the last `:`
/// and try the prefix — it handles both `IPv4:port` and `IPv6:port`.
///
/// IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`) are normalized to their
/// IPv4 form so that firewall rules target the correct address family.
fn try_parse_ip(token: &str) -> Option<IpAddr> {
    if let Ok(ip) = token.parse::<IpAddr>() {
        return Some(normalize_mapped(ip));
    }
    // Strip trailing `:port` or `:port:` suffixes iteratively.
    // Handles `10.0.0.1:8080`, `192.168.0.1:29530:`, `2001:db8::1:443`.
    let mut s = token;
    while let Some(colon) = s.rfind(':') {
        s = &s[..colon];
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Some(normalize_mapped(ip));
        }
    }
    None
}

/// Normalize IPv4-mapped IPv6 addresses (e.g. `::ffff:192.168.1.1`) to
/// plain IPv4. Many services log client addresses in this form; banning
/// the IPv6 representation would miss the actual IPv4 traffic.
pub(crate) fn normalize_mapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        IpAddr::V4(_) => ip,
    }
}
