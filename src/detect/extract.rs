//! Normalisation of IPs extracted at the regex HOST capture boundary.

use std::net::IpAddr;

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
