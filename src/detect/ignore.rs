//! IP ignore list — CIDR allowlists and local IP detection.
//!
//! IPs in the ignore list are never banned, even if they match failure patterns.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

use crate::error::Result;

/// Ignore list with CIDR networks and optional self-detection.
#[derive(Debug, Clone)]
pub struct IgnoreList {
    networks: Vec<IpNet>,
}

impl IgnoreList {
    /// Build an ignore list from CIDR strings, optionally adding local IPs.
    pub fn new(cidrs: &[String], ignoreself: bool) -> Result<Self> {
        let mut networks: Vec<IpNet> = cidrs
            .iter()
            .map(|s| parse_entry(s))
            .collect::<Result<Vec<_>>>()?;

        if ignoreself {
            networks.extend(local_addresses());
        }

        Ok(Self { networks })
    }

    /// Check if an IP should be ignored (never banned).
    pub fn is_ignored(&self, ip: &IpAddr) -> bool {
        self.networks.iter().any(|net| net.contains(ip))
    }

    /// Number of networks in the list.
    pub fn len(&self) -> usize {
        self.networks.len()
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.networks.is_empty()
    }
}

/// Parse a single ignore-list entry as a CIDR network or a bare IP address.
///
/// A bare IPv4 address becomes a `/32` host network; a bare IPv6 address
/// becomes a `/128`. This is the single acceptance path shared by the jail
/// runtime and config validation, so both agree on what is valid.
pub(crate) fn parse_entry(s: &str) -> Result<IpNet> {
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(net);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(IpNet::from(ip));
    }
    Err(crate::error::Error::config(format!(
        "invalid ignoreip entry (expected IP or CIDR): {s}"
    )))
}

/// Detect local IP addresses on this machine.
///
/// Uses `getifaddrs(2)` to enumerate all network interfaces, which works
/// on Linux, macOS, and BSD. Falls back to loopback addresses only if
/// the syscall fails.
fn local_addresses() -> Vec<IpNet> {
    let mut addrs = Vec::new();

    // Always include loopback.
    addrs.push(IpNet::from(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    addrs.push(IpNet::from(IpAddr::V6(Ipv6Addr::LOCALHOST)));

    // Enumerate interface addresses via getifaddrs(2).
    if let Ok(ifaddrs) = nix::ifaddrs::getifaddrs() {
        for ifa in ifaddrs {
            if let Some(addr) = ifa.address
                && let Some(ip) = sockaddr_to_ip(&addr)
            {
                addrs.push(IpNet::from(ip));
            }
        }
    }

    addrs
}

/// Extract an IP address from a `nix::sys::socket::SockaddrStorage`.
fn sockaddr_to_ip(addr: &nix::sys::socket::SockaddrStorage) -> Option<IpAddr> {
    if let Some(v4) = addr.as_sockaddr_in() {
        Some(IpAddr::V4(v4.ip()))
    } else {
        addr.as_sockaddr_in6().map(|v6| IpAddr::V6(v6.ip()))
    }
}

#[cfg(test)]
#[path = "ignore_test.rs"]
mod ignore_test;
