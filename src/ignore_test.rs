//! Tests for ignore list.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ignore::IgnoreList;

#[test]
fn empty_list_ignores_nothing() {
    let list = IgnoreList::new(&[], false).unwrap();
    assert!(!list.is_ignored(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
}

#[test]
fn cidr_match() {
    let cidrs = vec!["10.0.0.0/8".to_string(), "::1/128".to_string()];
    let list = IgnoreList::new(&cidrs, false).unwrap();

    assert!(list.is_ignored(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert!(list.is_ignored(&IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
    assert!(!list.is_ignored(&IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
    assert!(list.is_ignored(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
}

#[test]
fn single_host_cidr() {
    let cidrs = vec!["192.168.1.100/32".to_string()];
    let list = IgnoreList::new(&cidrs, false).unwrap();

    assert!(list.is_ignored(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
    assert!(!list.is_ignored(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101))));
}

#[test]
fn ignoreself_includes_loopback() {
    let list = IgnoreList::new(&[], true).unwrap();
    assert!(list.is_ignored(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert!(list.is_ignored(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
}

#[test]
fn invalid_cidr_errors() {
    let cidrs = vec!["not-a-cidr".to_string()];
    assert!(IgnoreList::new(&cidrs, false).is_err());
}

#[test]
fn ipv6_cidr() {
    let cidrs = vec!["2001:db8::/32".to_string()];
    let list = IgnoreList::new(&cidrs, false).unwrap();
    let ip: IpAddr = "2001:db8::1".parse().unwrap();
    assert!(list.is_ignored(&ip));

    let outside: IpAddr = "2001:db9::1".parse().unwrap();
    assert!(!list.is_ignored(&outside));
}
