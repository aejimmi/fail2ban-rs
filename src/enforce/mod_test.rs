use super::*;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn resolve_binary_finds_a_binary_present_on_every_unix_system() {
    // `sh` lives in one of SYSTEM_DIRS on every unix runner, but the exact dir
    // varies: usr-merged systems resolve it under `/usr/bin` while others use
    // `/bin`. Assert the contract (first existing SYSTEM_DIRS match) rather than
    // a hardcoded path.
    let path = resolve_binary("sh").expect("sh should resolve on any unix system");
    assert!(
        path.exists(),
        "resolved path must exist: {}",
        path.display()
    );
    assert_eq!(
        path.file_name().and_then(|n| n.to_str()),
        Some("sh"),
        "resolved path must end in the requested binary name: {}",
        path.display()
    );
    assert!(
        SYSTEM_DIRS
            .iter()
            .any(|dir| path == std::path::Path::new(dir).join("sh")),
        "resolved path must be a SYSTEM_DIRS entry: {}",
        path.display()
    );
}

#[test]
fn resolve_binary_rejects_unknown_binary_name() {
    let err = resolve_binary("definitely-not-a-real-binary-xyz")
        .expect_err("a nonexistent binary name must not resolve");
    assert!(err.to_string().contains("not found"), "got: {err}");
}

#[test]
fn create_backend_nftables() {
    if let Ok(backend) = create_backend(&crate::config::Backend::Nftables) {
        assert_eq!(backend.name(), "nftables");
    }
    // Binary not found on this system (e.g. macOS); skip.
}

#[test]
fn create_backend_iptables() {
    if let Ok(backend) = create_backend(&crate::config::Backend::Iptables) {
        assert_eq!(backend.name(), "iptables");
    }
    // Binaries not found on this system (e.g. macOS); skip.
}

#[test]
fn create_backend_script() {
    let backend = create_backend(&crate::config::Backend::Script {
        ban_cmd: "echo ban <IP>".to_string(),
        unban_cmd: "echo unban <IP>".to_string(),
    })
    .expect("script backend should always succeed");
    assert_eq!(backend.name(), "script");
}

#[test]
fn script_substitute() {
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let template = "echo ban <IP> in <JAIL>";
    let result = template
        .replace("<IP>", &ip.to_string())
        .replace("<JAIL>", "sshd");
    assert_eq!(result, "echo ban 1.2.3.4 in sshd");
}

#[test]
fn script_substitute_no_placeholders() {
    let template = "echo hello world";
    let result = template
        .replace("<IP>", "1.2.3.4")
        .replace("<JAIL>", "sshd");
    assert_eq!(result, "echo hello world");
}

#[test]
fn script_substitute_multiple_occurrences() {
    let template = "<IP> <IP> <JAIL> <JAIL>";
    let result = template
        .replace("<IP>", "10.0.0.1")
        .replace("<JAIL>", "ssh");
    assert_eq!(result, "10.0.0.1 10.0.0.1 ssh ssh");
}

#[test]
fn script_substitute_ipv6() {
    let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let template = "ban <IP> jail <JAIL>";
    let result = template
        .replace("<IP>", &ip.to_string())
        .replace("<JAIL>", "sshd");
    assert_eq!(result, "ban 2001:db8::1 jail sshd");
}
