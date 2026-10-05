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

/// Issue #50: NixOS has no FHS layout, so firewall binaries only exist in the
/// system profile.
#[test]
fn system_dirs_include_the_nixos_system_profile() {
    assert!(SYSTEM_DIRS.contains(&"/run/current-system/sw/bin"));
}

#[test]
fn resolve_binary_falls_through_to_a_later_dir_when_earlier_ones_lack_it() {
    let fhs = tempfile::tempdir().expect("tempdir");
    let profile = tempfile::tempdir().expect("tempdir");
    std::fs::write(profile.path().join("nft"), "").expect("write fake nft");
    let dirs = [
        fhs.path().to_str().expect("utf-8 path"),
        profile.path().to_str().expect("utf-8 path"),
    ];

    let path = resolve_binary_in(&dirs, "nft").expect("nft should resolve from the last dir");
    assert_eq!(path, profile.path().join("nft"));
}

#[test]
fn resolve_binary_prefers_the_earlier_dir_when_both_have_it() {
    let fhs = tempfile::tempdir().expect("tempdir");
    let profile = tempfile::tempdir().expect("tempdir");
    std::fs::write(fhs.path().join("nft"), "").expect("write fake nft");
    std::fs::write(profile.path().join("nft"), "").expect("write fake nft");
    let dirs = [
        fhs.path().to_str().expect("utf-8 path"),
        profile.path().to_str().expect("utf-8 path"),
    ];

    let path = resolve_binary_in(&dirs, "nft").expect("nft should resolve");
    assert_eq!(path, fhs.path().join("nft"));
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

/// An ipset jail needs three binaries; on hosts without them (e.g. macOS) the
/// error must name the missing one rather than silently degrading.
#[test]
fn test_create_backend_ipset() {
    let backend = crate::config::Backend::Ipset {
        maxelem: 65_536,
        chain: "INPUT".to_string(),
    };
    match create_backend(&backend) {
        Ok(b) => assert_eq!(b.name(), "ipset"),
        Err(e) => {
            let msg = e.to_string();
            assert!(msg.contains("not found"), "got: {msg}");
            assert!(
                ["ipset", "iptables", "ip6tables"]
                    .iter()
                    .any(|bin| msg.contains(bin)),
                "error must name the missing binary: {msg}"
            );
        }
    }
}
