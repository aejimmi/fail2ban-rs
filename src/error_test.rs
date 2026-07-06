use super::*;

use std::net::{IpAddr, Ipv4Addr};

#[test]
fn config_error_display() {
    let err = Error::config("bad value");
    assert_eq!(err.to_string(), "config error: bad value");
}

#[test]
fn config_not_found_display() {
    let err = Error::ConfigNotFound {
        path: "/tmp/missing.toml".into(),
    };
    assert!(err.to_string().contains("/tmp/missing.toml"));
}

#[test]
fn io_error_display() {
    let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "nope");
    let err = Error::io("reading file", io_err);
    let msg = err.to_string();
    assert!(msg.contains("reading file"), "got: {msg}");
}

#[test]
fn io_error_source() {
    use std::error::Error as StdError;
    let io_err = std::io::Error::other("inner");
    let err = Error::io("outer", io_err);
    let source = err.source().expect("should have source");
    assert!(source.to_string().contains("inner"));
}

#[test]
#[allow(clippy::invalid_regex)]
fn regex_error_display() {
    let re_err = regex::Regex::new("[invalid").unwrap_err();
    let err = Error::Regex {
        pattern: "[invalid".to_string(),
        source: re_err,
    };
    assert!(err.to_string().contains("[invalid"));
}

#[test]
fn firewall_error_display() {
    let err = Error::firewall("nft not found");
    assert!(err.to_string().contains("nft not found"));
}

#[test]
fn persistence_error_retains_underlying_detail() {
    // The public API owns no etchdb types; a backend error is folded into the
    // message via Display so its detail is preserved without leaking the type.
    let backend_err = etchdb::Error::WalCorrupted {
        offset: 42,
        reason: "test corruption".to_string(),
    };
    let err = Error::persistence(format!("replaying WAL: {backend_err}"));
    let msg = err.to_string();
    assert!(msg.contains("persistence error"), "got: {msg}");
    assert!(msg.contains("replaying WAL"), "got: {msg}");
    assert!(
        msg.contains("test corruption"),
        "underlying detail lost: {msg}"
    );
}

#[test]
fn schema_mismatch_error_display() {
    let err = Error::schema_mismatch("version 0 != supported 1");
    let msg = err.to_string();
    assert!(msg.contains("incompatible state schema"), "got: {msg}");
    assert!(msg.contains("version 0"), "got: {msg}");
}

#[test]
fn protocol_error_display() {
    let err = Error::protocol("malformed JSON");
    assert!(err.to_string().contains("malformed JSON"));
}

#[test]
fn channel_closed_display() {
    let err = Error::ChannelClosed;
    assert_eq!(err.to_string(), "channel closed");
}

#[test]
fn already_banned_display() {
    let err = Error::AlreadyBanned {
        ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        jail: "sshd".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("1.2.3.4"));
    assert!(msg.contains("sshd"));
}

#[test]
fn not_banned_display() {
    let err = Error::NotBanned {
        ip: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        jail: "nginx".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("5.6.7.8"));
    assert!(msg.contains("nginx"));
}

#[test]
#[allow(clippy::unnecessary_wraps)]
fn result_type_alias_works() {
    fn returns_ok() -> crate::error::Result<i32> {
        Ok(42)
    }
    fn returns_err() -> crate::error::Result<i32> {
        Err(Error::config("test"))
    }
    assert!(returns_ok().is_ok());
    assert!(returns_err().is_err());
}
