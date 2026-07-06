use super::*;

#[test]
fn no_jails_error() {
    let toml = "[global]\n";
    assert!(Config::parse(toml).is_err());
}

#[test]
fn no_enabled_jails_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    enabled = false
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    "#;
    assert!(Config::parse(toml).is_err());
}

#[test]
fn missing_host_placeholder_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    enabled = true
    log_path = "/var/log/auth.log"
    filter = ['Failed password for .*']
    "#;
    assert!(Config::parse(toml).is_err());
}

#[test]
fn zero_max_retry_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    enabled = true
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    max_retry = 0
    "#;
    assert!(Config::parse(toml).is_err());
}

#[test]
fn zero_find_time_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    find_time = 0
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("find_time"), "got: {err}");
}

#[test]
fn negative_find_time_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    find_time = -10
    "#;
    assert!(Config::parse(toml).is_err());
}

#[test]
fn zero_ban_time_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    ban_time = 0
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("ban_time"), "got: {err}");
}

#[test]
fn permanent_ban_time_ok() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    ban_time = -1
    "#;
    let config = Config::parse(toml).unwrap();
    assert_eq!(config.jail["sshd"].ban_time, -1);
}

#[test]
fn empty_filter_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = []
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("no filter"), "got: {err}");
}

// ---------------------------------------------------------------------------
// Global / logging validation
// ---------------------------------------------------------------------------

#[test]
fn zero_channel_size_error() {
    let toml = r#"
    [global]
    channel_size = 0

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("channel_size"), "got: {err}");
}

#[test]
fn unknown_logging_level_error() {
    let toml = r#"
    [global]

    [logging]
    level = "verbose"

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("logging.level"), "got: {err}");
}

#[test]
fn unknown_logging_format_error() {
    let toml = r#"
    [global]

    [logging]
    format = "yaml"

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("logging.format"), "got: {err}");
}

#[test]
fn unknown_logging_destination_error() {
    let toml = r#"
    [global]

    [logging]
    destination = "datadog"

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(
        err.to_string().contains("logging.destination"),
        "got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Timing / bantime validation
// ---------------------------------------------------------------------------

#[test]
fn ban_time_below_negative_one_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    ban_time = -2
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("ban_time"), "got: {err}");
}

#[test]
fn zero_bantime_maxtime_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    bantime_maxtime = 0
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("bantime_maxtime"), "got: {err}");
}

#[test]
fn zero_bantime_multiplier_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    bantime_multipliers = [1, 2, 0, 8]
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(
        err.to_string().contains("bantime_multipliers"),
        "got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Network validation
// ---------------------------------------------------------------------------

#[test]
fn zero_port_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    port = ["0"]
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("port"), "got: {err}");
}

#[test]
fn max_port_ok() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    port = ["65535"]
    "#;
    let config = Config::parse(toml).unwrap();
    assert_eq!(config.jail["sshd"].port, vec!["65535".to_string()]);
}

#[test]
fn invalid_ignoreip_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    ignoreip = ["not-an-ip"]
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("ignoreip"), "got: {err}");
}

#[test]
fn bare_ip_ignoreip_ok() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    ignoreip = ["192.168.1.10", "::1", "10.0.0.0/8"]
    "#;
    let config = Config::parse(toml).unwrap();
    assert_eq!(config.jail["sshd"].ignoreip.len(), 3);
}

#[test]
fn webhook_without_scheme_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    webhook = "example.com/hook"
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("webhook"), "got: {err}");
}

#[test]
fn webhook_https_ok() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    webhook = "https://example.com/hook"
    "#;
    let config = Config::parse(toml).unwrap();
    assert_eq!(
        config.jail["sshd"].webhook.as_deref(),
        Some("https://example.com/hook")
    );
}

// ---------------------------------------------------------------------------
// Pattern compilation validation
// ---------------------------------------------------------------------------

#[test]
fn invalid_filter_regex_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST> (unclosed']
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("filter regex"), "got: {err}");
}

#[test]
fn invalid_ignoreregex_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    ignoreregex = ['(unclosed']
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("ignoreregex"), "got: {err}");
}

// ---------------------------------------------------------------------------
// MaxMind field / global path coupling
// ---------------------------------------------------------------------------

#[test]
fn maxmind_field_without_global_path_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    maxmind = ["asn"]
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("maxmind_asn"), "got: {err}");
}

#[test]
fn maxmind_field_with_global_path_ok() {
    let toml = r#"
    [global]
    maxmind_asn = "/var/lib/GeoLite2-ASN.mmdb"

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    maxmind = ["asn"]
    "#;
    let config = Config::parse(toml).unwrap();
    assert_eq!(config.jail["sshd"].maxmind.len(), 1);
}
