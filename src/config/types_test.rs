use super::*;

#[test]
fn defaults_applied() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    "#;
    let config = Config::parse(toml).unwrap();
    let sshd = &config.jail["sshd"];
    assert_eq!(sshd.max_retry, 5);
    assert_eq!(sshd.find_time, 600);
    assert_eq!(sshd.ban_time, 3600);
    assert!(sshd.enabled);
    assert!(sshd.ignoreself);
    assert!(sshd.reban_on_restart);
}

#[test]
fn reban_on_restart_defaults_true() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    "#;
    let config = Config::parse(toml).unwrap();
    assert!(config.jail["sshd"].reban_on_restart);
}

#[test]
fn reban_on_restart_can_be_disabled() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    reban_on_restart = false
    "#;
    let config = Config::parse(toml).unwrap();
    assert!(!config.jail["sshd"].reban_on_restart);
}

#[test]
fn script_backend() {
    let toml = r#"
    [global]

    [jail.custom]
    log_path = "/var/log/custom.log"
    filter = ['from <HOST>']

    [jail.custom.backend.script]
    ban_cmd = "echo ban <IP>"
    unban_cmd = "echo unban <IP>"
    "#;
    let config = Config::parse(toml).unwrap();
    match &config.jail["custom"].backend {
        Backend::Script { ban_cmd, unban_cmd } => {
            assert!(ban_cmd.contains("<IP>"));
            assert!(unban_cmd.contains("<IP>"));
        }
        other => panic!("expected Script backend, got: {other:?}"),
    }
}

#[test]
fn iptables_backend() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    backend = "iptables"
    "#;
    let config = Config::parse(toml).unwrap();
    let sshd = &config.jail["sshd"];
    assert!(matches!(sshd.backend, Backend::Iptables));
}

#[test]
fn multiple_filters() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = [
        'Failed password for .* from <HOST>',
        'Invalid user .* from <HOST>',
        'Connection closed by .* <HOST>',
    ]
    "#;
    let config = Config::parse(toml).unwrap();
    assert_eq!(config.jail["sshd"].filter.len(), 3);
}

#[test]
fn enabled_jails_filter() {
    let toml = r#"
    [global]

    [jail.sshd]
    enabled = true
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']

    [jail.nginx]
    enabled = false
    log_path = "/var/log/nginx.log"
    filter = ['from <HOST>']
    "#;
    let config = Config::parse(toml).unwrap();
    let enabled: Vec<&str> = config.enabled_jails().map(|(name, _)| name).collect();
    assert_eq!(enabled.len(), 1);
    assert!(enabled.contains(&"sshd"));
}

#[test]
fn multiple_enabled_jails() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']

    [jail.nginx]
    log_path = "/var/log/nginx.log"
    filter = ['client <HOST>']

    [jail.postfix]
    log_path = "/var/log/mail.log"
    filter = ['reject from <HOST>']
    "#;
    let config = Config::parse(toml).unwrap();
    let enabled: Vec<&str> = config.enabled_jails().map(|(name, _)| name).collect();
    assert_eq!(enabled.len(), 3);
}

#[test]
fn logging_section_parses() {
    let toml = r#"
    [global]

    [logging]
    destination = "tell"
    endpoint = "ingest.tell.rs:9090"
    api_key = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
    level = "warn"
    service = "my-server"

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    "#;
    let config = Config::parse(toml).unwrap();
    assert_eq!(config.logging.destination.as_deref(), Some("tell"));
    assert_eq!(
        config.logging.endpoint.as_deref(),
        Some("ingest.tell.rs:9090")
    );
    assert_eq!(
        config.logging.api_key.as_deref(),
        Some("a1b2c3d4e5f60718293a4b5c6d7e8f90")
    );
    assert_eq!(config.logging.level.as_deref(), Some("warn"));
    assert_eq!(config.logging.service.as_deref(), Some("my-server"));
}

#[test]
fn logging_defaults_when_omitted() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    "#;
    let config = Config::parse(toml).unwrap();
    let logging = &config.logging;
    assert!(logging.destination.is_none());
    assert!(logging.endpoint.is_none());
    assert!(logging.api_key.is_none());
    assert!(logging.level.is_none());
    assert!(logging.service.is_none());
    assert_eq!(logging.clone(), LoggingConfig::default());
}

#[test]
fn duration_strings_in_config() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    find_time = "10m"
    ban_time = "1h"
    bantime_maxtime = "1w"
    "#;
    let config = Config::parse(toml).unwrap();
    let sshd = &config.jail["sshd"];
    assert_eq!(sshd.find_time, 600);
    assert_eq!(sshd.ban_time, 3600);
    assert_eq!(sshd.bantime_maxtime, 604_800);
}

#[test]
fn duration_integers_still_work() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    find_time = 600
    ban_time = 3600
    "#;
    let config = Config::parse(toml).unwrap();
    assert_eq!(config.jail["sshd"].find_time, 600);
    assert_eq!(config.jail["sshd"].ban_time, 3600);
}

#[test]
fn ignoreregex_parses() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    ignoreregex = ['Accepted', 'internal']
    "#;
    let config = Config::parse(toml).unwrap();
    assert_eq!(config.jail["sshd"].ignoreregex.len(), 2);
}

#[test]
fn ignoreregex_defaults_empty() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    "#;
    let config = Config::parse(toml).unwrap();
    assert!(config.jail["sshd"].ignoreregex.is_empty());
}

#[test]
fn state_file_alias_still_accepted() {
    let toml = r#"
    [global]
    state_file = "/tmp/state.bin"

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    "#;
    let config = Config::parse(toml).unwrap();
    assert_eq!(config.global.state_dir.to_str(), Some("/tmp/state.bin"));
}

#[test]
fn unknown_jail_key_error() {
    let toml = r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    max_rety = 10
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("max_rety"), "got: {err}");
}

#[test]
fn unknown_global_key_error() {
    let toml = r#"
    [global]
    sokcet_path = "/tmp/x.sock"

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    "#;
    let err = Config::parse(toml).unwrap_err();
    assert!(err.to_string().contains("sokcet_path"), "got: {err}");
}

#[test]
fn unknown_top_level_key_error() {
    let toml = r#"
    [global]

    [jial.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    "#;
    // `jial` is a typo of `jail` — rejected as an unknown top-level key.
    assert!(Config::parse(toml).is_err());
}
