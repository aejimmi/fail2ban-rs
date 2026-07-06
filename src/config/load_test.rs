use super::*;

fn valid_toml() -> String {
    r#"
    [global]
    state_file = "/tmp/state.bin"
    socket_path = "/tmp/fail2ban-rs.sock"
    channel_size = 512

    [jail.sshd]
    enabled = true
    log_path = "/var/log/auth.log"
    date_format = "syslog"
    filter = ['sshd\[\d+\]: Failed password for .* from <HOST>']
    max_retry = 5
    find_time = 600
    ban_time = 3600
    backend = "nftables"
    ignoreip = ["127.0.0.1/8"]
    ignoreself = true
    "#
    .to_string()
}

#[test]
fn parse_valid_config() {
    let config = Config::parse(&valid_toml()).unwrap();
    assert_eq!(config.global.channel_size, 512);
    assert_eq!(config.jail.len(), 1);
    let sshd = &config.jail["sshd"];
    assert!(sshd.enabled);
    assert_eq!(sshd.max_retry, 5);
    assert_eq!(sshd.find_time, 600);
    assert_eq!(sshd.ban_time, 3600);
}

#[test]
fn from_file_not_found() {
    let result = Config::from_file(std::path::Path::new("/nonexistent/config.toml"));
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("not found"), "got: {err}");
}

#[test]
fn from_file_invalid_toml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.toml");
    std::fs::write(&path, "not valid [[ toml").unwrap();
    let result = Config::from_file(&path);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// config.d overlay tests
// ---------------------------------------------------------------------------

#[test]
fn config_d_overlay_adds_jail() {
    let dir = tempfile::tempdir().unwrap();
    let main_path = dir.path().join("config.toml");
    std::fs::write(
        &main_path,
        r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    "#,
    )
    .unwrap();

    let config_d = dir.path().join("config.d");
    std::fs::create_dir(&config_d).unwrap();
    std::fs::write(
        config_d.join("nginx.toml"),
        r#"
    [jail.nginx]
    log_path = "/var/log/nginx.log"
    filter = ['client <HOST>']
    "#,
    )
    .unwrap();

    let config = Config::from_file(&main_path).unwrap();
    assert_eq!(config.jail.len(), 2);
    assert!(config.jail.contains_key("sshd"));
    assert!(config.jail.contains_key("nginx"));
}

#[test]
fn config_d_overlay_overrides_scalar() {
    let dir = tempfile::tempdir().unwrap();
    let main_path = dir.path().join("config.toml");
    std::fs::write(
        &main_path,
        r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    max_retry = 5
    "#,
    )
    .unwrap();

    let config_d = dir.path().join("config.d");
    std::fs::create_dir(&config_d).unwrap();
    std::fs::write(
        config_d.join("override.toml"),
        r"
    [jail.sshd]
    max_retry = 10
    ",
    )
    .unwrap();

    let config = Config::from_file(&main_path).unwrap();
    assert_eq!(config.jail["sshd"].max_retry, 10);
}

#[test]
fn config_d_sorted_order() {
    let dir = tempfile::tempdir().unwrap();
    let main_path = dir.path().join("config.toml");
    std::fs::write(
        &main_path,
        r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    max_retry = 1
    "#,
    )
    .unwrap();

    let config_d = dir.path().join("config.d");
    std::fs::create_dir(&config_d).unwrap();

    // "b.toml" sets max_retry=5, "c.toml" sets max_retry=8.
    // Alphabetical order: b then c, so c wins.
    std::fs::write(config_d.join("b.toml"), "[jail.sshd]\nmax_retry = 5\n").unwrap();
    std::fs::write(config_d.join("c.toml"), "[jail.sshd]\nmax_retry = 8\n").unwrap();

    let config = Config::from_file(&main_path).unwrap();
    assert_eq!(config.jail["sshd"].max_retry, 8);
}

#[test]
fn config_d_missing_dir_is_fine() {
    let dir = tempfile::tempdir().unwrap();
    let main_path = dir.path().join("config.toml");
    std::fs::write(
        &main_path,
        r#"
    [global]

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    "#,
    )
    .unwrap();

    // No config.d directory — should succeed without error.
    let config = Config::from_file(&main_path).unwrap();
    assert_eq!(config.jail.len(), 1);
}

// ---------------------------------------------------------------------------
// Deprecated global.log_level compatibility shim
// ---------------------------------------------------------------------------

#[test]
fn deprecated_log_level_applies_to_logging_level() {
    let toml = r#"
    [global]
    log_level = "debug"

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    "#;
    let config = Config::parse(toml).unwrap();
    assert_eq!(config.logging.level.as_deref(), Some("debug"));
}

#[test]
fn deprecated_log_level_yields_to_explicit_logging_level() {
    let toml = r#"
    [global]
    log_level = "debug"

    [logging]
    level = "warn"

    [jail.sshd]
    log_path = "/var/log/auth.log"
    filter = ['from <HOST>']
    "#;
    let config = Config::parse(toml).unwrap();
    assert_eq!(config.logging.level.as_deref(), Some("warn"));
}
