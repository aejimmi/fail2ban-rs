use super::*;

#[test]
fn validate_jail_name_accepts_typical_names() {
    for name in ["sshd", "nginx-auth", "my_jail", "a", &"x".repeat(64)] {
        assert!(
            ScriptBackend::validate_jail_name(name).is_ok(),
            "should accept {name:?}"
        );
    }
}

#[test]
fn validate_jail_name_rejects_shell_metacharacters() {
    for name in [
        "sshd; rm -rf /",
        "$(id)",
        "`id`",
        "jail with spaces",
        "a|b",
        "a&b",
        "a>b",
        "a\nb",
        "a'b",
        "a\"b",
        "jail/../etc",
    ] {
        assert!(
            ScriptBackend::validate_jail_name(name).is_err(),
            "should reject {name:?}"
        );
    }
}

#[test]
fn validate_jail_name_rejects_empty_and_overlong() {
    assert!(ScriptBackend::validate_jail_name("").is_err());
    assert!(ScriptBackend::validate_jail_name(&"x".repeat(65)).is_err());
}

#[tokio::test]
async fn ban_rejects_unsafe_jail_without_running() {
    let backend = ScriptBackend::new(
        "exit 1".to_string(), // would fail if it ever ran
        "exit 1".to_string(),
    );
    let ip: IpAddr = "1.2.3.4".parse().expect("valid ip");
    let err = backend
        .ban(&ip, "evil; touch /tmp/pwned")
        .await
        .expect_err("must reject unsafe jail");
    assert!(err.to_string().contains("unsafe jail name"), "got: {err}");
}

#[tokio::test]
async fn unban_rejects_unsafe_jail_without_running() {
    let backend = ScriptBackend::new(
        "exit 1".to_string(),
        "exit 1".to_string(), // would fail if it ever ran
    );
    let ip: IpAddr = "1.2.3.4".parse().expect("valid ip");
    let err = backend
        .unban(&ip, "$(id)")
        .await
        .expect_err("must reject unsafe jail");
    assert!(err.to_string().contains("unsafe jail name"), "got: {err}");
}

/// Ban runs the real templated command via `sh -c`, substituting `<IP>` and
/// `<JAIL>` — verified by reading back a marker file the command writes.
#[tokio::test]
async fn ban_runs_real_command_with_ip_and_jail_substituted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("ban.marker");
    let backend = ScriptBackend::new(
        format!("printf '%s %s' <IP> <JAIL> > {}", marker.display()),
        "exit 1".to_string(), // never run
    );
    let ip: IpAddr = "203.0.113.9".parse().expect("valid ip");

    backend.ban(&ip, "sshd").await.expect("ban should succeed");

    let content = std::fs::read_to_string(&marker).expect("marker file written");
    assert_eq!(content, "203.0.113.9 sshd");
}

/// Unban runs the real templated command via `sh -c`, substituting `<IP>`
/// and `<JAIL>`.
#[tokio::test]
async fn unban_runs_real_command_with_ip_and_jail_substituted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("unban.marker");
    let backend = ScriptBackend::new(
        "exit 1".to_string(), // never run
        format!("printf '%s %s' <IP> <JAIL> > {}", marker.display()),
    );
    let ip: IpAddr = "198.51.100.4".parse().expect("valid ip");

    backend
        .unban(&ip, "nginx")
        .await
        .expect("unban should succeed");

    let content = std::fs::read_to_string(&marker).expect("marker file written");
    assert_eq!(content, "198.51.100.4 nginx");
}

#[tokio::test]
async fn ban_nonzero_exit_maps_to_error() {
    let backend = ScriptBackend::new("exit 7".to_string(), "exit 0".to_string());
    let ip: IpAddr = "1.2.3.4".parse().expect("valid ip");
    let err = backend
        .ban(&ip, "sshd")
        .await
        .expect_err("a nonzero exit must surface as an error");
    assert!(err.to_string().contains("exit"), "got: {err}");
}

#[tokio::test]
async fn unban_nonzero_exit_maps_to_error() {
    let backend = ScriptBackend::new("exit 0".to_string(), "exit 7".to_string());
    let ip: IpAddr = "1.2.3.4".parse().expect("valid ip");
    let err = backend
        .unban(&ip, "sshd")
        .await
        .expect_err("a nonzero exit must surface as an error");
    assert!(err.to_string().contains("exit"), "got: {err}");
}

/// The script backend has no way to query firewall state, so `is_banned`
/// always reports `false` regardless of the configured commands.
#[tokio::test]
async fn is_banned_always_returns_false() {
    let backend = ScriptBackend::new("exit 0".to_string(), "exit 0".to_string());
    let ip: IpAddr = "1.2.3.4".parse().expect("valid ip");
    let banned = backend
        .is_banned(&ip, "sshd")
        .await
        .expect("is_banned should not error");
    assert!(
        !banned,
        "script backend cannot query state, must report false"
    );
}

/// `init`/`teardown` are no-ops for the script backend: no command is ever
/// run for jail lifecycle management, only ban/unban.
#[tokio::test]
async fn init_and_teardown_are_no_ops() {
    let backend = ScriptBackend::new("exit 1".to_string(), "exit 1".to_string());
    backend
        .init("sshd", &["22".to_string()], "tcp")
        .await
        .expect("init must be a no-op success even with a failing ban/unban command");
    backend
        .teardown("sshd")
        .await
        .expect("teardown must be a no-op success");
}
