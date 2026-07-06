use super::*;

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Separator the fake binary writes between invocations in its log file.
const SEP: &str = "===";

/// Write an executable shell script standing in for `iptables`/`ip6tables`.
///
/// Every invocation appends its argv (one arg per line) to `log_path`,
/// followed by a `===` separator line, then prints `stdout` and exits with
/// `exit_code`. This lets tests assert on exactly what args the backend
/// constructed without needing root or a real netfilter stack.
fn write_fake_bin(
    path: &std::path::Path,
    log_path: &std::path::Path,
    exit_code: i32,
    stdout: &str,
) {
    let script = format!(
        "#!/bin/sh\nfor a in \"$@\"; do\n  printf '%s\\n' \"$a\"\ndone >> \"{log}\"\nprintf '{sep}\\n' >> \"{log}\"\nprintf '%s' \"{stdout}\"\nexit {code}\n",
        log = log_path.display(),
        sep = SEP,
        stdout = stdout,
        code = exit_code,
    );
    fs::write(path, script).expect("write fake binary script");
    #[cfg(unix)]
    {
        let mut perm = fs::metadata(path).expect("stat fake binary").permissions();
        perm.set_mode(0o755);
        fs::set_permissions(path, perm).expect("chmod fake binary");
    }
}

/// Parse the log file into one `Vec<String>` of args per invocation.
///
/// Returns an empty list if the binary was never invoked (log file absent).
fn read_invocations(log_path: &std::path::Path) -> Vec<Vec<String>> {
    let Ok(content) = fs::read_to_string(log_path) else {
        return Vec::new();
    };
    content
        .split(&format!("{SEP}\n"))
        .filter(|block| !block.is_empty())
        .map(|block| block.lines().map(str::to_string).collect())
        .collect()
}

/// A pair of fake `iptables`/`ip6tables` binaries plus their invocation logs.
struct FakeBackend {
    backend: IptablesBackend,
    v4_log: std::path::PathBuf,
    v6_log: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

/// Build a fake backend where both binaries succeed (exit 0, empty stdout).
fn fake_backend_success() -> FakeBackend {
    fake_backend(0, 0, "", "")
}

/// Build a fake backend with independently controllable exit codes/stdout
/// for the v4 and v6 binaries.
fn fake_backend(v4_exit: i32, v6_exit: i32, v4_stdout: &str, v6_stdout: &str) -> FakeBackend {
    let dir = tempfile::tempdir().expect("tempdir");
    let iptables_path = dir.path().join("iptables");
    let ip6tables_path = dir.path().join("ip6tables");
    let v4_log = dir.path().join("iptables.log");
    let v6_log = dir.path().join("ip6tables.log");

    write_fake_bin(&iptables_path, &v4_log, v4_exit, v4_stdout);
    write_fake_bin(&ip6tables_path, &v6_log, v6_exit, v6_stdout);

    FakeBackend {
        backend: IptablesBackend::new(iptables_path, ip6tables_path),
        v4_log,
        v6_log,
        _dir: dir,
    }
}

#[tokio::test]
async fn init_with_ports_uses_multiport_and_jail_chain_name() {
    let fb = fake_backend_success();
    fb.backend
        .init("sshd", &["22".to_string(), "80".to_string()], "tcp")
        .await
        .expect("init should succeed");

    for log in [&fb.v4_log, &fb.v6_log] {
        let invocations = read_invocations(log);
        // create-chain, RETURN rule, INPUT jump rule.
        assert_eq!(
            invocations.len(),
            3,
            "unexpected invocation count: {invocations:?}"
        );
        assert_eq!(invocations[0], vec!["-N", "f2b-sshd"]);
        assert_eq!(invocations[1], vec!["-A", "f2b-sshd", "-j", "RETURN"]);
        assert_eq!(
            invocations[2],
            vec![
                "-I",
                "INPUT",
                "-p",
                "tcp",
                "-m",
                "multiport",
                "--dports",
                "22,80",
                "-j",
                "f2b-sshd",
            ]
        );
    }
}

#[tokio::test]
async fn init_without_ports_inserts_plain_jump_rule() {
    let fb = fake_backend_success();
    fb.backend
        .init("nginx", &[], "tcp")
        .await
        .expect("init should succeed");

    for log in [&fb.v4_log, &fb.v6_log] {
        let invocations = read_invocations(log);
        assert_eq!(
            invocations.len(),
            3,
            "unexpected invocation count: {invocations:?}"
        );
        assert_eq!(
            invocations[2],
            vec!["-I", "INPUT", "-j", "f2b-nginx"],
            "no-port init must not add -p/-m/--dports"
        );
    }
}

#[tokio::test]
async fn init_never_fails_even_when_every_underlying_command_fails() {
    // init logs failures but always returns Ok — chain/rule creation failing
    // (e.g. because it already exists) must not abort startup.
    let fb = fake_backend(1, 1, "", "");
    let result = fb.backend.init("sshd", &[], "tcp").await;
    assert!(result.is_ok(), "init must tolerate per-command failures");
}

#[tokio::test]
async fn ban_ipv4_only_invokes_iptables_not_ip6tables() {
    let fb = fake_backend_success();
    let ip: IpAddr = "203.0.113.5".parse().expect("valid ipv4");
    fb.backend
        .ban(&ip, "sshd")
        .await
        .expect("ban should succeed");

    let v4 = read_invocations(&fb.v4_log);
    let v6 = read_invocations(&fb.v6_log);
    assert_eq!(
        v4.len(),
        1,
        "iptables should be invoked exactly once: {v4:?}"
    );
    assert_eq!(
        v4[0],
        vec!["-I", "f2b-sshd", "-s", "203.0.113.5", "-j", "DROP"]
    );
    assert!(
        v6.is_empty(),
        "ip6tables must not be touched for an ipv4 ban: {v6:?}"
    );
}

#[tokio::test]
async fn ban_ipv6_only_invokes_ip6tables_not_iptables() {
    let fb = fake_backend_success();
    let ip: IpAddr = "2001:db8::5".parse().expect("valid ipv6");
    fb.backend
        .ban(&ip, "sshd")
        .await
        .expect("ban should succeed");

    let v4 = read_invocations(&fb.v4_log);
    let v6 = read_invocations(&fb.v6_log);
    assert!(
        v4.is_empty(),
        "iptables must not be touched for an ipv6 ban: {v4:?}"
    );
    assert_eq!(
        v6.len(),
        1,
        "ip6tables should be invoked exactly once: {v6:?}"
    );
    assert_eq!(
        v6[0],
        vec!["-I", "f2b-sshd", "-s", "2001:db8::5", "-j", "DROP"]
    );
}

#[tokio::test]
async fn ban_propagates_command_failure() {
    let fb = fake_backend(1, 0, "", "");
    let ip: IpAddr = "203.0.113.5".parse().expect("valid ipv4");
    let err = fb
        .backend
        .ban(&ip, "sshd")
        .await
        .expect_err("nonzero exit must surface as an error");
    assert!(err.to_string().contains("exit"), "got: {err}");
}

#[tokio::test]
async fn unban_ipv4_deletes_drop_rule_via_iptables() {
    let fb = fake_backend_success();
    let ip: IpAddr = "198.51.100.9".parse().expect("valid ipv4");
    fb.backend
        .unban(&ip, "sshd")
        .await
        .expect("unban should succeed");

    let v4 = read_invocations(&fb.v4_log);
    assert_eq!(v4.len(), 1);
    assert_eq!(
        v4[0],
        vec!["-D", "f2b-sshd", "-s", "198.51.100.9", "-j", "DROP"]
    );
    assert!(read_invocations(&fb.v6_log).is_empty());
}

#[tokio::test]
async fn unban_absent_rule_is_not_a_hard_error() {
    // The DROP rule may already be gone (kernel timeout, prior unban); a
    // nonzero exit from the underlying command must still yield Ok(()).
    let fb = fake_backend(1, 0, "", "");
    let ip: IpAddr = "198.51.100.9".parse().expect("valid ipv4");
    let result = fb.backend.unban(&ip, "sshd").await;
    assert!(result.is_ok(), "missing rule on unban must not be fatal");
}

#[tokio::test]
async fn teardown_runs_delete_flush_and_destroy_on_both_families() {
    let fb = fake_backend_success();
    fb.backend
        .teardown("sshd")
        .await
        .expect("teardown should succeed");

    for log in [&fb.v4_log, &fb.v6_log] {
        let invocations = read_invocations(log);
        assert_eq!(
            invocations.len(),
            3,
            "unexpected invocation count: {invocations:?}"
        );
        assert_eq!(invocations[0], vec!["-D", "INPUT", "-j", "f2b-sshd"]);
        assert_eq!(invocations[1], vec!["-F", "f2b-sshd"]);
        assert_eq!(invocations[2], vec!["-X", "f2b-sshd"]);
    }
}

#[tokio::test]
async fn teardown_ignores_failures_on_every_step() {
    // Every step is best-effort (chain may not exist, may still have
    // references, etc.) — teardown must still report success.
    let fb = fake_backend(1, 1, "", "");
    let result = fb.backend.teardown("sshd").await;
    assert!(result.is_ok(), "teardown must swallow per-command failures");
}

#[tokio::test]
async fn is_banned_true_when_ip_present_in_chain_listing() {
    let fb = fake_backend(0, 0, "DROP 203.0.113.5 0.0.0.0/0\n", "");
    let ip: IpAddr = "203.0.113.5".parse().expect("valid ipv4");
    let banned = fb
        .backend
        .is_banned(&ip, "sshd")
        .await
        .expect("is_banned should succeed");
    assert!(banned, "ip present in -L output must report banned");
}

#[tokio::test]
async fn is_banned_false_when_ip_absent_from_chain_listing() {
    let fb = fake_backend(0, 0, "Chain f2b-sshd (1 references)\n", "");
    let ip: IpAddr = "203.0.113.5".parse().expect("valid ipv4");
    let banned = fb
        .backend
        .is_banned(&ip, "sshd")
        .await
        .expect("is_banned should succeed");
    assert!(!banned, "ip absent from -L output must report not banned");
}

#[tokio::test]
async fn is_banned_uses_ip6tables_for_ipv6() {
    let fb = fake_backend(0, 0, "", "DROP 2001:db8::9 ::/0\n");
    let ip: IpAddr = "2001:db8::9".parse().expect("valid ipv6");
    let banned = fb
        .backend
        .is_banned(&ip, "sshd")
        .await
        .expect("is_banned should succeed");
    assert!(
        banned,
        "ipv6 lookup must read ip6tables output, not iptables"
    );
}

#[test]
fn backend_name_is_iptables() {
    let backend = IptablesBackend::new(
        std::path::PathBuf::from("/bin/true"),
        std::path::PathBuf::from("/bin/true"),
    );
    assert_eq!(backend.name(), "iptables");
}
