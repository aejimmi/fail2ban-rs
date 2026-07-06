use super::*;

use std::fs;

/// Separator the fake `nft` binary writes between invocations in its log
/// file. Mirrors the technique used in `iptables_test.rs`.
const SEP: &str = "===";

/// Write an executable shell script standing in for `nft`.
///
/// Every invocation appends its argv (one arg per line) to `log_path`,
/// followed by a `===` separator line, then exits with `exit_code` (and
/// prints `stdout`). This lets tests assert on exactly what args the backend
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
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(path).expect("stat fake binary").permissions();
        perm.set_mode(0o755);
        fs::set_permissions(path, perm).expect("chmod fake binary");
    }
}

/// A fake binary whose exit code depends on whether the 2nd argument
/// (`nft`'s subcommand, e.g. `table`/`chain`/`set`/`rule`/`element`) equals
/// `fail_on`. Used to test that `init` tolerates a chain-creation failure
/// (an `nft add chain` call whose exit is ignored) while still requiring
/// every other step to succeed.
fn write_conditional_fail_bin(path: &std::path::Path, log_path: &std::path::Path, fail_on: &str) {
    let script = format!(
        "#!/bin/sh\nfor a in \"$@\"; do\n  printf '%s\\n' \"$a\"\ndone >> \"{log}\"\nprintf '{sep}\\n' >> \"{log}\"\nif [ \"$2\" = \"{fail_on}\" ]; then\n  exit 1\nfi\nexit 0\n",
        log = log_path.display(),
        sep = SEP,
        fail_on = fail_on,
    );
    fs::write(path, script).expect("write fake binary script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
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

/// A fake `nft` binary plus its invocation log.
struct FakeNft {
    backend: NftablesBackend,
    log: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

/// Build a fake `nft` where every invocation succeeds (exit 0, empty stdout).
fn fake_nft_success() -> FakeNft {
    fake_nft(0, "")
}

/// Build a fake `nft` with a controllable exit code and stdout for every
/// invocation.
fn fake_nft(exit_code: i32, stdout: &str) -> FakeNft {
    let dir = tempfile::tempdir().expect("tempdir");
    let nft_path = dir.path().join("nft");
    let log = dir.path().join("nft.log");
    write_fake_bin(&nft_path, &log, exit_code, stdout);
    FakeNft {
        backend: NftablesBackend::new(nft_path),
        log,
        _dir: dir,
    }
}

/// Build a fake `nft` whose invocation with a given 2nd arg (subcommand)
/// always fails; every other invocation succeeds.
fn fake_nft_conditional_fail(fail_on: &str) -> FakeNft {
    let dir = tempfile::tempdir().expect("tempdir");
    let nft_path = dir.path().join("nft");
    let log = dir.path().join("nft.log");
    write_conditional_fail_bin(&nft_path, &log, fail_on);
    FakeNft {
        backend: NftablesBackend::new(nft_path),
        log,
        _dir: dir,
    }
}

#[test]
fn set_block_includes_timeout_flag() {
    let block = set_block("ipv4_addr");
    assert!(block.contains("flags"), "missing flags: {block}");
    assert!(block.contains("timeout"), "missing timeout flag: {block}");
    assert!(block.contains("ipv4_addr"), "missing type: {block}");
}

#[test]
fn set_block_ipv6_type() {
    let block = set_block("ipv6_addr");
    assert!(block.contains("ipv6_addr"));
    assert!(block.contains("timeout"));
}

#[test]
fn element_spec_with_expiry_has_timeout_seconds() {
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    let spec = element_spec(&ip, Some(1_060), 1_000);
    assert!(spec.contains("1.2.3.4"), "missing ip: {spec}");
    assert!(spec.contains("timeout 60s"), "missing timeout: {spec}");
}

#[test]
fn element_spec_without_expiry_has_no_timeout() {
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    let spec = element_spec(&ip, None, 1_000);
    assert!(spec.contains("1.2.3.4"));
    assert!(!spec.contains("timeout"), "unexpected timeout: {spec}");
}

#[test]
fn element_spec_clamps_past_expiry_to_one_second() {
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    let spec = element_spec(&ip, Some(500), 1_000);
    assert!(spec.contains("timeout 1s"), "expected clamp: {spec}");
}

#[test]
fn element_spec_ipv6() {
    let ip: IpAddr = "2001:db8::1".parse().unwrap();
    let spec = element_spec(&ip, Some(1_030), 1_000);
    assert!(spec.contains("2001:db8::1"));
    assert!(spec.contains("timeout 30s"));
}

#[tokio::test]
async fn init_without_ports_creates_table_chain_sets_and_reject_rules() {
    let fake = fake_nft_success();
    fake.backend
        .init("sshd", &[], "tcp")
        .await
        .expect("init should succeed");

    let invocations = read_invocations(&fake.log);
    assert_eq!(
        invocations.len(),
        6,
        "table, chain, v4 set, v6 set, v4 rule, v6 rule: {invocations:?}"
    );
    assert_eq!(invocations[0], vec!["add", "table", "inet", "fail2ban-rs"]);
    assert_eq!(invocations[1][0], "add");
    assert_eq!(invocations[1][1], "chain");
    assert_eq!(
        invocations[2],
        vec![
            "add",
            "set",
            "inet",
            "fail2ban-rs",
            "f2b-sshd",
            "{ type ipv4_addr; flags timeout; }",
        ]
    );
    assert_eq!(
        invocations[3],
        vec![
            "add",
            "set",
            "inet",
            "fail2ban-rs",
            "f2b-sshd-v6",
            "{ type ipv6_addr; flags timeout; }",
        ]
    );
    assert_eq!(
        invocations[4],
        vec![
            "add",
            "rule",
            "inet",
            "fail2ban-rs",
            "f2b-chain",
            "ip saddr @f2b-sshd reject",
        ]
    );
    assert_eq!(
        invocations[5],
        vec![
            "add",
            "rule",
            "inet",
            "fail2ban-rs",
            "f2b-chain",
            "ip6 saddr @f2b-sshd-v6 reject",
        ]
    );
}

#[tokio::test]
async fn init_with_ports_scopes_reject_rules_to_dport_list() {
    let fake = fake_nft_success();
    fake.backend
        .init("sshd", &["22".to_string(), "2222".to_string()], "tcp")
        .await
        .expect("init should succeed");

    let invocations = read_invocations(&fake.log);
    assert_eq!(
        invocations.len(),
        6,
        "unexpected invocations: {invocations:?}"
    );
    assert_eq!(
        invocations[4],
        vec![
            "add",
            "rule",
            "inet",
            "fail2ban-rs",
            "f2b-chain",
            "tcp dport { 22,2222 } ip saddr @f2b-sshd reject",
        ]
    );
    assert_eq!(
        invocations[5],
        vec![
            "add",
            "rule",
            "inet",
            "fail2ban-rs",
            "f2b-chain",
            "tcp dport { 22,2222 } ip6 saddr @f2b-sshd-v6 reject",
        ]
    );
}

#[tokio::test]
async fn init_tolerates_chain_already_existing_but_still_creates_sets_and_rules() {
    // The chain-creation call's failure is ignored (`.ok()`); init must still
    // proceed to create the sets and rules.
    let fake = fake_nft_conditional_fail("chain");
    fake.backend
        .init("sshd", &[], "tcp")
        .await
        .expect("init must tolerate a chain-creation failure");

    let invocations = read_invocations(&fake.log);
    assert_eq!(
        invocations.len(),
        6,
        "init must still attempt every step: {invocations:?}"
    );
}

#[tokio::test]
async fn init_aborts_on_first_hard_failure() {
    // Every invocation fails; table creation (the first, non-tolerant call)
    // must abort init immediately rather than attempting the rest.
    let fake = fake_nft(1, "");
    let err = fake
        .backend
        .init("sshd", &[], "tcp")
        .await
        .expect_err("table creation failure must abort init");
    assert!(err.to_string().contains("exit"), "got: {err}");

    let invocations = read_invocations(&fake.log);
    assert_eq!(
        invocations.len(),
        1,
        "init must stop at the first hard failure: {invocations:?}"
    );
}

#[tokio::test]
async fn init_errors_when_nft_binary_is_missing() {
    let backend = NftablesBackend::new(std::path::PathBuf::from(
        "/nonexistent/nft-binary-for-tests-xyz",
    ));
    let err = backend
        .init("sshd", &[], "tcp")
        .await
        .expect_err("a missing binary must surface as an error");
    assert!(err.to_string().contains("nft command failed"), "got: {err}");
}

#[tokio::test]
async fn ban_without_expiry_adds_element_with_no_timeout() {
    let fake = fake_nft_success();
    let ip: IpAddr = "203.0.113.5".parse().unwrap();
    fake.backend
        .ban(&ip, "sshd")
        .await
        .expect("ban should succeed");

    let invocations = read_invocations(&fake.log);
    assert_eq!(invocations.len(), 1);
    assert_eq!(
        invocations[0],
        vec![
            "add",
            "element",
            "inet",
            "fail2ban-rs",
            "f2b-sshd",
            "{ 203.0.113.5 }"
        ]
    );
}

#[tokio::test]
async fn ban_with_timeout_adds_element_with_timeout_clause() {
    let fake = fake_nft_success();
    let ip: IpAddr = "203.0.113.6".parse().unwrap();
    let now = 1_000;
    fake.backend
        .ban_with_timeout(&ip, "sshd", Some(1_060), now)
        .await
        .expect("ban should succeed");

    let invocations = read_invocations(&fake.log);
    assert_eq!(invocations.len(), 1);
    assert_eq!(
        invocations[0],
        vec![
            "add",
            "element",
            "inet",
            "fail2ban-rs",
            "f2b-sshd",
            "{ 203.0.113.6 timeout 60s }",
        ]
    );
}

#[tokio::test]
async fn ban_propagates_command_failure() {
    let fake = fake_nft(1, "");
    let ip: IpAddr = "203.0.113.7".parse().unwrap();
    let err = fake
        .backend
        .ban(&ip, "sshd")
        .await
        .expect_err("nonzero exit must surface as an error");
    assert!(err.to_string().contains("exit"), "got: {err}");
}

#[tokio::test]
async fn unban_deletes_the_element() {
    let fake = fake_nft_success();
    let ip: IpAddr = "198.51.100.9".parse().unwrap();
    fake.backend
        .unban(&ip, "sshd")
        .await
        .expect("unban should succeed");

    let invocations = read_invocations(&fake.log);
    assert_eq!(invocations.len(), 1);
    assert_eq!(
        invocations[0],
        vec![
            "delete",
            "element",
            "inet",
            "fail2ban-rs",
            "f2b-sshd",
            "{ 198.51.100.9 }"
        ]
    );
}

#[tokio::test]
async fn unban_tolerates_an_already_absent_element() {
    let fake = fake_nft(1, "");
    let ip: IpAddr = "198.51.100.9".parse().unwrap();
    let result = fake.backend.unban(&ip, "sshd").await;
    assert!(
        result.is_ok(),
        "missing element on unban must not be fatal: {result:?}"
    );
}

#[tokio::test]
async fn teardown_flushes_and_deletes_both_family_sets() {
    let fake = fake_nft_success();
    fake.backend
        .teardown("sshd")
        .await
        .expect("teardown should succeed");

    let invocations = read_invocations(&fake.log);
    assert_eq!(
        invocations.len(),
        4,
        "unexpected invocations: {invocations:?}"
    );
    assert_eq!(
        invocations[0],
        vec!["flush", "set", "inet", "fail2ban-rs", "f2b-sshd"]
    );
    assert_eq!(
        invocations[1],
        vec!["delete", "set", "inet", "fail2ban-rs", "f2b-sshd"]
    );
    assert_eq!(
        invocations[2],
        vec!["flush", "set", "inet", "fail2ban-rs", "f2b-sshd-v6"]
    );
    assert_eq!(
        invocations[3],
        vec!["delete", "set", "inet", "fail2ban-rs", "f2b-sshd-v6"]
    );
}

#[tokio::test]
async fn teardown_ignores_failures_on_every_step() {
    let fake = fake_nft(1, "");
    let result = fake.backend.teardown("sshd").await;
    assert!(result.is_ok(), "teardown must swallow per-command failures");
}

#[tokio::test]
async fn teardown_full_deletes_the_shared_table() {
    let fake = fake_nft_success();
    fake.backend
        .teardown_full("sshd")
        .await
        .expect("full teardown should succeed");

    let invocations = read_invocations(&fake.log);
    assert_eq!(invocations.len(), 1);
    assert_eq!(
        invocations[0],
        vec!["delete", "table", "inet", "fail2ban-rs"]
    );
}

#[tokio::test]
async fn teardown_full_ignores_failure() {
    let fake = fake_nft(1, "");
    let result = fake.backend.teardown_full("sshd").await;
    assert!(
        result.is_ok(),
        "full teardown must swallow the delete-table failure"
    );
}

#[tokio::test]
async fn is_banned_true_when_ip_present_in_set_listing() {
    let fake = fake_nft(0, "set f2b-sshd {\n  elements = { 203.0.113.5 }\n}\n");
    let ip: IpAddr = "203.0.113.5".parse().unwrap();
    let banned = fake
        .backend
        .is_banned(&ip, "sshd")
        .await
        .expect("is_banned should succeed");
    assert!(banned, "ip present in listing must report banned");
}

#[tokio::test]
async fn is_banned_false_when_ip_absent_from_set_listing() {
    let fake = fake_nft(0, "set f2b-sshd {\n  type ipv4_addr\n}\n");
    let ip: IpAddr = "203.0.113.5".parse().unwrap();
    let banned = fake
        .backend
        .is_banned(&ip, "sshd")
        .await
        .expect("is_banned should succeed");
    assert!(!banned, "ip absent from listing must report not banned");
}

/// A nonzero `nft` exit is a query failure, not "not banned" — reconcile
/// must skip on error instead of re-applying every ban against a broken nft.
#[tokio::test]
async fn is_banned_errors_when_nft_exits_nonzero() {
    let fake = fake_nft(1, "");
    let ip: IpAddr = "203.0.113.5".parse().unwrap();
    let err = fake
        .backend
        .is_banned(&ip, "sshd")
        .await
        .expect_err("nonzero nft exit must surface as an error");
    assert!(
        err.to_string().contains("nft list set failed"),
        "got: {err}"
    );
}

#[tokio::test]
async fn is_banned_errors_when_nft_binary_is_missing() {
    let backend = NftablesBackend::new(std::path::PathBuf::from(
        "/nonexistent/nft-binary-for-tests-xyz",
    ));
    let ip: IpAddr = "203.0.113.5".parse().unwrap();
    let err = backend
        .is_banned(&ip, "sshd")
        .await
        .expect_err("a missing binary must surface as an error");
    assert!(err.to_string().contains("nft command failed"), "got: {err}");
}

#[test]
fn backend_name_is_nftables() {
    let backend = NftablesBackend::new(std::path::PathBuf::from("/bin/true"));
    assert_eq!(backend.name(), "nftables");
}
