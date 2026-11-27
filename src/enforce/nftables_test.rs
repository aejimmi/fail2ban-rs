//! Fake-`nft` harness plus the nftables backend's pure helpers, `init`, and
//! teardown. The harness is shared with `nftables_ops_test.rs`.

use super::*;

use crate::enforce::fake_bin_test_support::{
    install_script, logging_prelude, read_invocations, write_fake_bin,
};

/// A fake `nft` binary plus its invocation log.
pub(super) struct FakeNft {
    pub(super) backend: NftablesBackend,
    log: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

impl FakeNft {
    /// Argv of every `nft` invocation, in order.
    pub(super) fn calls(&self) -> Vec<Vec<String>> {
        read_invocations(&self.log)
    }
}

/// Build a fake `nft` where every invocation succeeds (exit 0, empty stdout).
pub(super) fn fake_nft_success() -> FakeNft {
    fake_nft(0, "")
}

/// Build a fake `nft` with a controllable exit code and stdout.
pub(super) fn fake_nft(exit_code: i32, stdout: &str) -> FakeNft {
    let dir = tempfile::tempdir().expect("tempdir");
    let nft_path = dir.path().join("nft");
    let log = dir.path().join("nft.log");
    write_fake_bin(&nft_path, &log, exit_code, stdout, 1);
    FakeNft {
        backend: NftablesBackend::new(nft_path),
        log,
        _dir: dir,
    }
}

/// Build a fake `nft` that fails (exit 1) whenever its space-joined argv
/// matches the shell glob `pattern`; every other invocation succeeds.
pub(super) fn fake_nft_fail_matching(pattern: &str) -> FakeNft {
    let dir = tempfile::tempdir().expect("tempdir");
    let nft_path = dir.path().join("nft");
    let log = dir.path().join("nft.log");
    let script = format!(
        "{}case \"$*\" in\n  {pattern}) exit 1 ;;\nesac\nexit 0\n",
        logging_prelude(&log)
    );
    install_script(&nft_path, &script);
    FakeNft {
        backend: NftablesBackend::new(nft_path),
        log,
        _dir: dir,
    }
}

/// Argv for an nft invocation against the fail2ban-rs table.
fn table_args(verb: &str, kind: &str, name: &str) -> Vec<String> {
    [verb, kind, "inet", "fail2ban-rs", name]
        .iter()
        .map(ToString::to_string)
        .collect()
}

/// Argv for adding a rule to a jail chain.
fn rule_args(chain: &str, expr: &str) -> Vec<String> {
    let mut args = table_args("add", "rule", chain);
    args.push(expr.to_string());
    args
}

// --- pure helpers -------------------------------------------------------

#[test]
fn test_set_block_includes_timeout_flag() {
    let block = set_block("ipv4_addr", false);
    assert_eq!(block, "{ type ipv4_addr; flags timeout; }");
    assert!(set_block("ipv6_addr", true).contains("ipv6_addr"));
}

#[test]
fn test_element_spec_with_expiry_has_timeout_seconds() {
    let ip: BanTarget = "1.2.3.4".parse().unwrap();
    assert_eq!(
        element_spec(&ip, Some(1_060), 1_000),
        "{ 1.2.3.4 timeout 60s }"
    );
}

#[test]
fn test_element_spec_without_expiry_has_no_timeout() {
    let ip: BanTarget = "1.2.3.4".parse().unwrap();
    assert_eq!(element_spec(&ip, None, 1_000), "{ 1.2.3.4 }");
}

#[test]
fn test_element_spec_clamps_past_expiry_to_one_second() {
    let ip: BanTarget = "1.2.3.4".parse().unwrap();
    assert!(element_spec(&ip, Some(500), 1_000).contains("timeout 1s"));
}

#[test]
fn test_element_spec_ipv6() {
    let ip: BanTarget = "2001:db8::1".parse().unwrap();
    assert_eq!(
        element_spec(&ip, Some(1_030), 1_000),
        "{ 2001:db8::1 timeout 30s }"
    );
}

#[test]
fn test_rule_exprs_without_ports_match_all_traffic() {
    assert_eq!(
        rule_exprs("sshd", &[], "tcp"),
        [
            "ip saddr @f2b-sshd reject",
            "ip6 saddr @f2b-sshd-v6 reject",
            "ip6 saddr @f2b6-sshd reject"
        ]
    );
}

#[test]
fn test_rule_exprs_with_ports_scope_to_dport_list() {
    let ports = ["22".to_string(), "2222".to_string()];
    assert_eq!(
        rule_exprs("sshd", &ports, "tcp"),
        [
            "tcp dport { 22,2222 } ip saddr @f2b-sshd reject",
            "tcp dport { 22,2222 } ip6 saddr @f2b-sshd-v6 reject",
            "tcp dport { 22,2222 } ip6 saddr @f2b6-sshd reject",
        ]
    );
}

// --- init ---------------------------------------------------------------

#[tokio::test]
async fn test_init_without_ports_builds_jail_chain_sets_and_rules() {
    let fake = fake_nft_success();
    fake.backend.init("sshd", &[], "tcp").await.expect("init");

    let mut add_chain = table_args("add", "chain", "f2b-sshd");
    add_chain.push("{ type filter hook input priority -1; policy accept; }".into());
    let mut add_v4 = table_args("add", "set", "f2b-sshd");
    add_v4.push("{ type ipv4_addr; flags timeout; }".into());
    let mut add_v6 = table_args("add", "set", "f2b-sshd-v6");
    add_v6.push("{ type ipv6_addr; flags timeout; }".into());
    let mut add_prefix = table_args("add", "set", "f2b6-sshd");
    add_prefix.push("{ type ipv6_addr; flags interval,timeout; }".into());
    assert_eq!(
        fake.calls(),
        vec![
            vec!["add", "table", "inet", "fail2ban-rs"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>(),
            table_args("flush", "chain", "f2b-chain"),
            table_args("delete", "chain", "f2b-chain"),
            add_chain,
            table_args("flush", "chain", "f2b-sshd"),
            add_v4,
            add_v6,
            add_prefix,
            rule_args("f2b-sshd", "ip saddr @f2b-sshd reject"),
            rule_args("f2b-sshd", "ip6 saddr @f2b-sshd-v6 reject"),
            rule_args("f2b-sshd", "ip6 saddr @f2b6-sshd reject"),
        ]
    );
}

#[tokio::test]
async fn test_init_with_ports_adds_scoped_rules_to_jail_chain() {
    let fake = fake_nft_success();
    let ports = ["22".to_string(), "2222".to_string()];
    fake.backend
        .init("sshd", &ports, "tcp")
        .await
        .expect("init");

    let calls = fake.calls();
    assert_eq!(calls.len(), 11, "unexpected invocations: {calls:?}");
    assert_eq!(
        calls[8],
        rule_args(
            "f2b-sshd",
            "tcp dport { 22,2222 } ip saddr @f2b-sshd reject"
        )
    );
    assert_eq!(
        calls[9],
        rule_args(
            "f2b-sshd",
            "tcp dport { 22,2222 } ip6 saddr @f2b-sshd-v6 reject",
        )
    );
    assert!(
        calls
            .iter()
            .filter(|c| c[1] == "rule")
            .all(|c| c[4] == "f2b-sshd"),
        "every rule must land in the jail's own chain: {calls:?}"
    );
}

#[tokio::test]
async fn test_init_flushes_jail_chain_before_adding_rules() {
    // Re-init (e.g. a port change) must not stack rules on the old ones.
    let fake = fake_nft_success();
    fake.backend.init("sshd", &[], "tcp").await.expect("init");
    fake.backend
        .init("sshd", &["8080".to_string()], "tcp")
        .await
        .expect("re-init");

    let calls = fake.calls();
    let second = &calls[11..];
    let flush = second
        .iter()
        .position(|c| *c == table_args("flush", "chain", "f2b-sshd"))
        .expect("re-init must flush the jail chain");
    let first_rule = second
        .iter()
        .position(|c| c[1] == "rule")
        .expect("re-init adds rules");
    assert!(
        flush < first_rule,
        "flush must precede rule adds: {second:?}"
    );
}

#[tokio::test]
async fn test_init_tolerates_missing_legacy_chain() {
    let fake = fake_nft_fail_matching("*f2b-chain*");
    fake.backend
        .init("sshd", &[], "tcp")
        .await
        .expect("an absent legacy chain must not fail init");
    assert_eq!(fake.calls().len(), 11);
}

#[tokio::test]
async fn test_init_fails_when_jail_chain_creation_fails() {
    let fake = fake_nft_fail_matching("\"add chain inet fail2ban-rs f2b-sshd\"*");
    let err = fake
        .backend
        .init("sshd", &[], "tcp")
        .await
        .expect_err("a jail chain failure must be fatal");
    assert!(err.to_string().contains("nft exit"), "got: {err}");
    assert_eq!(fake.calls().len(), 4, "init must stop at the chain step");
}

#[tokio::test]
async fn test_init_aborts_on_table_failure() {
    let fake = fake_nft(1, "");
    let err = fake
        .backend
        .init("sshd", &[], "tcp")
        .await
        .expect_err("table creation failure must abort init");
    assert!(err.to_string().contains("exit"), "got: {err}");
    assert_eq!(fake.calls().len(), 1, "init must stop at the first failure");
}

#[tokio::test]
async fn test_init_errors_when_nft_binary_is_missing() {
    let backend = NftablesBackend::new("/nonexistent/nft-binary-for-tests-xyz".into());
    let err = backend
        .init("sshd", &[], "tcp")
        .await
        .expect_err("a missing binary must surface as an error");
    assert!(err.to_string().contains("nft command failed"), "got: {err}");
}

// --- teardown -----------------------------------------------------------

#[tokio::test]
async fn test_teardown_deletes_jail_chain_before_sets() {
    let fake = fake_nft_success();
    fake.backend.teardown("sshd").await.expect("teardown");

    assert_eq!(
        fake.calls(),
        vec![
            table_args("flush", "chain", "f2b-sshd"),
            table_args("delete", "chain", "f2b-sshd"),
            table_args("flush", "set", "f2b-sshd"),
            table_args("delete", "set", "f2b-sshd"),
            table_args("flush", "set", "f2b-sshd-v6"),
            table_args("delete", "set", "f2b-sshd-v6"),
            table_args("flush", "set", "f2b6-sshd"),
            table_args("delete", "set", "f2b6-sshd"),
        ]
    );
}

#[tokio::test]
async fn test_teardown_ignores_failures_on_every_step() {
    let fake = fake_nft(1, "");
    fake.backend
        .teardown("sshd")
        .await
        .expect("teardown must swallow per-command failures");
    assert_eq!(fake.calls().len(), 8, "every step must still be attempted");
}

#[tokio::test]
async fn test_teardown_full_deletes_the_shared_table() {
    let fake = fake_nft_success();
    fake.backend
        .teardown_full("sshd")
        .await
        .expect("teardown_full");
    assert_eq!(
        fake.calls(),
        vec![vec!["delete", "table", "inet", "fail2ban-rs"]]
    );
}

#[tokio::test]
async fn test_teardown_full_ignores_failure() {
    let fake = fake_nft(1, "");
    fake.backend
        .teardown_full("sshd")
        .await
        .expect("full teardown must swallow the delete-table failure");
}

/// The reserved jail name is exactly the one whose chain is the legacy chain,
/// so validation rejects precisely the name `remove_legacy_chain` would hit.
#[test]
fn test_chain_name_legacy_jail_name_maps_to_legacy_chain() {
    assert_eq!(chain_name(LEGACY_JAIL_NAME), LEGACY_CHAIN);
}

/// A jail's IPv6 set is its IPv4 set name plus the reserved suffix — the
/// collision validation prevents by rejecting names ending in the suffix.
#[test]
fn test_set_names_v6_uses_reserved_suffix() {
    let [v4, v6, prefix] = set_names("foo");
    assert_eq!(v6, format!("{v4}{V6_SET_SUFFIX}"));
    assert_eq!(prefix, "f2b6-foo");
    assert_eq!(set_names("foo-v6")[0], v6, "the collision being guarded");
}
