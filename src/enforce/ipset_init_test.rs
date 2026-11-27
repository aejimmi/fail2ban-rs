//! Re-initialization and missing-binary behavior of the ipset backend's `init`.
//!
//! Split from `ipset_test.rs`, which owns the fake-binary harness these tests
//! reuse, to keep both files under the project's 500-line limit.

use super::*;

use super::ipset_test::{fake_ok, missing_binaries};

#[tokio::test]
async fn test_init_errors_when_the_ipset_binary_is_missing() {
    let err = missing_binaries()
        .init("sshd", &[], "tcp")
        .await
        .expect_err("a missing binary must surface as an error");
    assert!(
        err.to_string().contains("ipset command failed"),
        "got: {err}"
    );
}

/// Re-initializing an already-initialized jail must not stack a duplicate
/// match rule: the `-C` probe finds the existing rule and skips `-I`.
#[tokio::test]
async fn test_init_twice_inserts_the_match_rule_once() {
    let f = fake_ok();
    f.backend.init("sshd", &[], "tcp").await.expect("init");
    f.backend.init("sshd", &[], "tcp").await.expect("re-init");
    for (rules, sets) in [(f.iptables(), 1), (f.ip6tables(), 2)] {
        let inserts = rules.iter().filter(|r| r[0] == "-I").count();
        assert_eq!(inserts, sets, "one -I per set across two inits: {rules:?}");
        assert_eq!(rules.len(), 3 * sets, "-C, -I, -C: {rules:?}");
    }
}
