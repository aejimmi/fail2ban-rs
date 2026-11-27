//! Ban, unban, query, and snapshot behavior of the nftables backend.
//!
//! Split from `nftables_test.rs`, which owns the fake-`nft` harness.

use super::*;

use super::nftables_test::{fake_nft, fake_nft_success};

/// A realistic multi-element IPv4 listing with per-element timeouts.
const V4_LISTING: &str = "table inet fail2ban-rs {
\tset f2b-sshd {
\t\ttype ipv4_addr
\t\tflags timeout
\t\telements = { 1.2.3.4 timeout 1m expires 59s, 5.6.7.8,
\t\t\t     9.9.9.9 timeout 10m expires 9m58s }
\t}
}
";

/// A multi-element IPv6 listing.
const V6_LISTING: &str = "table inet fail2ban-rs {
\tset f2b-sshd-v6 {
\t\ttype ipv6_addr
\t\tflags timeout
\t\telements = { 2001:db8::1, 2001:db8::2 timeout 30s expires 29s }
\t}
}
";

fn ip(s: &str) -> BanTarget {
    s.parse().unwrap()
}

// --- parse_set_elements --------------------------------------------------

#[test]
fn test_parse_set_elements_finds_every_element_in_a_multi_element_listing() {
    let got = parse_set_elements(V4_LISTING);
    let want: HashSet<BanTarget> = ["1.2.3.4", "5.6.7.8", "9.9.9.9"].map(ip).into();
    assert_eq!(got, want);
}

#[test]
fn test_parse_set_elements_handles_ipv6() {
    let got = parse_set_elements(V6_LISTING);
    let want: HashSet<BanTarget> = ["2001:db8::1", "2001:db8::2"].map(ip).into();
    assert_eq!(got, want);
}

#[test]
fn test_parse_set_elements_empty_set_has_no_elements() {
    let listing = "table inet fail2ban-rs {\n\tset f2b-sshd {\n\t\ttype ipv4_addr\n\t}\n}\n";
    assert!(parse_set_elements(listing).is_empty());
}

#[test]
fn test_parse_set_elements_ignores_garbage_tokens() {
    assert!(parse_set_elements("elements = { not-an-ip, 60s, 300 }").is_empty());
}

// --- ban / unban -----------------------------------------------------------

#[tokio::test]
async fn test_ban_ipv4_without_expiry_targets_ipv4_set() {
    let fake = fake_nft_success();
    fake.backend
        .ban(&ip("203.0.113.5"), "sshd")
        .await
        .expect("ban");
    assert_eq!(
        fake.calls(),
        vec![vec![
            "add",
            "element",
            "inet",
            "fail2ban-rs",
            "f2b-sshd",
            "{ 203.0.113.5 }"
        ]]
    );
}

#[tokio::test]
async fn test_ban_with_timeout_ipv4_targets_ipv4_set() {
    let fake = fake_nft_success();
    fake.backend
        .ban_with_timeout(&ip("203.0.113.6"), "sshd", Some(1_060), 1_000)
        .await
        .expect("ban");
    assert_eq!(
        fake.calls()[0],
        vec![
            "add",
            "element",
            "inet",
            "fail2ban-rs",
            "f2b-sshd",
            "{ 203.0.113.6 timeout 60s }"
        ]
    );
}

#[tokio::test]
async fn test_ban_with_timeout_ipv6_targets_ipv6_set() {
    let fake = fake_nft_success();
    fake.backend
        .ban_with_timeout(&ip("2001:db8::6"), "sshd", Some(1_060), 1_000)
        .await
        .expect("ban");
    assert_eq!(fake.calls()[0][4], "f2b-sshd-v6");
}

#[tokio::test]
async fn test_ban_propagates_command_failure() {
    let fake = fake_nft(1, "");
    let err = fake
        .backend
        .ban(&ip("203.0.113.7"), "sshd")
        .await
        .expect_err("nonzero exit must surface as an error");
    assert!(err.to_string().contains("exit"), "got: {err}");
}

#[tokio::test]
async fn test_unban_ipv4_deletes_from_ipv4_set() {
    let fake = fake_nft_success();
    fake.backend
        .unban(&ip("198.51.100.9"), "sshd")
        .await
        .expect("unban");
    assert_eq!(
        fake.calls(),
        vec![vec![
            "delete",
            "element",
            "inet",
            "fail2ban-rs",
            "f2b-sshd",
            "{ 198.51.100.9 }"
        ]]
    );
}

#[tokio::test]
async fn test_unban_ipv6_deletes_from_ipv6_set() {
    let fake = fake_nft_success();
    fake.backend
        .unban(&ip("2001:db8::9"), "sshd")
        .await
        .expect("unban");
    assert_eq!(fake.calls()[0][4], "f2b-sshd-v6");
}

#[tokio::test]
async fn test_unban_tolerates_an_already_absent_element() {
    let fake = fake_nft(1, "");
    fake.backend
        .unban(&ip("198.51.100.9"), "sshd")
        .await
        .expect("missing element on unban must not be fatal");
}

// --- is_banned -------------------------------------------------------------

#[tokio::test]
async fn test_is_banned_true_for_a_non_final_element() {
    // Regression: `1.2.3.4,` used to be compared verbatim and never matched.
    let fake = fake_nft(0, V4_LISTING);
    for addr in ["1.2.3.4", "5.6.7.8", "9.9.9.9"] {
        assert!(
            fake.backend
                .is_banned(&ip(addr), "sshd")
                .await
                .expect("query"),
            "{addr} is in the listing"
        );
    }
    assert_eq!(
        fake.calls()[0],
        vec!["list", "set", "inet", "fail2ban-rs", "f2b-sshd"]
    );
}

#[tokio::test]
async fn test_is_banned_ipv6_reads_the_ipv6_set() {
    let fake = fake_nft(0, V6_LISTING);
    assert!(
        fake.backend
            .is_banned(&ip("2001:db8::1"), "sshd")
            .await
            .expect("query")
    );
    assert_eq!(fake.calls()[0][4], "f2b-sshd-v6");
}

#[tokio::test]
async fn test_is_banned_false_when_ip_absent() {
    let fake = fake_nft(0, V4_LISTING);
    let banned = fake
        .backend
        .is_banned(&ip("1.2.3.5"), "sshd")
        .await
        .expect("query");
    assert!(!banned, "ip absent from listing must report not banned");
}

#[tokio::test]
async fn test_is_banned_errors_when_nft_exits_nonzero() {
    let fake = fake_nft(1, "");
    let err = fake
        .backend
        .is_banned(&ip("203.0.113.5"), "sshd")
        .await
        .expect_err("nonzero nft exit must surface as an error");
    assert!(
        err.to_string().contains("nft list set failed"),
        "got: {err}"
    );
}

#[tokio::test]
async fn test_is_banned_errors_when_nft_binary_is_missing() {
    let backend = NftablesBackend::new("/nonexistent/nft-binary-for-tests-xyz".into());
    let err = backend
        .is_banned(&ip("203.0.113.5"), "sshd")
        .await
        .expect_err("a missing binary must surface as an error");
    assert!(err.to_string().contains("nft command failed"), "got: {err}");
}

// --- snapshot --------------------------------------------------------------

#[tokio::test]
async fn test_snapshot_lists_all_sets_once() {
    let listing = format!("{V4_LISTING}{V6_LISTING} elements = {{ 2001:db8::/64 timeout 5m }}");
    let fake = fake_nft(0, &listing);
    let snap = fake
        .backend
        .snapshot("sshd")
        .await
        .expect("snapshot")
        .expect("nftables supports snapshots");
    assert_eq!(snap.len(), 6, "got: {snap:?}");
    assert!(snap.contains(&ip("2001:db8::2")));
    let calls = fake.calls();
    assert!(snap.contains(&ip("2001:db8::/64")));
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0][4], "f2b-sshd");
    assert_eq!(calls[1][4], "f2b-sshd-v6");
    assert_eq!(calls[2][4], "f2b6-sshd");
}

#[tokio::test]
async fn test_snapshot_errors_when_listing_fails() {
    let fake = fake_nft(1, "");
    let err = fake
        .backend
        .snapshot("sshd")
        .await
        .expect_err("a failed listing must not read as empty");
    assert!(
        err.to_string().contains("nft list set failed"),
        "got: {err}"
    );
}

#[test]
fn test_backend_name_is_nftables() {
    let backend = NftablesBackend::new("/bin/true".into());
    assert_eq!(backend.name(), "nftables");
    assert!(backend.can_verify());
}
