//! Ban, unban, query, and snapshot behavior of the iptables backend.
//!
//! Split from `iptables_test.rs`, which owns the fake-binary harness.

use super::*;

use super::iptables_test::{Bin, argv, fake_backend, table};

fn ip(s: &str) -> BanTarget {
    s.parse().expect("valid ip literal")
}

fn failing() -> Bin {
    Bin {
        exit: 1,
        ..Bin::default()
    }
}

fn printing(stdout: &'static str) -> Bin {
    Bin {
        stdout,
        ..Bin::default()
    }
}

/// Realistic `iptables -L f2b-sshd -n` output with two bans.
const V4_LISTING: &str = "Chain f2b-sshd (1 references)
target     prot opt source               destination
DROP       all  --  203.0.113.5          0.0.0.0/0
DROP       all  --  198.51.100.7         0.0.0.0/0
RETURN     all  --  0.0.0.0/0            0.0.0.0/0
";

// --- parse_listing ---------------------------------------------------------

#[test]
fn test_parse_listing_collects_sources_and_skips_wildcards() {
    let got = parse_listing(V4_LISTING);
    let want: HashSet<BanTarget> = [ip("203.0.113.5"), ip("198.51.100.7")].into();
    assert_eq!(got, want);
}

#[test]
fn test_parse_listing_strips_host_prefix_suffixes() {
    let got = parse_listing("DROP all 2001:db8::9/128 ::/0\nDROP all 10.0.0.1/32 0.0.0.0/0");
    let want: HashSet<BanTarget> = [ip("2001:db8::9"), ip("10.0.0.1")].into();
    assert_eq!(got, want);
}

// --- ban / unban -----------------------------------------------------------

/// Argv of the DROP rule for `ip` in jail `sshd` under operation `op`.
fn drop_rule(op: &str, ip: &str) -> Vec<String> {
    argv(&[op, "f2b-sshd", "-s", ip, "-j", "DROP"])
}

#[tokio::test]
async fn test_ban_ipv4_only_invokes_iptables() {
    let fb = fake_backend(table(), table());
    fb.backend
        .ban(&ip("203.0.113.5"), "sshd")
        .await
        .expect("ban");
    assert_eq!(
        fb.v4(),
        vec![
            drop_rule("-C", "203.0.113.5"),
            drop_rule("-I", "203.0.113.5")
        ]
    );
    assert!(fb.v6().is_empty());
}

#[tokio::test]
async fn test_ban_ipv6_only_invokes_ip6tables() {
    let fb = fake_backend(table(), table());
    fb.backend
        .ban(&ip("2001:db8::5"), "sshd")
        .await
        .expect("ban");
    assert!(fb.v4().is_empty());
    assert_eq!(
        fb.v6(),
        vec![
            drop_rule("-C", "2001:db8::5"),
            drop_rule("-I", "2001:db8::5")
        ]
    );
}

/// C7: banning an already-banned IP (restore, reconcile, reload seeding)
/// must not stack a duplicate DROP rule.
#[tokio::test]
async fn test_ban_existing_rule_is_not_duplicated() {
    let fb = fake_backend(table(), table());
    fb.seed(&drop_rule("-I", "203.0.113.5")[1..], 1);
    fb.backend
        .ban(&ip("203.0.113.5"), "sshd")
        .await
        .expect("ban");
    assert_eq!(fb.v4(), vec![drop_rule("-C", "203.0.113.5")]);
}

/// C7: unban removes every stacked copy, so the IP is actually unblocked.
#[tokio::test]
async fn test_unban_removes_all_duplicate_rules() {
    let fb = fake_backend(table(), table());
    fb.seed(&drop_rule("-I", "198.51.100.9")[1..], 2);
    fb.backend
        .unban(&ip("198.51.100.9"), "sshd")
        .await
        .expect("unban");
    let (check, delete) = (
        drop_rule("-C", "198.51.100.9"),
        drop_rule("-D", "198.51.100.9"),
    );
    assert_eq!(
        fb.v4(),
        vec![check.clone(), delete.clone(), check.clone(), delete, check]
    );
}

#[tokio::test]
async fn test_ban_propagates_command_failure() {
    let fb = fake_backend(failing(), Bin::default());
    let err = fb
        .backend
        .ban(&ip("203.0.113.5"), "sshd")
        .await
        .expect_err("nonzero exit must surface as an error");
    assert!(err.to_string().contains("iptables exit"), "got: {err}");
}

/// Exit 4 is iptables' "resource problem" (e.g. xtables lock contention).
fn lock_contended() -> Bin {
    Bin {
        exit: 4,
        ..Bin::default()
    }
}

/// A `-C` probe failing with exit 4 must not be mistaken for "rule absent":
/// unban reports the error instead of silently leaving the DROP rule.
#[tokio::test]
async fn test_unban_lock_contention_on_probe_is_an_error() {
    let fb = fake_backend(lock_contended(), Bin::default());
    let err = fb
        .backend
        .unban(&ip("198.51.100.9"), "sshd")
        .await
        .expect_err("exit 4 on -C must not read as absent");
    assert!(err.to_string().contains("iptables exit"), "got: {err}");
    assert_eq!(fb.v4(), vec![drop_rule("-C", "198.51.100.9")], "no -D");
}

/// Exit 4 on the ban probe must not fall through to an `-I`.
#[tokio::test]
async fn test_ban_lock_contention_on_probe_is_an_error() {
    let fb = fake_backend(lock_contended(), Bin::default());
    fb.backend
        .ban(&ip("203.0.113.5"), "sshd")
        .await
        .expect_err("exit 4 on -C must surface");
    assert_eq!(fb.v4(), vec![drop_rule("-C", "203.0.113.5")], "no -I");
}

#[tokio::test]
async fn test_unban_ipv4_deletes_drop_rule() {
    let fb = fake_backend(table(), table());
    fb.seed(&drop_rule("-I", "198.51.100.9")[1..], 1);
    fb.backend
        .unban(&ip("198.51.100.9"), "sshd")
        .await
        .expect("unban");
    let (check, delete) = (
        drop_rule("-C", "198.51.100.9"),
        drop_rule("-D", "198.51.100.9"),
    );
    assert_eq!(fb.v4(), vec![check.clone(), delete, check]);
    assert!(fb.v6().is_empty());
}

#[tokio::test]
async fn test_unban_absent_rule_is_not_a_hard_error() {
    let fb = fake_backend(failing(), Bin::default());
    fb.backend
        .unban(&ip("198.51.100.9"), "sshd")
        .await
        .expect("missing rule on unban must not be fatal");
}

/// C7: a rule that is present but cannot be deleted is a real error.
#[tokio::test]
async fn test_unban_delete_failure_while_present_errors() {
    let bin = Bin {
        fail_glob: Some("\"-D \"*"),
        ..table()
    };
    let fb = fake_backend(bin, table());
    fb.seed(&drop_rule("-I", "198.51.100.9")[1..], 1);
    fb.backend
        .unban(&ip("198.51.100.9"), "sshd")
        .await
        .expect_err("an undeletable present rule must surface");
}

// --- is_banned ---------------------------------------------------------------

#[tokio::test]
async fn test_is_banned_true_when_ip_present() {
    let fb = fake_backend(printing(V4_LISTING), Bin::default());
    assert!(
        fb.backend
            .is_banned(&ip("198.51.100.7"), "sshd")
            .await
            .expect("query")
    );
    assert_eq!(fb.v4(), vec![argv(&["-L", "f2b-sshd", "-n"])]);
}

#[tokio::test]
async fn test_is_banned_false_when_ip_absent() {
    let fb = fake_backend(printing(V4_LISTING), Bin::default());
    assert!(
        !fb.backend
            .is_banned(&ip("203.0.113.6"), "sshd")
            .await
            .expect("query")
    );
}

#[tokio::test]
async fn test_is_banned_uses_ip6tables_for_ipv6() {
    let fb = fake_backend(Bin::default(), printing("DROP all 2001:db8::9 ::/0\n"));
    assert!(
        fb.backend
            .is_banned(&ip("2001:db8::9"), "sshd")
            .await
            .expect("query")
    );
}

#[tokio::test]
async fn test_is_banned_errors_when_listing_fails() {
    // A missing chain must not read as "not banned" — reconcile would then
    // re-insert DROP rules every tick.
    let fb = fake_backend(failing(), Bin::default());
    let err = fb
        .backend
        .is_banned(&ip("203.0.113.5"), "sshd")
        .await
        .expect_err("a failed listing must error");
    assert!(
        err.to_string().contains("iptables list failed"),
        "got: {err}"
    );
}

// --- snapshot ----------------------------------------------------------------

#[tokio::test]
async fn test_snapshot_unions_both_families() {
    let fb = fake_backend(
        printing(V4_LISTING),
        printing("DROP all 2001:db8::9 ::/0\n"),
    );
    let snap = fb
        .backend
        .snapshot("sshd")
        .await
        .expect("snapshot")
        .expect("iptables supports snapshots");
    let want: HashSet<BanTarget> =
        [ip("203.0.113.5"), ip("198.51.100.7"), ip("2001:db8::9")].into();
    assert_eq!(snap, want);
}

#[tokio::test]
async fn test_snapshot_errors_when_a_family_listing_fails() {
    let fb = fake_backend(printing(V4_LISTING), failing());
    fb.backend
        .snapshot("sshd")
        .await
        .expect_err("a failed listing must not read as empty");
}

#[test]
fn test_backend_name_is_iptables() {
    let backend = IptablesBackend::new("/bin/true".into(), "/bin/true".into());
    assert_eq!(backend.name(), "iptables");
    assert!(backend.can_verify());
}

#[tokio::test]
async fn test_unban_ipv6_prefix_keeps_host_rule_with_same_base_address() {
    let fb = fake_backend(
        Bin::default(),
        printing(concat!(
            "-N f2b-sshd\n",
            "-A f2b-sshd -s 2001:db8::/64 -j DROP\n",
            "-A f2b-sshd -s 2001:db8::/128 -j DROP\n",
            "-A f2b-sshd -s 2001:db8::/64 -j DROP\n",
            "-A f2b-sshd -j RETURN\n",
        )),
    );

    let target = ip("2001:db8::/64");
    fb.backend.unban(&target, "sshd").await.unwrap();
    assert_eq!(
        fb.v6(),
        [
            vec!["-S", "f2b-sshd"],
            vec!["-D", "f2b-sshd", "3"],
            vec!["-D", "f2b-sshd", "1"]
        ]
    );
}
