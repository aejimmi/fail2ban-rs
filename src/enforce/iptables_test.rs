//! Fake-binary harness plus the iptables backend's `init` and `teardown`.
//! The harness is shared with `iptables_ops_test.rs`.

use super::*;

use crate::enforce::cmd::MAX_RULE_DELETES;
use crate::enforce::fake_bin_test_support::{
    install_script, logging_prelude, read_xtables_invocations, rule_table_body, seed_rule,
};

/// Shell glob matching every `-C` probe — makes the fake behave like a host
/// where no fail2ban-rs rule exists yet.
pub(super) const NO_RULES: &str = "\"-C \"*";

/// Behavior of one fake `iptables`/`ip6tables` binary.
/// The default succeeds silently for every invocation.
#[derive(Clone, Copy, Default)]
pub(super) struct Bin {
    /// Exit code for invocations not matched by `fail_glob`.
    pub(super) exit: i32,
    /// Text printed on stdout.
    pub(super) stdout: &'static str,
    /// Shell glob over the space-joined argv; matches exit 1.
    pub(super) fail_glob: Option<&'static str>,
    /// Emulate a stateful rule table (see [`rule_table_body`]).
    pub(super) table: bool,
}

/// A fresh host: every `-C` probe fails, everything else succeeds.
pub(super) fn fresh() -> Bin {
    Bin {
        fail_glob: Some(NO_RULES),
        ..Bin::default()
    }
}

/// A host with a stateful rule table that starts empty.
pub(super) fn table() -> Bin {
    Bin {
        table: true,
        ..Bin::default()
    }
}

/// Write one fake binary behaving per `bin`.
fn write_bin(path: &std::path::Path, log: &std::path::Path, bin: Bin) {
    let fail = bin
        .fail_glob
        .map(|g| format!("case \"$*\" in\n  {g}) exit 1 ;;\nesac\n"))
        .unwrap_or_default();
    let rules = if bin.table {
        rule_table_body(log)
    } else {
        String::new()
    };
    let script = format!(
        "{}{fail}{rules}printf '%s' \"{}\"\nexit {}\n",
        logging_prelude(log),
        bin.stdout,
        bin.exit
    );
    install_script(path, &script);
}

/// A pair of fake `iptables`/`ip6tables` binaries plus their invocation logs.
pub(super) struct FakeBackend {
    pub(super) backend: IptablesBackend,
    v4_bin: std::path::PathBuf,
    v6_bin: std::path::PathBuf,
    v4_log: std::path::PathBuf,
    v6_log: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

impl FakeBackend {
    /// Argv of every `iptables` invocation, in order.
    pub(super) fn v4(&self) -> Vec<Vec<String>> {
        read_xtables_invocations(&self.v4_log)
    }

    /// Argv of every `ip6tables` invocation, in order.
    pub(super) fn v6(&self) -> Vec<Vec<String>> {
        read_xtables_invocations(&self.v6_log)
    }

    /// Seed `copies` of rule `args` into both families' rule tables.
    pub(super) fn seed(&self, args: &[String], copies: u32) {
        seed_rule(&self.v4_bin, &self.v4_log, args, copies);
        seed_rule(&self.v6_bin, &self.v6_log, args, copies);
    }
}

/// Build a backend wired to two fake binaries.
pub(super) fn fake_backend(v4: Bin, v6: Bin) -> FakeBackend {
    let dir = tempfile::tempdir().expect("tempdir");
    let iptables_path = dir.path().join("iptables");
    let ip6tables_path = dir.path().join("ip6tables");
    let v4_log = dir.path().join("iptables.log");
    let v6_log = dir.path().join("ip6tables.log");
    write_bin(&iptables_path, &v4_log, v4);
    write_bin(&ip6tables_path, &v6_log, v6);
    FakeBackend {
        backend: IptablesBackend::new(iptables_path.clone(), ip6tables_path.clone()),
        v4_bin: iptables_path,
        v6_bin: ip6tables_path,
        v4_log,
        v6_log,
        _dir: dir,
    }
}

/// Convert string literals to an owned argv.
pub(super) fn argv(args: &[&str]) -> Vec<String> {
    args.iter().map(ToString::to_string).collect()
}

fn ports(list: &[&str]) -> Vec<String> {
    argv(list)
}

// --- helpers ------------------------------------------------------------

#[test]
fn test_jump_args_insert_and_delete_differ_only_by_flag() {
    let spec = RuleSpec {
        ports: ports(&["22", "80"]),
        protocol: "tcp".into(),
    };
    let mut delete = jump_args("-D", "f2b-sshd", &spec);
    assert_eq!(delete[0], "-D");
    delete[0] = "-I".into();
    assert_eq!(jump_args("-I", "f2b-sshd", &spec), delete);
}

// --- init ---------------------------------------------------------------

#[tokio::test]
async fn test_init_with_ports_inserts_multiport_jump_on_fresh_host() {
    let fb = fake_backend(fresh(), fresh());
    fb.backend
        .init("sshd", &ports(&["22", "80"]), "tcp")
        .await
        .expect("init");

    let jump = argv(&[
        "INPUT",
        "-p",
        "tcp",
        "-m",
        "multiport",
        "--dports",
        "22,80",
        "-j",
        "f2b-sshd",
    ]);
    for calls in [fb.v4(), fb.v6()] {
        let mut check = vec!["-C".to_string()];
        check.extend(jump.clone());
        let mut insert = vec!["-I".to_string()];
        insert.extend(jump.clone());
        assert_eq!(
            calls,
            vec![
                argv(&["-N", "f2b-sshd"]),
                argv(&["-C", "f2b-sshd", "-j", "RETURN"]),
                argv(&["-A", "f2b-sshd", "-j", "RETURN"]),
                check,
                insert,
            ]
        );
    }
}

#[tokio::test]
async fn test_init_without_ports_inserts_plain_jump() {
    let fb = fake_backend(fresh(), fresh());
    fb.backend.init("nginx", &[], "tcp").await.expect("init");
    for calls in [fb.v4(), fb.v6()] {
        assert_eq!(calls[4], argv(&["-I", "INPUT", "-j", "f2b-nginx"]));
    }
}

#[tokio::test]
async fn test_init_skips_insert_when_rules_already_exist() {
    // `-C` succeeds for every rule: re-init must not stack duplicates.
    let fb = fake_backend(Bin::default(), Bin::default());
    fb.backend.init("sshd", &[], "tcp").await.expect("init");
    for calls in [fb.v4(), fb.v6()] {
        assert_eq!(calls.len(), 3, "only -N and two -C probes: {calls:?}");
        assert!(calls.iter().all(|c| c[0] != "-I" && c[0] != "-A"));
    }
}

#[tokio::test]
async fn test_init_fails_and_cleans_up_when_ipv4_jump_insert_fails() {
    let v4 = Bin {
        fail_glob: Some("\"-C \"*|\"-I INPUT\"*"),
        ..Bin::default()
    };
    let fb = fake_backend(v4, fresh());
    let err = fb
        .backend
        .init("sshd", &[], "tcp")
        .await
        .expect_err("an ineffective IPv4 jail must fail init (#21)");
    assert!(err.to_string().contains("iptables exit"), "got: {err}");

    let calls = fb.v4();
    let n = calls.len();
    assert_eq!(calls[n - 2], argv(&["-F", "f2b-sshd"]));
    assert_eq!(calls[n - 1], argv(&["-X", "f2b-sshd"]));
    assert!(
        fb.v6().is_empty(),
        "IPv6 must not be touched after v4 fails"
    );
}

#[tokio::test]
async fn test_init_tolerates_ipv6_jump_insert_failure() {
    let v6 = Bin {
        fail_glob: Some("\"-C \"*|\"-I INPUT\"*"),
        ..Bin::default()
    };
    let fb = fake_backend(fresh(), v6);
    fb.backend
        .init("sshd", &[], "tcp")
        .await
        .expect("a host without IPv6 must still start");
    assert_eq!(fb.v4()[4], argv(&["-I", "INPUT", "-j", "f2b-sshd"]));
    assert!(
        fb.v6().iter().all(|c| c[0] != "-F"),
        "IPv6 failure must not clean up"
    );
    let ip6 = "2606:4700::1".parse().unwrap();
    fb.backend.ban(&ip6, "sshd").await.unwrap();
    assert!(!fb.backend.reportable(ip6));
    assert!(fb.backend.reportable("8.8.8.8".parse().unwrap()));
}

#[tokio::test]
async fn test_init_fails_when_every_command_fails() {
    let failing = Bin {
        exit: 1,
        ..Bin::default()
    };
    let fb = fake_backend(failing, failing);
    fb.backend
        .init("sshd", &[], "tcp")
        .await
        .expect_err("init must not report success with no jump rule");
}

#[tokio::test]
async fn test_init_with_changed_ports_removes_the_old_jump() {
    let fb = fake_backend(table(), table());
    fb.backend
        .init("sshd", &ports(&["22"]), "tcp")
        .await
        .expect("init");
    fb.backend
        .init("sshd", &ports(&["2222"]), "tcp")
        .await
        .expect("re-init");

    let old = argv(&[
        "-D",
        "INPUT",
        "-p",
        "tcp",
        "-m",
        "multiport",
        "--dports",
        "22",
        "-j",
        "f2b-sshd",
    ]);
    for calls in [fb.v4(), fb.v6()] {
        assert!(calls.contains(&old), "old jump must be deleted: {calls:?}");
    }
}

#[tokio::test]
async fn test_init_errors_when_binaries_are_missing() {
    let backend = IptablesBackend::new(
        "/nonexistent/iptables-for-tests-xyz".into(),
        "/nonexistent/ip6tables-for-tests-xyz".into(),
    );
    let err = backend
        .init("sshd", &[], "tcp")
        .await
        .expect_err("missing binary must fail");
    assert!(
        err.to_string().contains("iptables command failed"),
        "got: {err}"
    );
}

// --- teardown -------------------------------------------------------------

#[tokio::test]
async fn test_teardown_deletes_exactly_the_jump_init_inserted() {
    let fb = fake_backend(table(), table());
    fb.backend
        .init("sshd", &ports(&["22", "80"]), "tcp")
        .await
        .expect("init");
    fb.backend.teardown("sshd").await.expect("teardown");

    let jump = |flag: &str| {
        argv(&[
            flag,
            "INPUT",
            "-p",
            "tcp",
            "-m",
            "multiport",
            "--dports",
            "22,80",
            "-j",
            "f2b-sshd",
        ])
    };
    for calls in [fb.v4(), fb.v6()] {
        assert_eq!(calls[4], jump("-I"));
        assert_eq!(
            calls[5..],
            [
                jump("-C"),
                jump("-D"),
                jump("-C"),
                argv(&["-F", "f2b-sshd"]),
                argv(&["-X", "f2b-sshd"]),
            ]
        );
    }
}

#[tokio::test]
async fn test_teardown_without_init_uses_the_portless_jump() {
    let fb = fake_backend(table(), table());
    fb.seed(&argv(&["INPUT", "-j", "f2b-sshd"]), 1);
    fb.backend.teardown("sshd").await.expect("teardown");
    for calls in [fb.v4(), fb.v6()] {
        assert_eq!(
            calls,
            vec![
                argv(&["-C", "INPUT", "-j", "f2b-sshd"]),
                argv(&["-D", "INPUT", "-j", "f2b-sshd"]),
                argv(&["-C", "INPUT", "-j", "f2b-sshd"]),
                argv(&["-F", "f2b-sshd"]),
                argv(&["-X", "f2b-sshd"]),
            ]
        );
    }
}

#[tokio::test]
async fn test_teardown_ignores_failures_on_every_step() {
    let failing = Bin {
        exit: 1,
        ..Bin::default()
    };
    let fb = fake_backend(failing, failing);
    fb.backend
        .teardown("sshd")
        .await
        .expect("teardown must swallow per-command failures");
    assert_eq!(fb.v4().len(), 3);
    assert_eq!(fb.v6().len(), 3);
}

/// Older releases could stack duplicate INPUT jumps; teardown removes every
/// copy, not just one.
#[tokio::test]
async fn test_teardown_removes_every_duplicate_jump() {
    let fb = fake_backend(table(), table());
    fb.seed(&argv(&["INPUT", "-j", "f2b-sshd"]), 3);
    fb.backend.teardown("sshd").await.expect("teardown");
    for calls in [fb.v4(), fb.v6()] {
        let deletes = calls.iter().filter(|c| c[0] == "-D").count();
        assert_eq!(deletes, 3, "all three copies deleted: {calls:?}");
        assert_eq!(calls[6], argv(&["-C", "INPUT", "-j", "f2b-sshd"]));
    }
}

/// A `-C` that always matches (a broken or lying binary) cannot make
/// teardown loop forever.
#[tokio::test]
async fn test_teardown_duplicate_removal_is_bounded() {
    let fb = fake_backend(Bin::default(), Bin::default());
    fb.backend.teardown("sshd").await.expect("teardown");
    for calls in [fb.v4(), fb.v6()] {
        let deletes = calls.iter().filter(|c| c[0] == "-D").count();
        assert_eq!(deletes, MAX_RULE_DELETES);
    }
}
