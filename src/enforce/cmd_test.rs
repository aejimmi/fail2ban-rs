use super::*;

use std::time::Instant;

#[tokio::test]
async fn test_run_success_returns_ok() {
    run("sh", "sh", &["-c", "exit 0"]).await.expect("exit 0");
}

#[tokio::test]
async fn test_run_nonzero_exit_carries_label_and_stderr() {
    let err = run("sh", "fake", &["-c", "echo boom >&2; exit 3"])
        .await
        .expect_err("nonzero exit must error");
    let msg = err.to_string();
    assert!(msg.contains("fake exit"), "got: {msg}");
    assert!(msg.contains("boom"), "got: {msg}");
}

#[tokio::test]
async fn test_output_returns_nonzero_exit_without_error() {
    let out = output("sh", "sh", &["-c", "printf hi; exit 1"])
        .await
        .expect("nonzero exit is not a spawn error");
    assert!(!out.status.success());
    assert_eq!(out.stdout, b"hi");
}

#[tokio::test]
async fn test_output_missing_binary_is_command_failed() {
    let err = output("/nonexistent/bin-for-tests-xyz", "ghost", &["x"])
        .await
        .expect_err("missing binary must error");
    assert!(
        err.to_string().contains("ghost command failed"),
        "got: {err}"
    );
}

#[tokio::test]
async fn test_output_with_timeout_kills_hung_command() {
    let start = Instant::now();
    let err = output_with_timeout(
        "sh",
        "hang",
        &["-c", "sleep 30"],
        Duration::from_millis(200),
    )
    .await
    .expect_err("hung command must time out");
    assert!(
        err.to_string().contains("hang command timed out"),
        "got: {err}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "timeout must not wait for the child"
    );
}

#[test]
fn test_command_timeout_is_thirty_seconds() {
    assert_eq!(COMMAND_TIMEOUT, Duration::from_secs(30));
}

/// Whether `pid` still names a live (non-reaped) process.
fn alive(pid: i32) -> bool {
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok()
}

/// L5: a script that backgrounds a grandchild holding stdout and exits must
/// not keep the call waiting past the timeout, and the grandchild must be
/// killed with the rest of the process group.
#[tokio::test]
async fn test_output_with_timeout_kills_background_grandchild() {
    let dir = tempfile::TempDir::new().unwrap();
    let pid_file = dir.path().join("pid");
    let script = format!("sleep 60 & echo $! > '{}'; exit 0", pid_file.display());
    let start = Instant::now();
    let err = output_with_timeout(
        "sh",
        "bg",
        &["-c", script.as_str()],
        Duration::from_millis(300),
    )
    .await
    .expect_err("grandchild holding stdout must hit the timeout");
    assert!(
        err.to_string().contains("bg command timed out"),
        "got: {err}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "must return promptly"
    );

    let pid: i32 = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // The orphaned sleep is reaped by init/launchd shortly after the kill.
    let deadline = Instant::now() + Duration::from_secs(5);
    while alive(pid) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!alive(pid), "background sleep {pid} must be killed");
}

/// Fake `iptables` that logs argv to `log` and exits `check_exit` for `-C`
/// probes (after the leading `-w`) and 0 otherwise.
fn fake_xtables(
    dir: &tempfile::TempDir,
    check_exit: i32,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let bin = dir.path().join("iptables");
    let log = dir.path().join("log");
    let body = format!("case \"$1\" in\n  -C) exit {check_exit} ;;\nesac\nexit 0\n");
    crate::enforce::fake_bin_test_support::install_script(
        &bin,
        &format!(
            "{}{body}",
            crate::enforce::fake_bin_test_support::logging_prelude(&log)
        ),
    );
    (bin, log)
}

/// Argv of every fake invocation, asserting each leads with `-w`.
fn calls(log: &std::path::Path) -> Vec<Vec<String>> {
    crate::enforce::fake_bin_test_support::read_xtables_invocations(log)
}

#[tokio::test]
async fn test_rule_present_exit_codes() {
    for (code, want) in [(0, Some(true)), (1, Some(false)), (2, None), (4, None)] {
        let dir = tempfile::TempDir::new().unwrap();
        let (bin, _log) = fake_xtables(&dir, code);
        let got = rule_present(&bin, "iptables", &["-C", "X"]).await.ok();
        assert_eq!(got, want, "exit {code}");
    }
}

#[tokio::test]
async fn test_ensure_rule_absent_probe_adds_rule() {
    let dir = tempfile::TempDir::new().unwrap();
    let (bin, log) = fake_xtables(&dir, RULE_ABSENT_EXIT);
    ensure_rule(&bin, "iptables", &["-C", "X"], &["-I", "X"])
        .await
        .expect("exit 1 means absent: add");
    assert_eq!(calls(&log), vec![vec!["-C", "X"], vec!["-I", "X"]]);
}

#[tokio::test]
async fn test_ensure_rule_lock_contention_is_error_without_add() {
    let dir = tempfile::TempDir::new().unwrap();
    let (bin, log) = fake_xtables(&dir, 4);
    let err = ensure_rule(&bin, "iptables", &["-C", "X"], &["-I", "X"])
        .await
        .expect_err("exit 4 on -C must be an error");
    assert!(err.to_string().contains("iptables exit"), "got: {err}");
    assert_eq!(calls(&log), vec![vec!["-C", "X"]]);
}

#[tokio::test]
async fn test_delete_all_rules_absent_probe_deletes_nothing() {
    let dir = tempfile::TempDir::new().unwrap();
    let (bin, log) = fake_xtables(&dir, RULE_ABSENT_EXIT);
    let n = delete_all_rules(&bin, "iptables", &["-C", "X"], &["-D", "X"])
        .await
        .expect("absent rule is not an error");
    assert_eq!(n, 0);
    assert_eq!(calls(&log), vec![vec!["-C", "X"]]);
}

#[tokio::test]
async fn test_delete_all_rules_lock_contention_is_error() {
    let dir = tempfile::TempDir::new().unwrap();
    let (bin, log) = fake_xtables(&dir, 4);
    let err = delete_all_rules(&bin, "iptables", &["-C", "X"], &["-D", "X"])
        .await
        .expect_err("exit 4 on -C must not read as absent");
    assert!(err.to_string().contains("iptables exit"), "got: {err}");
    assert_eq!(calls(&log), vec![vec!["-C", "X"]]);
}

#[tokio::test]
async fn test_xtables_run_and_output_prepend_wait_flag() {
    let dir = tempfile::TempDir::new().unwrap();
    let (bin, log) = fake_xtables(&dir, 0);
    xtables_run(&bin, "iptables", &["-N", "c"])
        .await
        .expect("run");
    let out = xtables_output(&bin, "iptables", &["-L", "c"])
        .await
        .expect("output");
    assert!(out.status.success());
    assert_eq!(calls(&log), vec![vec!["-N", "c"], vec!["-L", "c"]]);
}

#[tokio::test]
async fn test_bounded_capture_preserves_exact_limit_and_rejects_next_byte() {
    let data = vec![b'x'; 32];
    let bytes = read_bounded(Some(data.as_slice()), 32, false, "probe", "stdout")
        .await
        .expect("exact bound");
    assert_eq!(bytes, data);
    let too_large = vec![b'x'; 33];
    let error = read_bounded(Some(too_large.as_slice()), 32, false, "probe", "stdout")
        .await
        .expect_err("overflow must not be a truncated listing");
    assert!(
        error
            .to_string()
            .contains("stdout exceeds 32 byte output limit")
    );
}

#[tokio::test]
async fn test_stderr_truncates_but_drains_to_eof() {
    let data = vec![b'x'; 1024 * 1024];
    let bytes = read_bounded(Some(data.as_slice()), 64, true, "probe", "stderr")
        .await
        .expect("large diagnostics are drained");
    assert_eq!(bytes.len(), 64);
    assert!(bytes.ends_with(TRUNCATED));
    assert!(bytes.starts_with(b"xxx"));
}

#[tokio::test]
async fn test_run_discards_large_stdout_and_bounds_stderr_without_deadlock() {
    let out = execute(
        "sh",
        "noisy",
        &[
            "-c",
            "head -c 262144 /dev/zero >&2 & head -c 33554432 /dev/zero; wait",
        ],
        Duration::from_secs(5),
        false,
    )
    .await
    .expect("both pipes must finish");
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
    assert_eq!(out.stderr.len(), MAX_STDERR_BYTES);
    assert!(out.stderr.ends_with(TRUNCATED));
}

#[tokio::test]
async fn test_output_overflow_kills_command_instead_of_returning_partial_listing() {
    let start = Instant::now();
    let error = output_with_timeout(
        "sh",
        "listing",
        &["-c", "head -c 16777217 /dev/zero; sleep 60"],
        Duration::from_secs(5),
    )
    .await
    .expect_err("oversized listing must fail");
    assert!(
        error
            .to_string()
            .contains("stdout exceeds 16777216 byte output limit"),
        "{error}"
    );
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn test_discarded_stdout_still_times_out_and_kills_background_writer() {
    let dir = tempfile::TempDir::new().unwrap();
    let pid_file = dir.path().join("pid");
    let script = format!("sleep 60 2>/dev/null & echo $! > '{}'", pid_file.display());
    let error = execute(
        "sh",
        "background",
        &["-c", &script],
        Duration::from_millis(200),
        false,
    )
    .await
    .expect_err("discarding bytes must still drain the stdout pipe");
    assert!(error.to_string().contains("timed out"));
    let pid: i32 = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while alive(pid) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!alive(pid), "background process {pid} must be killed");
}
