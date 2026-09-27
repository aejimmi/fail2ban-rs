//! D2: the resume cursor is dropped only when `journalctl` rejects it.

use super::*;

use std::time::Duration;

/// Run `supervise` from `stale-cursor` against a fake journalctl whose body
/// is `body` (argv is logged to `args.txt` first). Returns the final cursor
/// and the logged invocations.
async fn run_fake(body: &str) -> (Option<String>, Vec<String>) {
    let dir = tempfile::TempDir::new().unwrap();
    let args = dir.path().join("args.txt");
    let script = dir.path().join("journalctl.sh");
    std::fs::write(
        &script,
        format!("echo \"$@\" >> '{}'\n{body}\n", args.display()),
    )
    .unwrap();
    let (tx, _rx) = mpsc::channel(16);
    let ctx = JournalCtx {
        handoff: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        jail_id: "test".to_string(),
        journalmatch: Vec::new(),
        matcher: JailMatcher::new(&[r"Failed password for .* from <HOST>".to_string()]).unwrap(),
        date_parser: DateParser::new(crate::detect::date::DateFormat::Syslog).unwrap(),
        ignore_list: IgnoreList::new(&[], false).unwrap(),
        failure_tx: tx,
        program: OsString::from("/bin/sh"),
        prefix_args: vec![script.as_os_str().to_owned()],
    };
    let cancel = CancellationToken::new();
    let c = cancel.clone();
    let handle =
        tokio::spawn(async move { supervise(&ctx, Some("stale-cursor".to_string()), &c).await });
    // First session + 1s backoff + second session.
    tokio::time::sleep(Duration::from_millis(1800)).await;
    cancel.cancel();
    let cursor = tokio::time::timeout(Duration::from_secs(3), handle)
        .await
        .expect("supervise must stop promptly on cancel")
        .unwrap();
    let logged = std::fs::read_to_string(&args).unwrap_or_default();
    (cursor, logged.lines().map(str::to_string).collect())
}

fn assert_restarted_at_tail(calls: &[String]) {
    let first = calls.first().expect("journalctl never invoked");
    assert!(first.contains("--after-cursor=stale-cursor"));
    let second = calls.get(1).expect("journalctl must be restarted");
    assert!(
        !second.contains("--after-cursor"),
        "cursor reused: {second}"
    );
    assert!(second.contains("--lines=0"));
}

#[tokio::test]
async fn test_supervise_drops_cursor_when_stderr_reports_seek_failure() {
    let (cursor, calls) =
        run_fake("echo 'Failed to seek to cursor: Invalid argument' >&2\nexit 0").await;
    assert!(cursor.is_none());
    assert_restarted_at_tail(&calls);
}

#[tokio::test]
async fn test_supervise_drops_cursor_on_fast_nonzero_exit() {
    let (cursor, calls) = run_fake("exit 1").await;
    assert!(cursor.is_none());
    assert_restarted_at_tail(&calls);
}

/// A quiet session that ends cleanly must keep its cursor: restarting at
/// the tail would silently lose entries logged in between.
#[tokio::test]
async fn test_supervise_keeps_cursor_after_quiet_clean_exit() {
    let (cursor, calls) = run_fake("exit 0").await;
    assert_eq!(cursor.as_deref(), Some("stale-cursor"));
    let second = calls.get(1).expect("journalctl must be restarted");
    assert!(second.contains("--after-cursor=stale-cursor"), "{second}");
    assert!(second.contains("--lines=all"));
}
