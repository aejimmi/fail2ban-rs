use super::*;

// --- journalctl supervision (restart + cursor handoff) ----------------------

const JSON_FAILURE: &str = r#"{"__CURSOR":"c%s","SYSLOG_IDENTIFIER":"sshd","_PID":"1","MESSAGE":"Failed password for root from 192.168.1.100 port 22"}"#;

/// Write a fake `journalctl` shell script. Each invocation appends its args
/// to `args.txt`, prints one failure entry with cursor `c<N>` (N = run
/// number), then runs `tail` (e.g. `exit 0` or `exec sleep 30`).
fn fake_journalctl(
    dir: &tempfile::TempDir,
    tail: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let args = dir.path().join("args.txt");
    std::fs::write(&args, "").unwrap();
    let script = dir.path().join("journalctl.sh");
    let body = format!(
        "n=$(( $(wc -l < '{a}') + 1 ))\necho \"$@\" >> '{a}'\nprintf '{j}\\n' \"$n\"\n{tail}\n",
        a = args.display(),
        j = JSON_FAILURE,
    );
    std::fs::write(&script, body).unwrap();
    (script, args)
}

/// Build a journal context that runs `/bin/sh <script>` instead of journalctl.
fn fake_ctx(script: &std::path::Path, tx: mpsc::Sender<Failure>) -> JournalCtx {
    JournalCtx {
        handoff: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        jail_id: "test".to_string(),
        journalmatch: vec!["_SYSTEMD_UNIT=sshd.service".to_string()],
        matcher: JailMatcher::new(&[r"Failed password for .* from <HOST>".to_string()]).unwrap(),
        date_parser: DateParser::new(crate::detect::date::DateFormat::Syslog).unwrap(),
        ignore_list: IgnoreList::new(&[], false).unwrap(),
        failure_tx: tx,
        program: std::ffi::OsString::from("/bin/sh"),
        prefix_args: vec![script.as_os_str().to_owned()],
    }
}

async fn recv_within(rx: &mut mpsc::Receiver<Failure>, secs: u64) -> Failure {
    tokio::time::timeout(std::time::Duration::from_secs(secs), rx.recv())
        .await
        .expect("timeout waiting for failure")
        .expect("channel closed")
}

#[tokio::test]
async fn test_supervise_restarts_after_journalctl_exits() {
    let dir = tempfile::TempDir::new().unwrap();
    let (script, args) = fake_journalctl(&dir, "exit 0");
    let (tx, mut rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let ctx = fake_ctx(&script, tx);
    let c = cancel.clone();
    let handle = tokio::spawn(async move { supervise(&ctx, None, &c).await });

    let first = recv_within(&mut rx, 3).await;
    assert_eq!(first.ip.to_string(), "192.168.1.100");
    // Restart happens after the 1s backoff.
    recv_within(&mut rx, 4).await;

    cancel.cancel();
    let cursor = handle.await.unwrap();
    assert!(cursor.is_some_and(|c| c.starts_with('c')));

    let invocations = std::fs::read_to_string(&args).unwrap();
    let mut lines = invocations.lines();
    let first = lines.next().expect("journalctl never invoked");
    let second = lines.next().expect("journalctl must be restarted");
    assert!(first.contains("--output=json") && first.contains("--lines=0"));
    assert!(first.ends_with("_SYSTEMD_UNIT=sshd.service"));
    assert!(
        second.contains("--after-cursor=c1"),
        "restart must resume after the last cursor: {second}"
    );
}

#[tokio::test]
async fn test_supervise_cancel_kills_child_and_returns_cursor() {
    let dir = tempfile::TempDir::new().unwrap();
    let (script, _args) = fake_journalctl(&dir, "exec sleep 30");
    let (tx, mut rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let ctx = fake_ctx(&script, tx);
    let c = cancel.clone();
    let handle = tokio::spawn(async move { supervise(&ctx, None, &c).await });

    recv_within(&mut rx, 3).await;
    cancel.cancel();
    let cursor = tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .expect("supervise must stop promptly on cancel")
        .unwrap();
    assert_eq!(cursor.as_deref(), Some("c1"));
}

#[tokio::test]
async fn test_supervise_starts_after_given_cursor() {
    let dir = tempfile::TempDir::new().unwrap();
    let (script, args) = fake_journalctl(&dir, "exec sleep 30");
    let (tx, mut rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let ctx = fake_ctx(&script, tx);
    let c = cancel.clone();
    let handle =
        tokio::spawn(async move { supervise(&ctx, Some("s=prev;i=9".to_string()), &c).await });

    recv_within(&mut rx, 3).await;
    cancel.cancel();
    handle.await.unwrap();
    let invocations = std::fs::read_to_string(&args).unwrap();
    assert!(invocations.contains("--after-cursor=s=prev;i=9"));
    assert!(invocations.contains("--lines=all"));
    assert!(!invocations.contains("--lines=0"));
}

#[tokio::test]
async fn test_supervise_spawn_failure_retries_until_cancel() {
    let (tx, _rx) = mpsc::channel(16);
    let mut ctx = fake_ctx(std::path::Path::new("/unused"), tx);
    ctx.program = std::ffi::OsString::from("/nonexistent/journalctl");
    ctx.prefix_args.clear();
    let cancel = CancellationToken::new();
    let c = cancel.clone();
    let handle = tokio::spawn(async move { supervise(&ctx, None, &c).await });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        !handle.is_finished(),
        "spawn failure must not end the watcher"
    );
    cancel.cancel();
    let cursor = tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .expect("supervise must stop promptly on cancel")
        .unwrap();
    assert!(cursor.is_none());
}

/// L2: a non-UTF-8 `MESSAGE` arrives as a JSON byte array (~4x its decoded
/// size). An attacker-padded message whose JSON exceeds the old 64 KiB cap
/// must still be read, decoded, truncated to `MAX_LINE_LEN`, and matched.
#[tokio::test]
async fn test_parse_entry_large_non_utf8_message_truncated_and_matched() {
    let mut msg = b"Failed password for root from 10.0.0.77 port 22 ".to_vec();
    msg.push(0xff); // invalid UTF-8 forces the byte-array encoding
    msg.resize(crate::detect::watcher::MAX_LINE_LEN + 4096, b'A');
    let bytes: Vec<String> = msg.iter().map(u8::to_string).collect();
    let json = format!(
        r#"{{"__CURSOR":"c","SYSLOG_IDENTIFIER":"sshd","_PID":"1","MESSAGE":[{}]}}"#,
        bytes.join(",")
    );
    assert!(
        json.len() > crate::detect::watcher::MAX_LINE_LEN,
        "entry must exceed the per-line cap"
    );

    let mut input = json.into_bytes();
    input.push(b'\n');
    let mut reader = BufReader::new(input.as_slice());
    let mut raw = Vec::new();
    let mut buf = String::new();
    let n = read_line_bounded(&mut reader, &mut raw, &mut buf, "test")
        .await
        .unwrap();
    assert!(
        n > 0 && !buf.is_empty(),
        "entry must not be skipped as oversized"
    );

    let entry =
        crate::detect::journal_entry::parse_entry(buf.trim_end()).expect("valid JSON entry");
    assert!(
        entry.message.len() <= crate::detect::watcher::MAX_LINE_LEN,
        "message truncated"
    );
    let matcher = crate::detect::matcher::JailMatcher::new(&[
        r"Failed password for .* from <HOST>".to_string(),
    ])
    .unwrap();
    let line = entry.lines().next().unwrap();
    let m = matcher
        .try_match(&line)
        .expect("truncated line still matches");
    assert_eq!(m.ip.to_string(), "10.0.0.77");
}
