use super::*;

/// Tom's reproduction case from issue #7: a short line containing a
/// newline within a single `fill_buf` chunk. This is the exact path that
/// tripped the double mutable borrow in v1.2.0.
#[tokio::test]
async fn test_read_line_bounded_newline_in_single_chunk() {
    let input: &[u8] = b"hello\n";
    let mut reader = BufReader::new(input);
    let mut buf = String::new();

    let n = read_line_bounded(&mut reader, &mut buf, "test")
        .await
        .unwrap();

    assert_eq!(n, 6);
    assert_eq!(buf, "hello\n");
}

/// Two successive calls should return two lines independently.
#[tokio::test]
async fn test_read_line_bounded_two_lines() {
    let input: &[u8] = b"one\ntwo\n";
    let mut reader = BufReader::new(input);

    let mut buf = String::new();
    let n1 = read_line_bounded(&mut reader, &mut buf, "test")
        .await
        .unwrap();
    assert_eq!(n1, 4);
    assert_eq!(buf, "one\n");

    buf.clear();
    let n2 = read_line_bounded(&mut reader, &mut buf, "test")
        .await
        .unwrap();
    assert_eq!(n2, 4);
    assert_eq!(buf, "two\n");
}

/// EOF with nothing buffered returns 0 so the caller can detect end-of-stream.
#[tokio::test]
async fn test_read_line_bounded_eof_returns_zero() {
    let input: &[u8] = b"";
    let mut reader = BufReader::new(input);
    let mut buf = String::new();

    let n = read_line_bounded(&mut reader, &mut buf, "test")
        .await
        .unwrap();

    assert_eq!(n, 0);
    assert_eq!(buf, "");
}

/// Input ending without a newline still returns what was read.
#[tokio::test]
async fn test_read_line_bounded_partial_line_then_eof() {
    let input: &[u8] = b"no-newline";
    let mut reader = BufReader::new(input);
    let mut buf = String::new();

    let n = read_line_bounded(&mut reader, &mut buf, "test")
        .await
        .unwrap();

    assert_eq!(n, 10);
    assert_eq!(buf, "no-newline");
}

/// A line that spans multiple `fill_buf` chunks should still reassemble
/// correctly. Forced by a tiny `BufReader` capacity.
#[tokio::test]
async fn test_read_line_bounded_line_spans_multiple_chunks() {
    let input: &[u8] = b"helloworld\n";
    let mut reader = BufReader::with_capacity(4, input);
    let mut buf = String::new();

    let n = read_line_bounded(&mut reader, &mut buf, "test")
        .await
        .unwrap();

    assert_eq!(n, 11);
    assert_eq!(buf, "helloworld\n");
}

/// An oversized line (newline present but content over the cap) is
/// skipped: buf cleared, non-zero returned so the caller doesn't mistake
/// it for EOF.
#[tokio::test]
async fn test_read_line_bounded_oversized_line_skipped() {
    let mut line = "x".repeat(MAX_ENTRY_LEN + 10);
    line.push('\n');
    let bytes = line.into_bytes();
    let mut reader = BufReader::with_capacity(MAX_ENTRY_LEN + 100, bytes.as_slice());
    let mut buf = String::new();

    let n = read_line_bounded(&mut reader, &mut buf, "test")
        .await
        .unwrap();

    assert_eq!(n, MAX_ENTRY_LEN + 11);
    assert_eq!(buf, "", "oversized line must leave buf empty");
}

/// Invalid UTF-8 bytes must be replaced, not panic.
#[tokio::test]
async fn test_read_line_bounded_invalid_utf8_replaced() {
    let input: &[u8] = &[0xff, 0xfe, b'\n'];
    let mut reader = BufReader::new(input);
    let mut buf = String::new();

    let n = read_line_bounded(&mut reader, &mut buf, "test")
        .await
        .unwrap();

    assert_eq!(n, 3);
    assert!(buf.ends_with('\n'));
    // The two invalid bytes decode to the U+FFFD replacement character.
    assert!(buf.contains('\u{FFFD}'));
}

/// An oversized line whose first chunks contain NO newline forces the
/// `skip_oversized` branch — distinct from the in-chunk oversized branch.
/// This exercises `skip_oversized` and `drain_until_newline`, neither of
/// which are reached by the watcher.rs tests (which test the sync file
/// path, not the async journal path).
///
/// Sizing: with a 4 KiB `BufReader` capacity and 'x' × (MAX_ENTRY_LEN +
/// 8192), the line exceeds MAX_ENTRY_LEN several chunks before the chunk
/// containing the trailing newline, guaranteeing the no-newline +
/// over-limit branch fires.
#[tokio::test]
async fn test_read_line_bounded_skip_oversized_no_newline_in_first_chunk() {
    let mut line = "x".repeat(MAX_ENTRY_LEN + 8192);
    line.push('\n');
    let bytes = line.into_bytes();
    let mut reader = BufReader::with_capacity(4096, bytes.as_slice());
    let mut buf = String::new();

    let n = read_line_bounded(&mut reader, &mut buf, "test")
        .await
        .unwrap();

    // skip_oversized returns MAX_ENTRY_LEN + 1 as the non-zero sentinel.
    assert_eq!(n, MAX_ENTRY_LEN + 1);
    assert_eq!(buf, "", "oversized line must leave buf empty");
}

/// After an oversized line is skipped via the `skip_oversized` +
/// `drain_until_newline` path, the next `read_line_bounded` call must
/// cleanly return the following normal line. Proves `drain_until_newline`
/// leaves the reader positioned right after the oversized line's
/// terminating newline.
#[tokio::test]
async fn test_read_line_bounded_recovers_after_oversized_line() {
    let mut input = "x".repeat(MAX_ENTRY_LEN + 8192);
    input.push('\n');
    input.push_str("next\n");
    let bytes = input.into_bytes();
    let mut reader = BufReader::with_capacity(4096, bytes.as_slice());

    let mut buf = String::new();
    let n1 = read_line_bounded(&mut reader, &mut buf, "test")
        .await
        .unwrap();
    assert_eq!(n1, MAX_ENTRY_LEN + 1);
    assert_eq!(buf, "");

    buf.clear();
    let n2 = read_line_bounded(&mut reader, &mut buf, "test")
        .await
        .unwrap();
    assert_eq!(n2, 5);
    assert_eq!(buf, "next\n");
}

/// An empty line (`"\n"`) is valid input — `pos = 0`, `to_take = 1`.
#[tokio::test]
async fn test_read_line_bounded_empty_line() {
    let input: &[u8] = b"\n";
    let mut reader = BufReader::new(input);
    let mut buf = String::new();

    let n = read_line_bounded(&mut reader, &mut buf, "test")
        .await
        .unwrap();

    assert_eq!(n, 1);
    assert_eq!(buf, "\n");
}

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
    let mut buf = String::new();
    let n = read_line_bounded(&mut reader, &mut buf, "test")
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
