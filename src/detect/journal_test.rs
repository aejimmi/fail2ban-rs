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
    let mut line = "x".repeat(MAX_LINE_LEN + 10);
    line.push('\n');
    let bytes = line.into_bytes();
    let mut reader = BufReader::with_capacity(MAX_LINE_LEN + 100, bytes.as_slice());
    let mut buf = String::new();

    let n = read_line_bounded(&mut reader, &mut buf, "test")
        .await
        .unwrap();

    assert_eq!(n, MAX_LINE_LEN + 11);
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
/// Sizing: with a 4 KiB `BufReader` capacity and 'x' × (MAX_LINE_LEN +
/// 8192), the line exceeds MAX_LINE_LEN several chunks before the chunk
/// containing the trailing newline, guaranteeing the no-newline +
/// over-limit branch fires.
#[tokio::test]
async fn test_read_line_bounded_skip_oversized_no_newline_in_first_chunk() {
    let mut line = "x".repeat(MAX_LINE_LEN + 8192);
    line.push('\n');
    let bytes = line.into_bytes();
    let mut reader = BufReader::with_capacity(4096, bytes.as_slice());
    let mut buf = String::new();

    let n = read_line_bounded(&mut reader, &mut buf, "test")
        .await
        .unwrap();

    // skip_oversized returns MAX_LINE_LEN + 1 as the non-zero sentinel.
    assert_eq!(n, MAX_LINE_LEN + 1);
    assert_eq!(buf, "", "oversized line must leave buf empty");
}

/// After an oversized line is skipped via the `skip_oversized` +
/// `drain_until_newline` path, the next `read_line_bounded` call must
/// cleanly return the following normal line. Proves `drain_until_newline`
/// leaves the reader positioned right after the oversized line's
/// terminating newline.
#[tokio::test]
async fn test_read_line_bounded_recovers_after_oversized_line() {
    let mut input = "x".repeat(MAX_LINE_LEN + 8192);
    input.push('\n');
    input.push_str("next\n");
    let bytes = input.into_bytes();
    let mut reader = BufReader::with_capacity(4096, bytes.as_slice());

    let mut buf = String::new();
    let n1 = read_line_bounded(&mut reader, &mut buf, "test")
        .await
        .unwrap();
    assert_eq!(n1, MAX_LINE_LEN + 1);
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
