//! Journal watcher — reads log entries from the systemd journal.
//!
//! Uses `journalctl --follow` as a subprocess to stream new journal entries.
//! Matched lines are sent as `Failure` events to the tracker.

use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::detect::date::DateParser;
use crate::detect::ignore::IgnoreList;
use crate::detect::matcher::JailMatcher;
use crate::detect::watcher::{Failure, MAX_LINE_LEN};

/// Run the journal watcher for a single jail.
///
/// Spawns `journalctl --follow --no-pager --output=short` with optional
/// match filters, reads new lines, and sends `Failure` events.
pub async fn run(
    jail_id: String,
    journalmatch: Vec<String>,
    matcher: JailMatcher,
    date_parser: DateParser,
    ignore_list: IgnoreList,
    failure_tx: mpsc::Sender<Failure>,
    cancel: CancellationToken,
) {
    info!(jail = %jail_id, "journal watcher started");

    let mut cmd = Command::new("journalctl");
    cmd.arg("--follow")
        .arg("--no-pager")
        .arg("--output=short")
        .arg("--lines=0"); // Start from current position, no backlog.

    for m in &journalmatch {
        cmd.arg(m);
    }

    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::null());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            error!(
                jail = %jail_id,
                error = %e,
                "jail configured with log_backend = \"systemd\" but journalctl is not available on this system — install systemd-journald, or switch this jail to log_backend = \"file\" with a log_path",
            );
            return;
        }
    };

    let Some(stdout) = child.stdout.take() else {
        error!(jail = %jail_id, "journalctl stdout not available");
        return;
    };

    let mut reader = BufReader::new(stdout);
    let mut line_buf = String::new();

    loop {
        line_buf.clear();
        tokio::select! {
            () = cancel.cancelled() => {
                info!(jail = %jail_id, "journal watcher shutting down");
                let _ = child.kill().await;
                break;
            }

            result = read_line_bounded(&mut reader, &mut line_buf, &jail_id) => {
                match result {
                    Ok(0) => {
                        warn!(jail = %jail_id, "journalctl stream ended");
                        break;
                    }
                    Ok(_) => {
                        let text = line_buf.trim_end();
                        if text.is_empty() {
                            continue;
                        }
                        process_line(
                            text,
                            &jail_id,
                            &matcher,
                            &date_parser,
                            &ignore_list,
                            &failure_tx,
                        ).await;
                    }
                    Err(e) => {
                        error!(jail = %jail_id, error = %e, "error reading journal");
                        break;
                    }
                }
            }
        }
    }

    let _ = child.wait().await;
    info!(jail = %jail_id, "journal watcher stopped");
}

async fn process_line(
    line: &str,
    jail_id: &str,
    matcher: &JailMatcher,
    date_parser: &DateParser,
    ignore_list: &IgnoreList,
    failure_tx: &mpsc::Sender<Failure>,
) {
    let Some(match_result) = matcher.try_match(line) else {
        return;
    };

    if ignore_list.is_ignored(&match_result.ip) {
        return;
    }

    let timestamp = date_parser
        .parse_line(line)
        .unwrap_or_else(|| chrono::Utc::now().timestamp());

    let failure = Failure {
        ip: match_result.ip,
        jail_id: jail_id.to_string(),
        timestamp,
    };

    if failure_tx.send(failure).await.is_err() {
        warn!(jail = %jail_id, "failure channel closed");
    }
}

/// Read a single line from the async reader, bounded by [`MAX_LINE_LEN`].
///
/// Uses `fill_buf` / `consume` to accumulate bytes into `buf` up to the
/// limit. If the line exceeds [`MAX_LINE_LEN`], logs a warning, drains
/// remaining bytes to the next newline, clears `buf`, and returns a
/// non-zero byte count so the caller can distinguish it from EOF (0).
async fn read_line_bounded<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut String,
    jail_id: &str,
) -> std::io::Result<usize> {
    let mut total = 0usize;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(total); // EOF — 0 if nothing was buffered
        }
        if let Some(pos) = memchr_newline(available) {
            let to_take = pos + 1; // include the newline
            let new_total = total + to_take;
            if new_total > MAX_LINE_LEN {
                warn!(jail = %jail_id, "skipping oversized journal line (>{MAX_LINE_LEN} bytes)");
                buf.clear();
            } else if let Some(slice) = available.get(..to_take) {
                append_valid_utf8(buf, slice);
            }
            reader.consume(to_take);
            return Ok(new_total);
        }
        // No newline found in this chunk.
        let chunk_len = available.len();
        if total + chunk_len > MAX_LINE_LEN {
            return skip_oversized(reader, buf, chunk_len, jail_id).await;
        }
        append_valid_utf8(buf, available);
        reader.consume(chunk_len);
        total += chunk_len;
    }
}

/// Skip an oversized line: consume the current chunk and drain to the next newline.
async fn skip_oversized<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut String,
    chunk_len: usize,
    jail_id: &str,
) -> std::io::Result<usize> {
    warn!(jail = %jail_id, "skipping oversized journal line (>{MAX_LINE_LEN} bytes)");
    reader.consume(chunk_len);
    buf.clear();
    drain_until_newline(reader).await?;
    // Return non-zero so caller knows this is not EOF.
    Ok(MAX_LINE_LEN + 1)
}

/// Discard bytes from the reader until a newline or EOF is reached.
async fn drain_until_newline<R: AsyncBufRead + Unpin>(reader: &mut R) -> std::io::Result<()> {
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            break; // EOF
        }
        if let Some(pos) = memchr_newline(available) {
            reader.consume(pos + 1);
            break;
        }
        let len = available.len();
        reader.consume(len);
    }
    Ok(())
}

/// Find the position of the first newline byte in a slice.
fn memchr_newline(buf: &[u8]) -> Option<usize> {
    buf.iter().position(|&b| b == b'\n')
}

/// Append bytes to a `String`, replacing invalid UTF-8 sequences.
fn append_valid_utf8(buf: &mut String, bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    buf.push_str(&text);
}

#[cfg(test)]
mod tests {
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
}
