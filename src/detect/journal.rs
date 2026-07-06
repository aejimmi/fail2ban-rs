//! Journal watcher — reads log entries from the systemd journal.
//!
//! Uses `journalctl --follow` as a subprocess to stream new journal entries.
//! Matched lines are sent as `Failure` events to the tracker.

use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::detect::date::DateParser;
use crate::detect::ignore::IgnoreList;
use crate::detect::matcher::JailMatcher;
use crate::detect::watcher::{Failure, MAX_LINE_LEN};

/// Run the journal watcher for a single jail.
///
/// Spawns `journalctl --follow --no-pager --output=short` with optional
/// match filters, reads new lines, and sends `Failure` events.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    jail_id: String,
    journalmatch: Vec<String>,
    matcher: JailMatcher,
    date_parser: DateParser,
    ignore_list: IgnoreList,
    failure_tx: mpsc::Sender<Failure>,
    cancel: CancellationToken,
    phase: &'static str,
) {
    info!(phase, jail = %jail_id, "journal watcher started");

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
                "journalctl spawn failed (install systemd-journald or switch jail to log_backend=\"file\")",
            );
            return;
        }
    };

    let Some(stdout) = child.stdout.take() else {
        error!(jail = %jail_id, "journalctl stdout unavailable");
        return;
    };

    let mut reader = BufReader::new(stdout);
    let mut line_buf = String::new();

    loop {
        line_buf.clear();
        tokio::select! {
            () = cancel.cancelled() => {
                debug!(jail = %jail_id, "journal watcher stopping");
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
                        error!(jail = %jail_id, error = %e, "journal read failed");
                        break;
                    }
                }
            }
        }
    }

    let _ = child.wait().await;
    debug!(jail = %jail_id, "journal watcher stopped");
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
                warn!(
                    jail = %jail_id,
                    limit = MAX_LINE_LEN,
                    reason = "oversized",
                    "journal line skipped"
                );
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
    warn!(
        jail = %jail_id,
        limit = MAX_LINE_LEN,
        reason = "oversized",
        "journal line skipped"
    );
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
#[path = "journal_test.rs"]
mod journal_test;
