//! Blocking log-file read loop.
//!
//! Runs on a dedicated `spawn_blocking` thread. Tails a log file, decodes
//! bounded lines (skipping oversized ones), detects rotation via
//! [`FileIdentity`], and forwards matched [`Failure`] events. All state is
//! bundled in [`ReadCtx`] so the steady-state and rotation-drain paths share
//! line-processing logic.

use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::detect::date::DateParser;
use crate::detect::identity::FileIdentity;
use crate::detect::ignore::IgnoreList;
use crate::detect::matcher::JailMatcher;
use crate::detect::watcher::{Failure, MAX_LINE_LEN};

/// Shared, move-by-value state for a blocking read loop.
///
/// Bundles the per-jail matching machinery so line-processing logic is shared
/// between the steady-state reader and the rotation drain path without a long
/// argument list.
struct ReadCtx {
    jail_id: String,
    matcher: JailMatcher,
    date_parser: DateParser,
    ignore_list: IgnoreList,
    tx: mpsc::Sender<Failure>,
}

impl ReadCtx {
    /// Match, filter and forward one already-trimmed line.
    ///
    /// Returns `false` only when the downstream channel is closed and the
    /// loop should stop.
    fn handle_line(&self, line: &str) -> bool {
        let Some(m) = self.matcher.try_match(line) else {
            return true;
        };
        if self.ignore_list.is_ignored(&m.ip) {
            debug!(
                ip = %m.ip,
                jail = %self.jail_id,
                reason = "allowlist",
                "failure ignored"
            );
            return true;
        }
        let timestamp = self
            .date_parser
            .parse_line(line)
            .unwrap_or_else(|| chrono::Utc::now().timestamp());
        let failure = Failure {
            ip: m.ip,
            jail_id: self.jail_id.clone(),
            timestamp,
        };
        self.tx.blocking_send(failure).is_ok()
    }
}

/// Outcome of a single `read_line_bounded` call.
enum ReadOutcome {
    /// A complete, newline-terminated line was decoded into the output buffer.
    Complete,
    /// An oversized line was skipped; keep reading.
    Skipped,
    /// No complete line available (EOF); any partial bytes stay buffered.
    Eof,
}

/// Blocking file-read loop running on a dedicated thread.
///
/// All parameters are passed by value because this function runs on a
/// `spawn_blocking` thread and the closure must be `'static`.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn read_loop(
    jail_id: String,
    log_path: PathBuf,
    matcher: JailMatcher,
    date_parser: DateParser,
    ignore_list: IgnoreList,
    tx: mpsc::Sender<Failure>,
    cancel: CancellationToken,
) {
    let poll_interval = std::time::Duration::from_millis(250);
    let rotation_check_interval = std::time::Duration::from_secs(5);

    let mut file = match open_at_end(&log_path) {
        Ok(f) => f,
        Err(e) => {
            error!(jail = %jail_id, error = %e, "log open failed");
            return;
        }
    };

    let ctx = ReadCtx {
        jail_id,
        matcher,
        date_parser,
        ignore_list,
        tx,
    };
    let mut identity = FileIdentity::from_file(&log_path);
    let mut last_rotation_check = std::time::Instant::now();
    // Bytes of an unterminated line, carried across polls until the newline
    // arrives, the line is oversized, or the file rotates.
    let mut carry: Vec<u8> = Vec::new();
    let mut line = String::new();

    loop {
        if cancel.is_cancelled() {
            break;
        }

        if last_rotation_check.elapsed() >= rotation_check_interval {
            if !maybe_rotate(
                &log_path,
                &mut file,
                &mut identity,
                &mut carry,
                &mut line,
                &ctx,
            ) {
                return;
            }
            last_rotation_check = std::time::Instant::now();
        }

        if !read_available(&mut file, &mut carry, &mut line, &ctx) {
            return; // downstream channel closed
        }

        std::thread::sleep(poll_interval);
    }
}

/// Read every currently-available complete line from `reader`.
///
/// Returns `false` when the downstream channel closes (stop the loop). A
/// partial trailing line with no newline stays buffered in `carry`.
fn read_available(
    reader: &mut BufReader<std::fs::File>,
    carry: &mut Vec<u8>,
    line: &mut String,
    ctx: &ReadCtx,
) -> bool {
    loop {
        line.clear();
        match read_line_bounded(reader, carry, line, &ctx.jail_id) {
            Ok(ReadOutcome::Complete) => {
                if !ctx.handle_line(line.trim_end()) {
                    return false;
                }
            }
            // Oversized line already skipped — keep reading.
            Ok(ReadOutcome::Skipped) => {}
            Ok(ReadOutcome::Eof) => return true,
            Err(e) => {
                warn!(jail = %ctx.jail_id, error = %e, "log read failed");
                return true;
            }
        }
    }
}

/// Check for log rotation and, when detected, drain the old handle before
/// switching to the freshly opened file. Returns `false` on channel close.
fn maybe_rotate(
    log_path: &PathBuf,
    file: &mut BufReader<std::fs::File>,
    identity: &mut Option<FileIdentity>,
    carry: &mut Vec<u8>,
    line: &mut String,
    ctx: &ReadCtx,
) -> bool {
    let (Some(old_id), Some(new_id)) = (identity.as_ref(), FileIdentity::from_file(log_path))
    else {
        return true;
    };
    if !old_id.is_rotated(&new_id) {
        *identity = Some(new_id);
        return true;
    }
    info!(jail = %ctx.jail_id, "reopening rotated log");
    // Drain trailing complete lines and any buffered partial from the OLD
    // file before we lose the handle.
    if !drain_reader(file, carry, line, ctx) {
        return false;
    }
    match open_from_start(log_path) {
        Ok(f) => {
            *file = f;
            *identity = Some(new_id);
        }
        Err(e) => {
            warn!(jail = %ctx.jail_id, error = %e, "log reopen failed");
        }
    }
    true
}

/// Drain all remaining complete lines from a soon-to-be-replaced reader, then
/// flush any buffered partial as a final line. Returns `false` on channel close.
fn drain_reader(
    reader: &mut BufReader<std::fs::File>,
    carry: &mut Vec<u8>,
    line: &mut String,
    ctx: &ReadCtx,
) -> bool {
    if !read_available(reader, carry, line, ctx) {
        return false;
    }
    if !carry.is_empty() {
        let remainder = String::from_utf8_lossy(carry).into_owned();
        carry.clear();
        if !ctx.handle_line(remainder.trim_end()) {
            return false;
        }
    }
    true
}

/// Read one line, buffering unterminated bytes in `carry` across calls.
///
/// Uses `take()` to cap how many bytes are read per call, preventing OOM on
/// files with no newlines. Raw bytes are decoded via `from_utf8_lossy` so
/// invalid UTF-8 never causes an error. A line with no trailing newline is
/// retained in `carry` and completed on a later call once the newline arrives.
fn read_line_bounded(
    reader: &mut BufReader<std::fs::File>,
    carry: &mut Vec<u8>,
    out: &mut String,
    jail_id: &str,
) -> std::io::Result<ReadOutcome> {
    let limit = (MAX_LINE_LEN as u64) + 1;
    reader.by_ref().take(limit).read_until(b'\n', carry)?;

    if carry.last() == Some(&b'\n') {
        out.push_str(&String::from_utf8_lossy(carry));
        carry.clear();
        return Ok(ReadOutcome::Complete);
    }

    // No newline yet. Oversized without a terminator → skip the whole line.
    if carry.len() > MAX_LINE_LEN {
        warn!(
            jail = %jail_id,
            limit = MAX_LINE_LEN,
            reason = "oversized",
            "log line skipped"
        );
        drain_until_newline(reader)?;
        carry.clear();
        return Ok(ReadOutcome::Skipped);
    }

    // Partial line at EOF — retain bytes in `carry` for the next poll.
    Ok(ReadOutcome::Eof)
}

/// Drain remaining bytes until the next newline or EOF, without heap allocation.
fn drain_until_newline(reader: &mut BufReader<std::fs::File>) -> std::io::Result<()> {
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            break; // EOF
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            reader.consume(pos + 1);
            break;
        }
        let len = available.len();
        reader.consume(len);
    }
    Ok(())
}

fn open_at_end(path: &PathBuf) -> std::io::Result<BufReader<std::fs::File>> {
    let mut file = std::fs::File::open(path)?;
    file.seek(SeekFrom::End(0))?;
    Ok(BufReader::new(file))
}

fn open_from_start(path: &PathBuf) -> std::io::Result<BufReader<std::fs::File>> {
    let file = std::fs::File::open(path)?;
    Ok(BufReader::new(file))
}

#[cfg(test)]
#[path = "reader_test.rs"]
mod reader_test;
