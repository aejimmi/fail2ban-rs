//! Blocking log-file read loop.
//!
//! Runs on a dedicated `spawn_blocking` thread. Tails a log file, decodes
//! bounded lines (skipping oversized ones), detects rotation via
//! [`FileIdentity`](crate::detect::identity::FileIdentity), and forwards matched [`Failure`](crate::detect::watcher::Failure) events. All state is
//! bundled in `ReadCtx` so the steady-state and rotation-drain paths share
//! line-processing logic.

use std::io::{BufRead, BufReader, Read, Seek};
use std::path::PathBuf;

use memchr::memchr;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::detect::date::DateParser;
use crate::detect::identity::FileIdentity;
use crate::detect::ignore::IgnoreList;
use crate::detect::matcher::JailMatcher;
use crate::detect::resume::{FilePosition, open_log};
use crate::detect::watcher::{Failure, MAX_LINE_LEN};
use crate::text::lossy;

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

/// Poll interval between reads of the log file.
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);
/// How often the path is re-fingerprinted to detect rotation.
const ROTATION_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Open file handle plus line buffers for one tailing session.
struct TailState {
    file: BufReader<std::fs::File>,
    identity: Option<FileIdentity>,
    /// Bytes of an unterminated line, carried across polls until the newline
    /// arrives, the line is oversized, or the file rotates.
    carry: Vec<u8>,
    line: String,
}

impl TailState {
    /// The position of the first unprocessed byte in the current handle.
    ///
    /// Buffered-but-unterminated bytes in `carry` are excluded so a successor
    /// re-reads the partial line in full.
    fn position(&mut self, path: PathBuf) -> Option<FilePosition> {
        let pos = match self.file.stream_position() {
            Ok(p) => p,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "log position unavailable");
                return None;
            }
        };
        Some(FilePosition {
            identity: FileIdentity::from_handle(self.file.get_ref()),
            offset: pos.saturating_sub(self.carry.len() as u64),
            path,
        })
    }
}

/// Blocking file-read loop running on a dedicated thread.
///
/// Opens the log (retrying with backoff while it is missing), starting at
/// `resume` when it identifies the same file, otherwise at EOF. On
/// cancellation performs one final read, then returns the position reached
/// so a replacement reader can continue without a gap. All parameters are
/// passed by value because this runs on a `spawn_blocking` thread.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub(crate) fn read_loop(
    jail_id: String,
    log_path: PathBuf,
    matcher: JailMatcher,
    date_parser: DateParser,
    ignore_list: IgnoreList,
    tx: mpsc::Sender<Failure>,
    cancel: CancellationToken,
    resume: Option<FilePosition>,
) -> Option<FilePosition> {
    let Some(file) = open_log(&jail_id, &log_path, resume.as_ref(), &cancel) else {
        return Some(FilePosition::absent(log_path));
    };
    let ctx = ReadCtx {
        jail_id,
        matcher,
        date_parser,
        ignore_list,
        tx,
    };
    let mut state = TailState {
        identity: handle_identity(file.get_ref(), &log_path),
        file,
        carry: Vec::new(),
        line: String::new(),
    };
    tail(&ctx, &log_path, &mut state, &cancel);
    state.position(log_path)
}

/// Poll the open file until cancelled or the downstream channel closes.
fn tail(ctx: &ReadCtx, log_path: &PathBuf, st: &mut TailState, cancel: &CancellationToken) {
    let mut last_rotation_check = std::time::Instant::now();
    loop {
        if cancel.is_cancelled() {
            // Final read: lines written since the last poll are not lost.
            if !read_available(&mut st.file, &mut st.carry, &mut st.line, ctx) {
                debug!(jail = %ctx.jail_id, "final read stopped: channel closed");
            }
            return;
        }
        if last_rotation_check.elapsed() >= ROTATION_CHECK_INTERVAL {
            let (file, identity) = (&mut st.file, &mut st.identity);
            if !maybe_rotate(log_path, file, identity, &mut st.carry, &mut st.line, ctx) {
                return;
            }
            last_rotation_check = std::time::Instant::now();
        }
        if !read_available(&mut st.file, &mut st.carry, &mut st.line, ctx) {
            return; // downstream channel closed
        }
        std::thread::sleep(POLL_INTERVAL);
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
    let Some(new_id) = rotated_identity(log_path, file, identity) else {
        return true;
    };
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

/// The path's identity if it names a rotated/replaced file, else `None`.
///
/// When the file merely grew, the stored identity is refreshed (upgrading an
/// unknown first line once it completes). A missing stored identity is
/// retried from the open handle rather than disabling rotation detection.
fn rotated_identity(
    log_path: &PathBuf,
    file: &BufReader<std::fs::File>,
    identity: &mut Option<FileIdentity>,
) -> Option<FileIdentity> {
    if identity.is_none() {
        *identity = handle_identity(file.get_ref(), log_path);
    }
    let new_id = FileIdentity::from_file(log_path)?;
    if identity.as_ref()?.is_rotated(&new_id) {
        return Some(new_id);
    }
    *identity = Some(new_id);
    None
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
        // Owned: the borrow must end before `carry` is cleared.
        let remainder = lossy(carry).into_owned();
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
        out.push_str(&lossy(carry));
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
        if let Some(pos) = memchr(b'\n', available) {
            reader.consume(pos + 1);
            break;
        }
        let len = available.len();
        reader.consume(len);
    }
    Ok(())
}

/// Fingerprint the file the reader actually holds open.
///
/// Uses the handle (not the path, which may already name a rotated-in file);
/// falls back to the path only where handle fingerprinting is unsupported.
fn handle_identity(file: &std::fs::File, path: &PathBuf) -> Option<FileIdentity> {
    FileIdentity::from_handle(file).or_else(|| {
        if cfg!(unix) {
            None
        } else {
            FileIdentity::from_file(path)
        }
    })
}

/// Open `path` for reading from its first byte.
fn open_from_start(path: &PathBuf) -> std::io::Result<BufReader<std::fs::File>> {
    let file = std::fs::File::open(path)?;
    Ok(BufReader::new(file))
}

#[cfg(test)]
#[path = "reader_test.rs"]
mod reader_test;

#[cfg(test)]
#[path = "reader_rotation_test.rs"]
mod reader_rotation_test;
