//! Journal watcher — reads log entries from the systemd journal.
//!
//! Streams `journalctl --follow --output=json` as a subprocess. Each entry is
//! rebuilt into the classic short syslog layout for matching, and its cursor
//! is remembered so that a restart (after `journalctl` exits unexpectedly) or
//! a reload handoff resumes with `--after-cursor` instead of skipping entries.

use std::ffi::OsString;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::detect::backoff::Backoff;
use crate::detect::date::DateParser;
use crate::detect::ignore::IgnoreList;
use crate::detect::journal_entry::parse_entry;
use crate::detect::journal_proc::{StderrCapture, cursor_rejected, reap};
use crate::detect::matcher::JailMatcher;
use crate::detect::resume::ResumePoint;
use crate::detect::watcher::Failure;

/// Program used to stream the journal.
const JOURNALCTL: &str = "journalctl";

/// Upper bound on one `journalctl --output=json` line (a whole entry).
///
/// Deliberately far larger than the per-message
/// [`MAX_LINE_LEN`](crate::detect::watcher::MAX_LINE_LEN): the JSON object
/// carries every journal field, and a non-UTF-8 `MESSAGE` is encoded as a
/// byte array (`[97,98,...]`, ~4 bytes per byte). Capping the entry at the
/// message limit would let an attacker push a failure line past the cap —
/// and out of matching — with a modest non-UTF-8 message. The decoded
/// message is truncated to `MAX_LINE_LEN` instead (see `parse_entry`).
pub(crate) const MAX_ENTRY_LEN: usize = 1024 * 1024;

/// State shared by every `journalctl` session of one jail.
pub(crate) struct JournalCtx {
    pub(crate) jail_id: String,
    pub(crate) journalmatch: Vec<String>,
    pub(crate) matcher: JailMatcher,
    pub(crate) date_parser: DateParser,
    pub(crate) ignore_list: IgnoreList,
    pub(crate) failure_tx: mpsc::Sender<Failure>,
    /// Program to run (`journalctl`; overridable for tests).
    pub(crate) program: OsString,
    /// Arguments placed before the journalctl flags (empty in production).
    pub(crate) prefix_args: Vec<OsString>,
    pub(crate) handoff: Arc<AtomicBool>,
}

/// Run the journal watcher for a single jail, starting at the journal tail.
///
/// Equivalent to [`run_from`] with no resume point.
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
) -> Option<ResumePoint> {
    run_from(
        jail_id,
        journalmatch,
        matcher,
        date_parser,
        ignore_list,
        failure_tx,
        cancel,
        phase,
        None,
    )
    .await
}

/// Run the journal watcher for a single jail, optionally resuming.
///
/// With a journal `resume` point, streaming starts right after that cursor
/// (`--after-cursor`); otherwise at the tail (`--lines=0`). If `journalctl`
/// exits or its stream fails, it is restarted with capped backoff from the
/// last seen cursor. Returns the last processed cursor once cancelled (or
/// when the failure channel closes), for handing to a replacement watcher.
#[allow(clippy::too_many_arguments)]
pub async fn run_from(
    jail_id: String,
    journalmatch: Vec<String>,
    matcher: JailMatcher,
    date_parser: DateParser,
    ignore_list: IgnoreList,
    failure_tx: mpsc::Sender<Failure>,
    cancel: CancellationToken,
    phase: &'static str,
    resume: Option<ResumePoint>,
) -> Option<ResumePoint> {
    run_supervised_from(
        jail_id,
        journalmatch,
        matcher,
        date_parser,
        ignore_list,
        failure_tx,
        cancel,
        phase,
        resume,
        Arc::new(AtomicBool::new(false)),
    )
    .await
}

/// Server-managed journal watcher whose reload cancellation drains an entry
/// before advancing its handoff cursor.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_supervised_from(
    jail_id: String,
    journalmatch: Vec<String>,
    matcher: JailMatcher,
    date_parser: DateParser,
    ignore_list: IgnoreList,
    failure_tx: mpsc::Sender<Failure>,
    cancel: CancellationToken,
    phase: &'static str,
    resume: Option<ResumePoint>,
    handoff: Arc<AtomicBool>,
) -> Option<ResumePoint> {
    info!(phase, jail = %jail_id, "journal watcher started");
    let ctx = JournalCtx {
        jail_id,
        journalmatch,
        matcher,
        date_parser,
        ignore_list,
        failure_tx,
        program: OsString::from(JOURNALCTL),
        prefix_args: Vec::new(),
        handoff,
    };
    let cursor = resume.and_then(ResumePoint::into_journal_cursor);
    let cursor = supervise(&ctx, cursor, &cancel).await;
    debug!(jail = %ctx.jail_id, "journal watcher stopped");
    cursor.map(ResumePoint::journal)
}

/// How a single `journalctl` session ended.
enum Session {
    /// Cancelled or failure channel closed — do not restart.
    Stopped,
    /// `journalctl` exited or failed; restart after backoff.
    Ended {
        /// Whether any entry was read (resets the backoff).
        progressed: bool,
        /// Whether `journalctl` evidently rejected the resume cursor (stderr
        /// names it, or a fast non-zero exit without entries).
        cursor_rejected: bool,
        /// Human-readable cause, for logging.
        reason: String,
    },
}

impl Session {
    fn ended(progressed: bool, reason: impl Into<String>) -> Self {
        Self::Ended {
            progressed,
            cursor_rejected: false,
            reason: reason.into(),
        }
    }

    /// Fold the child's exit status and stderr into an ended session.
    fn with_exit(
        self,
        elapsed: std::time::Duration,
        status: Option<std::process::ExitStatus>,
        stderr: &str,
    ) -> Self {
        let Self::Ended {
            progressed, reason, ..
        } = self
        else {
            return self;
        };
        let stderr = stderr.trim();
        Self::Ended {
            progressed,
            cursor_rejected: !progressed && cursor_rejected(elapsed, status, stderr),
            reason: if stderr.is_empty() {
                reason
            } else {
                format!("{reason}: {stderr}")
            },
        }
    }
}

/// Run `journalctl` sessions until cancelled, restarting after exits.
///
/// Returns the cursor of the last fully processed entry.
pub(crate) async fn supervise(
    ctx: &JournalCtx,
    mut cursor: Option<String>,
    cancel: &CancellationToken,
) -> Option<String> {
    let mut backoff = Backoff::new();
    loop {
        let used_cursor = cursor.is_some();
        let Session::Ended {
            progressed,
            cursor_rejected,
            reason,
        } = run_session(ctx, &mut cursor, cancel).await
        else {
            return cursor;
        };
        if progressed {
            backoff.reset();
        } else if used_cursor && cursor_rejected {
            // A cursor journalctl cannot seek to would fail every restart.
            // A merely quiet session keeps its cursor so nothing is skipped.
            warn!(jail = %ctx.jail_id, reason, "journal cursor rejected, restarting at tail");
            cursor = None;
        }
        let delay = backoff.next_delay();
        log_restart(&ctx.jail_id, &reason, &backoff, delay);
        tokio::select! {
            () = cancel.cancelled() => return cursor,
            () = tokio::time::sleep(delay) => {}
        }
    }
}

/// Log a session failure: `warn!` for the first in a row, then `debug!`.
fn log_restart(jail_id: &str, reason: &str, backoff: &Backoff, delay: std::time::Duration) {
    let retry_secs = delay.as_secs();
    if backoff.is_first_failure() {
        warn!(jail = %jail_id, reason, retry_secs, "journalctl stopped, restarting");
    } else {
        debug!(jail = %jail_id, reason, retry_secs, "journalctl stopped again, restarting");
    }
}

/// Spawn one `journalctl` and stream it until it ends or we are cancelled.
async fn run_session(
    ctx: &JournalCtx,
    cursor: &mut Option<String>,
    cancel: &CancellationToken,
) -> Session {
    let started = std::time::Instant::now();
    let mut child = match build_command(ctx, cursor.as_deref()).spawn() {
        Ok(c) => c,
        Err(e) => {
            return Session::ended(
                false,
                format!(
                    "journalctl spawn failed: {e} (install systemd-journald or switch jail to log_backend=\"file\")"
                ),
            );
        }
    };
    let stderr = StderrCapture::spawn(&mut child);
    let session = match child.stdout.take() {
        Some(stdout) => stream(ctx, BufReader::new(stdout), cursor, cancel).await,
        None => Session::ended(false, "journalctl stdout unavailable"),
    };
    if matches!(session, Session::Stopped) {
        stop_child(&ctx.jail_id, &mut child).await;
        return session;
    }
    let status = reap(&ctx.jail_id, &mut child).await;
    let stderr = stderr.collect().await;
    session.with_exit(started.elapsed(), status, &stderr)
}

/// Build the `journalctl` command line for a session.
fn build_command(ctx: &JournalCtx, cursor: Option<&str>) -> Command {
    let mut cmd = Command::new(&ctx.program);
    cmd.args(&ctx.prefix_args)
        .args(["--follow", "--no-pager", "--output=json", "--all"]);
    match cursor {
        Some(c) => cmd.arg(format!("--after-cursor={c}")).arg("--lines=all"),
        None => cmd.arg("--lines=0"), // start at the tail, no backlog
    };
    cmd.args(&ctx.journalmatch)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    cmd
}

/// Kill and reap the child (a no-op error if it already exited).
async fn stop_child(jail_id: &str, child: &mut Child) {
    if let Err(e) = child.kill().await {
        debug!(jail = %jail_id, error = %e, "journalctl kill failed (already exited)");
    }
}

/// Read JSON entries from `reader` until EOF, error, or cancellation.
async fn stream<R: AsyncBufRead + Unpin>(
    ctx: &JournalCtx,
    mut reader: R,
    cursor: &mut Option<String>,
    cancel: &CancellationToken,
) -> Session {
    let mut buf = String::new();
    let mut progressed = false;
    loop {
        buf.clear();
        let result = tokio::select! {
            () = cancel.cancelled() => return Session::Stopped,
            r = read_line_bounded(&mut reader, &mut buf, &ctx.jail_id) => r,
        };
        match result {
            Ok(0) => return Session::ended(progressed, "journalctl stream ended"),
            Ok(_) => {
                progressed = true;
                if !handle_entry(ctx, buf.trim_end(), cursor, cancel).await {
                    return Session::Stopped;
                }
            }
            Err(e) => return Session::ended(progressed, format!("journal read failed: {e}")),
        }
    }
}

/// Match every line of one JSON entry, then advance `cursor` past it.
///
/// Returns `false` when cancelled mid-send or the failure channel closed.
///
/// Delivery is at-least-once per entry: `cursor` only advances after *all*
/// lines of the entry were forwarded, so a cancellation part-way through a
/// multi-line entry leaves the cursor before it and the successor watcher
/// replays the whole entry — lines already forwarded are counted again.
async fn handle_entry(
    ctx: &JournalCtx,
    json: &str,
    cursor: &mut Option<String>,
    cancel: &CancellationToken,
) -> bool {
    if json.is_empty() {
        return true;
    }
    let Some(entry) = parse_entry(json) else {
        debug!(jail = %ctx.jail_id, "journal entry not valid JSON, skipped");
        return true;
    };
    for line in entry.lines() {
        if !process_line(ctx, &line, entry.timestamp, cancel).await {
            return false;
        }
    }
    if entry.cursor.is_some() {
        *cursor = entry.cursor;
    }
    true
}

/// Match one short-format line and forward a failure if it matches.
///
/// Returns `false` when cancelled mid-send or the failure channel closed.
async fn process_line(
    ctx: &JournalCtx,
    line: &str,
    entry_ts: Option<i64>,
    cancel: &CancellationToken,
) -> bool {
    let Some(m) = ctx.matcher.try_match(line) else {
        return true;
    };
    if ctx.ignore_list.is_ignored(&m.ip) {
        return true;
    }
    let timestamp = entry_ts
        .or_else(|| ctx.date_parser.parse_line(line))
        .unwrap_or_else(|| chrono::Utc::now().timestamp());
    let failure = Failure {
        ip: m.ip,
        jail_id: ctx.jail_id.clone(),
        timestamp,
    };
    tokio::select! {
        biased;
        r = ctx.failure_tx.reserve() => {
            if r.is_err() {
                warn!(jail = %ctx.jail_id, "failure channel closed");
            }
            if let Ok(permit) = r { permit.send(failure); true } else { false }
        }
        () = cancel.cancelled() => {
            if ctx.handoff.load(Ordering::Acquire) {
                ctx.failure_tx.send(failure).await.is_ok()
            } else {
                false
            }
        },
    }
}

/// Read a single line from the async reader, bounded by [`MAX_ENTRY_LEN`].
///
/// Uses `fill_buf` / `consume` to accumulate bytes into `buf` up to the
/// limit. If the line exceeds [`MAX_ENTRY_LEN`], logs a warning, drains
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
            let to_take = finish_line(available, pos, total, buf, jail_id);
            reader.consume(to_take);
            return Ok(total + to_take);
        }
        // No newline found in this chunk.
        let chunk_len = available.len();
        if total + chunk_len > MAX_ENTRY_LEN {
            return skip_oversized(reader, buf, chunk_len, jail_id).await;
        }
        append_valid_utf8(buf, available);
        reader.consume(chunk_len);
        total += chunk_len;
    }
}

/// Complete a line whose newline sits at `pos` in `available`: append it to
/// `buf`, or drop the whole line if it would exceed [`MAX_ENTRY_LEN`]. Returns
/// the byte count (newline included) the caller must consume.
fn finish_line(
    available: &[u8],
    pos: usize,
    total: usize,
    buf: &mut String,
    jail_id: &str,
) -> usize {
    let to_take = pos + 1;
    if total + to_take > MAX_ENTRY_LEN {
        warn!(
            jail = %jail_id,
            limit = MAX_ENTRY_LEN,
            reason = "oversized",
            "journal line skipped"
        );
        buf.clear();
    } else if let Some(slice) = available.get(..to_take) {
        append_valid_utf8(buf, slice);
    }
    to_take
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
        limit = MAX_ENTRY_LEN,
        reason = "oversized",
        "journal line skipped"
    );
    reader.consume(chunk_len);
    buf.clear();
    drain_until_newline(reader).await?;
    // Return non-zero so caller knows this is not EOF.
    Ok(MAX_ENTRY_LEN + 1)
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

#[cfg(test)]
#[path = "journal_cursor_test.rs"]
mod journal_cursor_test;
