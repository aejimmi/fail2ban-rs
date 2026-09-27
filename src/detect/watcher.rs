//! Log file watcher — tails log files and emits failure events.
//!
//! Each jail gets its own watcher task. The blocking read loop lives in
//! `reader`; this module owns the async task that
//! spawns it and forwards [`Failure`](crate::detect::watcher::Failure) events. Rotation detection via
//! inode/size changes reopens the file automatically.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Maximum line length before we skip the line (64 KB).
pub(crate) const MAX_LINE_LEN: usize = 64 * 1024;

use crate::detect::date::DateParser;
use crate::detect::ignore::IgnoreList;
use crate::detect::matcher::JailMatcher;
use crate::detect::reader::read_loop;
use crate::detect::resume::{FilePosition, ResumePoint};

/// A detected authentication failure.
#[derive(Debug, Clone)]
pub struct Failure {
    /// The offending IP address.
    pub ip: IpAddr,
    /// Which jail detected it.
    pub jail_id: String,
    /// Unix timestamp from the log line.
    pub timestamp: i64,
}

/// How long a cancelled watcher keeps forwarding already-read failures
/// before giving up and dropping the rest.
pub(crate) const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Capacity of the channel between the blocking reader and the async task.
const LINE_CHANNEL_CAPACITY: usize = 256;

/// Run a watcher task for a single jail, starting at the end of the log.
///
/// Equivalent to [`run_from`] with no resume point. Returns the position
/// reached when the watcher stops (see [`run_from`]).
#[allow(clippy::too_many_arguments)]
pub async fn run(
    jail_id: String,
    log_path: PathBuf,
    matcher: JailMatcher,
    date_parser: DateParser,
    ignore_list: IgnoreList,
    tx: mpsc::Sender<Failure>,
    cancel: CancellationToken,
    phase: &'static str,
) -> Option<ResumePoint> {
    run_from(
        jail_id,
        log_path,
        matcher,
        date_parser,
        ignore_list,
        tx,
        cancel,
        phase,
        None,
    )
    .await
}

/// Run a watcher task for a single jail, optionally resuming a predecessor.
///
/// File I/O is performed on a blocking thread via `spawn_blocking` to avoid
/// stalling the tokio worker pool. If `resume` came from a watcher on the
/// same file, reading continues at its offset; otherwise the log is tailed
/// from EOF. A log that does not exist yet is retried with backoff and read
/// from its start once it appears.
///
/// On cancellation the reader does one final read and the task forwards
/// queued failures for up to `DRAIN_TIMEOUT`. Returns the position the
/// reader reached, for handing to a replacement watcher; `None` if the
/// reader failed, its position could not be determined, or the drain timed
/// out (queued failures were dropped, so the reader's position is past
/// failures that were never delivered).
#[allow(clippy::too_many_arguments)]
pub async fn run_from(
    jail_id: String,
    log_path: PathBuf,
    matcher: JailMatcher,
    date_parser: DateParser,
    ignore_list: IgnoreList,
    tx: mpsc::Sender<Failure>,
    cancel: CancellationToken,
    phase: &'static str,
    resume: Option<ResumePoint>,
) -> Option<ResumePoint> {
    run_supervised_from(
        jail_id,
        log_path,
        matcher,
        date_parser,
        ignore_list,
        tx,
        cancel,
        phase,
        resume,
        Arc::new(AtomicBool::new(false)),
    )
    .await
}

/// Server-managed watcher. Reload switches `handoff` on before cancellation
/// so queued failures must drain before the replacement starts.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_supervised_from(
    jail_id: String,
    log_path: PathBuf,
    matcher: JailMatcher,
    date_parser: DateParser,
    ignore_list: IgnoreList,
    tx: mpsc::Sender<Failure>,
    cancel: CancellationToken,
    phase: &'static str,
    resume: Option<ResumePoint>,
    handoff: Arc<AtomicBool>,
) -> Option<ResumePoint> {
    info!(phase, jail = %jail_id, path = %log_path.display(), "watcher started");

    let (line_tx, mut line_rx) = mpsc::channel::<Failure>(LINE_CHANNEL_CAPACITY);
    let reader_cancel = cancel.child_token();
    let (reader_jail, rc) = (jail_id.clone(), reader_cancel.clone());
    let start = resume.and_then(ResumePoint::into_file);
    let reader_handle = tokio::task::spawn_blocking(move || {
        read_loop(
            reader_jail,
            log_path,
            matcher,
            date_parser,
            ignore_list,
            line_tx,
            rc,
            start,
        )
    });

    let stop = forward(&jail_id, &mut line_rx, &tx, &cancel).await;
    let drained = stop_reader(&jail_id, stop, line_rx, &tx, &reader_cancel, &handoff).await;
    let resume = join_reader(&jail_id, reader_handle).await;
    drained_resume(&jail_id, drained, resume)
}

/// The resume point to hand on: none if the drain dropped queued failures,
/// since the reader's position is already past them.
fn drained_resume(
    jail_id: &str,
    drained: bool,
    resume: Option<ResumePoint>,
) -> Option<ResumePoint> {
    if !drained && resume.is_some() {
        warn!(jail = %jail_id, "resume point discarded: queued failures were dropped");
        return None;
    }
    resume
}

/// Why the forwarding loop ended.
enum Stop {
    /// Watcher cancelled; carries a failure received but not yet forwarded.
    Cancelled(Option<Failure>),
    /// Reader exited or the downstream channel closed.
    Done,
}

/// Forward failures from the blocking reader until cancelled or done.
///
/// Both the receive and the downstream send race against cancellation, so
/// a full downstream channel can never stall shutdown.
async fn forward(
    jail_id: &str,
    line_rx: &mut mpsc::Receiver<Failure>,
    tx: &mpsc::Sender<Failure>,
    cancel: &CancellationToken,
) -> Stop {
    loop {
        let failure = tokio::select! {
            () = cancel.cancelled() => return Stop::Cancelled(None),
            f = line_rx.recv() => match f {
                Some(f) => f,
                None => return Stop::Done, // reader exited
            },
        };
        tokio::select! {
            () = cancel.cancelled() => return Stop::Cancelled(Some(failure)),
            permit = tx.reserve() => {
                let Ok(permit) = permit else {
                    debug!(jail = %jail_id, reason = "channel_closed", "watcher stopping");
                    return Stop::Done;
                };
                permit.send(failure);
            }
        }
    }
}

/// Let the reader finish, then drop the internal receiver.
///
/// On cancellation, keep forwarding (bounded by `DRAIN_TIMEOUT`) so the
/// reader's final read is delivered. Dropping `line_rx` afterwards makes
/// any `blocking_send` still pending in the reader fail immediately, so the
/// reader thread can never hang on a full channel.
///
/// Returns `false` if the drain timed out, i.e. queued failures were
/// dropped undelivered.
async fn stop_reader(
    jail_id: &str,
    stop: Stop,
    mut line_rx: mpsc::Receiver<Failure>,
    tx: &mpsc::Sender<Failure>,
    reader_cancel: &CancellationToken,
    handoff: &AtomicBool,
) -> bool {
    let mut complete = true;
    match stop {
        Stop::Cancelled(pending) => {
            debug!(jail = %jail_id, "watcher stopping");
            if handoff.load(Ordering::Acquire) {
                drain(pending, &mut line_rx, tx).await;
            } else {
                let drained = tokio::time::timeout(DRAIN_TIMEOUT, drain(pending, &mut line_rx, tx));
                if drained.await.is_err() {
                    warn!(jail = %jail_id, "watcher drain timed out, queued failures dropped");
                    complete = false;
                }
            }
        }
        Stop::Done => reader_cancel.cancel(),
    }
    drop(line_rx);
    complete
}

/// Forward `pending` and everything the reader sends until it exits.
async fn drain(
    pending: Option<Failure>,
    line_rx: &mut mpsc::Receiver<Failure>,
    tx: &mpsc::Sender<Failure>,
) {
    if let Some(f) = pending
        && tx.send(f).await.is_err()
    {
        return;
    }
    while let Some(f) = line_rx.recv().await {
        if tx.send(f).await.is_err() {
            return;
        }
    }
}

/// Await the blocking reader and convert its final position.
async fn join_reader(
    jail_id: &str,
    handle: tokio::task::JoinHandle<Option<FilePosition>>,
) -> Option<ResumePoint> {
    match handle.await {
        Ok(pos) => pos.map(ResumePoint::file),
        Err(e) => {
            error!(jail = %jail_id, error = %e, "watcher reader task failed");
            None
        }
    }
}

#[cfg(test)]
#[path = "watcher_test.rs"]
mod watcher_test;
