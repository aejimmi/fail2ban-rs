//! Log file watcher — tails log files and emits failure events.
//!
//! Each jail gets its own watcher task. The blocking read loop lives in
//! [`reader`](crate::detect::reader); this module owns the async task that
//! spawns it and forwards [`Failure`] events. Rotation detection via
//! inode/size changes reopens the file automatically.

use std::net::IpAddr;
use std::path::PathBuf;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

/// Maximum line length before we skip the line (64 KB).
pub(crate) const MAX_LINE_LEN: usize = 64 * 1024;

use crate::detect::date::DateParser;
use crate::detect::ignore::IgnoreList;
use crate::detect::matcher::JailMatcher;
use crate::detect::reader::read_loop;

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

/// Run a watcher task for a single jail.
///
/// File I/O is performed on a blocking thread via `spawn_blocking` to
/// avoid stalling the tokio worker pool.
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
) {
    info!(
        phase,
        jail = %jail_id,
        path = %log_path.display(),
        "watcher started"
    );

    // Internal channel between blocking reader and async sender.
    let (line_tx, mut line_rx) = mpsc::channel::<Failure>(256);

    // Spawn blocking reader thread.
    let reader_jail = jail_id.clone();
    let reader_cancel = cancel.clone();
    let reader_handle = tokio::task::spawn_blocking(move || {
        read_loop(
            reader_jail,
            log_path,
            matcher,
            date_parser,
            ignore_list,
            line_tx,
            reader_cancel,
        );
    });

    // Forward failures from blocking reader to the async failure channel.
    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                debug!(jail = %jail_id, "watcher stopping");
                break;
            }
            failure = line_rx.recv() => {
                match failure {
                    Some(f) => {
                        if tx.send(f).await.is_err() {
                            debug!(jail = %jail_id, reason = "channel_closed", "watcher stopping");
                            break;
                        }
                    }
                    None => break, // reader exited
                }
            }
        }
    }

    let _ = reader_handle.await;
}

#[cfg(test)]
#[path = "watcher_test.rs"]
mod watcher_test;
