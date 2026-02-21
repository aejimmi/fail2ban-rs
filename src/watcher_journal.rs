//! Journal watcher — reads log entries from the systemd journal.
//!
//! Uses `journalctl --follow` as a subprocess to stream new journal entries.
//! Matched lines are sent as `Failure` events to the tracker.
//!
//! Only compiled when the `systemd` feature is enabled.

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::date::DateParser;
use crate::ignore::IgnoreList;
use crate::matcher::JailMatcher;
use crate::watcher::Failure;

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
            error!(jail = %jail_id, error = %e, "failed to spawn journalctl");
            return;
        }
    };

    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            error!(jail = %jail_id, "journalctl stdout not available");
            return;
        }
    };

    let mut reader = BufReader::new(stdout).lines();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!(jail = %jail_id, "journal watcher shutting down");
                let _ = child.kill().await;
                break;
            }

            line = reader.next_line() => {
                match line {
                    Ok(Some(text)) => {
                        process_line(
                            &text,
                            &jail_id,
                            &matcher,
                            &date_parser,
                            &ignore_list,
                            &failure_tx,
                        ).await;
                    }
                    Ok(None) => {
                        warn!(jail = %jail_id, "journalctl stream ended");
                        break;
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
    let match_result = match matcher.try_match(line) {
        Some(r) => r,
        None => return,
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
