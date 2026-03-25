//! Log file watcher — tails log files and emits failure events.
//!
//! Each jail gets its own watcher task. Detects log rotation via inode/size
//! changes and reopens the file automatically.

use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::PathBuf;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use xxhash_rust::xxh3::xxh3_64;

/// Maximum line length before we skip the line (64 KB).
const MAX_LINE_LEN: usize = 64 * 1024;

use crate::date::DateParser;
use crate::ignore::IgnoreList;
use crate::matcher::JailMatcher;

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

/// Identifies a log file for rotation detection.
#[derive(Debug)]
struct FileIdentity {
    /// File inode (unix only).
    #[cfg(unix)]
    inode: u64,
    /// File size in bytes.
    size: u64,
    /// Hash of the first line.
    first_line_hash: u64,
}

impl FileIdentity {
    fn from_file(path: &PathBuf) -> Option<Self> {
        let meta = std::fs::metadata(path).ok()?;
        let size = meta.len();

        #[cfg(unix)]
        let inode = {
            use std::os::unix::fs::MetadataExt;
            meta.ino()
        };

        let first_line_hash = {
            let file = std::fs::File::open(path).ok()?;
            let mut reader = BufReader::new(file);
            let mut line = String::new();
            reader.read_line(&mut line).ok()?;
            xxh3_64(line.as_bytes())
        };

        Some(Self {
            #[cfg(unix)]
            inode,
            size,
            first_line_hash,
        })
    }

    fn is_rotated(&self, other: &FileIdentity) -> bool {
        #[cfg(unix)]
        if self.inode != other.inode {
            return true;
        }
        // Size shrunk → truncated/rotated.
        if other.size < self.size {
            return true;
        }
        // First line hash changed → different file.
        self.first_line_hash != other.first_line_hash
    }
}

/// Run a watcher task for a single jail.
///
/// File I/O is performed on a blocking thread via `spawn_blocking` to
/// avoid stalling the tokio worker pool.
pub async fn run(
    jail_id: String,
    log_path: PathBuf,
    matcher: JailMatcher,
    date_parser: DateParser,
    ignore_list: IgnoreList,
    tx: mpsc::Sender<Failure>,
    cancel: CancellationToken,
) {
    info!(jail = %jail_id, path = %log_path.display(), "watcher started");

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
                info!(jail = %jail_id, "watcher shutting down");
                break;
            }
            failure = line_rx.recv() => {
                match failure {
                    Some(f) => {
                        if tx.send(f).await.is_err() {
                            info!(jail = %jail_id, "channel closed, stopping watcher");
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

/// Blocking file-read loop running on a dedicated thread.
///
/// All parameters are passed by value because this function runs on a
/// `spawn_blocking` thread and the closure must be `'static`.
#[allow(clippy::needless_pass_by_value)]
fn read_loop(
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
            error!(jail = %jail_id, error = %e, "failed to open log file");
            return;
        }
    };

    let mut identity = FileIdentity::from_file(&log_path);
    let mut last_rotation_check = std::time::Instant::now();

    loop {
        if cancel.is_cancelled() {
            break;
        }

        // Check for rotation periodically.
        if last_rotation_check.elapsed() >= rotation_check_interval {
            if let Some(ref old_id) = identity
                && let Some(new_id) = FileIdentity::from_file(&log_path)
            {
                if old_id.is_rotated(&new_id) {
                    info!(jail = %jail_id, "log rotation detected, reopening");
                    match open_from_start(&log_path) {
                        Ok(f) => {
                            file = f;
                            identity = Some(new_id);
                        }
                        Err(e) => {
                            warn!(jail = %jail_id, error = %e, "failed to reopen after rotation");
                        }
                    }
                } else {
                    identity = Some(new_id);
                }
            }
            last_rotation_check = std::time::Instant::now();
        }

        // Read new lines.
        let mut line = String::new();
        loop {
            line.clear();
            match read_line_bounded(&mut file, &mut line, &jail_id) {
                Ok(0) => break, // No more data.
                Ok(_) => {
                    let trimmed = line.trim_end();
                    if let Some(m) = matcher.try_match(trimmed) {
                        if ignore_list.is_ignored(&m.ip) {
                            debug!(jail = %jail_id, ip = %m.ip, "ignored");
                            continue;
                        }
                        let timestamp = date_parser
                            .parse_line(trimmed)
                            .unwrap_or_else(|| chrono::Utc::now().timestamp());

                        let failure = Failure {
                            ip: m.ip,
                            jail_id: jail_id.clone(),
                            timestamp,
                        };
                        if tx.blocking_send(failure).is_err() {
                            return; // async side closed
                        }
                    }
                }
                Err(e) => {
                    warn!(jail = %jail_id, error = %e, "read error");
                    break;
                }
            }
        }

        std::thread::sleep(poll_interval);
    }
}

/// Read a line, skipping (with warning) if it exceeds `MAX_LINE_LEN`.
///
/// Uses `take()` to cap how many bytes `read_line()` can allocate,
/// preventing OOM on files with no newlines (e.g. `/dev/zero` via symlink).
fn read_line_bounded(
    reader: &mut BufReader<std::fs::File>,
    buf: &mut String,
    jail_id: &str,
) -> std::io::Result<usize> {
    let limit = (MAX_LINE_LEN as u64) + 1;
    let n = reader.by_ref().take(limit).read_line(buf)?;
    if n == 0 {
        return Ok(0);
    }
    // If we read up to the limit without a newline, the line is oversized.
    if buf.len() > MAX_LINE_LEN && !buf.ends_with('\n') {
        warn!(jail = %jail_id, "skipping oversized log line (>{MAX_LINE_LEN} bytes)");
        buf.clear();
        drain_until_newline(reader)?;
        return Ok(0);
    }
    Ok(n)
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
