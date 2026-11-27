//! Webhook notification on ban events.
//!
//! Fires a non-blocking HTTP POST via `curl` subprocess. Webhook failures
//! never affect the ban pipeline — errors are logged and discarded.
//!
//! Delivery is bounded: at most [`MAX_CONCURRENT`] `curl` processes run at
//! once, and at most [`MAX_PENDING`] deliveries (running + waiting) exist at
//! any time. Events beyond that are dropped with a warning so a ban burst can
//! never fork thousands of processes or grow memory without bound. Response
//! bodies are discarded and captured stderr is capped at [`STDERR_CAP`].

use std::process::Stdio;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use crate::ban_target::BanTarget;

use tokio::io::AsyncReadExt;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::warn;

/// Maximum number of `curl` processes running concurrently.
pub const MAX_CONCURRENT: usize = 8;

/// Maximum number of deliveries admitted (running + queued). Beyond this,
/// new events are dropped.
pub const MAX_PENDING: usize = 64;

/// Maximum bytes of `curl` stderr retained for logging.
pub const STDERR_CAP: u64 = 1024;

/// Hard wall-clock bound on one delivery, slightly above curl's own
/// `--max-time` so a wedged process is killed via `kill_on_drop`.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(15);

/// Two-level delivery limiter: a non-blocking admission gate bounding the
/// backlog, and a concurrency gate bounding running processes.
pub(crate) struct Limiter {
    admission: Arc<Semaphore>,
    concurrency: Arc<Semaphore>,
}

/// Proof that a delivery was admitted. Holding it counts toward the backlog.
pub(crate) struct Ticket {
    _admission: OwnedSemaphorePermit,
    concurrency: Arc<Semaphore>,
}

impl Limiter {
    /// Create a limiter with the given concurrency and backlog bounds.
    pub(crate) fn new(concurrent: usize, pending: usize) -> Self {
        Self {
            admission: Arc::new(Semaphore::new(pending.max(concurrent))),
            concurrency: Arc::new(Semaphore::new(concurrent)),
        }
    }

    /// Try to admit one delivery without waiting. `None` means the backlog
    /// is full and the event should be dropped.
    #[must_use]
    pub(crate) fn try_admit(&self) -> Option<Ticket> {
        let permit = Arc::clone(&self.admission).try_acquire_owned().ok()?;
        Some(Ticket {
            _admission: permit,
            concurrency: Arc::clone(&self.concurrency),
        })
    }
}

impl Ticket {
    /// Wait for a concurrency slot. `None` only if the semaphore was closed.
    pub(crate) async fn run_slot(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.concurrency).acquire_owned().await.ok()
    }
}

/// Process-wide limiter shared by all webhook deliveries.
static LIMITER: LazyLock<Limiter> = LazyLock::new(|| Limiter::new(MAX_CONCURRENT, MAX_PENDING));

/// Returns `true` only if `url` uses an `http://` or `https://` scheme.
///
/// This guards against scheme laundering: without it, `curl` would happily
/// accept `file://`, `gopher://`, `dict://`, etc. Validation belongs at the
/// config layer too, but this backend never trusts its caller.
#[must_use]
fn is_http_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

/// Build the `curl` argument vector for a webhook POST.
///
/// The `--` terminator guarantees `url` is always treated as a positional
/// argument, never as an option — so a URL beginning with `-` (e.g.
/// `-o/etc/cron.d/x`) cannot be laundered into a curl flag. The response
/// body is written to `/dev/null`; `-S` keeps error messages on stderr.
#[must_use]
fn curl_args<'a>(body: &'a str, url: &'a str) -> Vec<&'a str> {
    vec![
        "-s",
        "-S",
        "-o",
        "/dev/null",
        "-X",
        "POST",
        "-H",
        "Content-Type: application/json",
        "--max-time",
        "10",
        "-d",
        body,
        "--",
        url,
    ]
}

/// Fire a webhook notification for a ban event.
///
/// Spawns a `curl` subprocess in the background. Returns immediately.
/// Non-`http(s)` URLs are refused and logged without spawning anything.
pub fn notify_ban(url: &str, ip: BanTarget, jail: &str, ban_time: i64) {
    let payload = serde_json::json!({
        "event": "ban",
        "ip": ip.to_string(),
        "jail": jail,
        "ban_time": ban_time,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    dispatch(url, &payload);
}

/// Fire a webhook notification for an unban event.
///
/// Non-`http(s)` URLs are refused and logged without spawning anything.
pub fn notify_unban(url: &str, ip: BanTarget, jail: &str) {
    let payload = serde_json::json!({
        "event": "unban",
        "ip": ip.to_string(),
        "jail": jail,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    dispatch(url, &payload);
}

/// Validate, serialize, admit, and spawn one delivery. Never blocks.
fn dispatch(url: &str, payload: &serde_json::Value) {
    if !is_http_url(url) {
        warn!(url = %url, "webhook: refusing non-http(s) URL");
        return;
    }
    let body = match serde_json::to_string(payload) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "webhook: failed to serialize payload");
            return;
        }
    };
    let Some(ticket) = LIMITER.try_admit() else {
        warn!(url = %url, limit = MAX_PENDING, "webhook: backlog full, dropping event");
        return;
    };
    let url = url.to_string();
    tokio::spawn(async move {
        let Some(_slot) = ticket.run_slot().await else {
            return;
        };
        match tokio::time::timeout(DELIVERY_TIMEOUT, deliver(&body, &url)).await {
            Ok(Ok(())) => {}
            Ok(Err(msg)) => warn!(url = %url, error = %msg, "webhook POST failed"),
            Err(_) => warn!(url = %url, "webhook: delivery timed out, killed curl"),
        }
    });
}

/// Run `curl` once with stdout discarded and stderr capped.
async fn deliver(body: &str, url: &str) -> Result<(), String> {
    let mut child = tokio::process::Command::new("curl")
        .args(curl_args(body, url))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("curl not available: {e}"))?;

    let stderr = match child.stderr.take() {
        Some(pipe) => read_capped(pipe, STDERR_CAP).await,
        None => String::new(),
    };
    let status = child
        .wait()
        .await
        .map_err(|e| format!("wait for curl: {e}"))?;
    if status.success() {
        return Ok(());
    }
    Err(format!("curl exited with {status}: {}", stderr.trim()))
}

/// Read at most `cap` bytes from `reader`, then drain (and discard) the rest
/// so the child never blocks on a full pipe.
pub(crate) async fn read_capped<R>(mut reader: R, cap: u64) -> String
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    if let Err(e) = (&mut reader).take(cap).read_to_end(&mut buf).await {
        return format!("<stderr read error: {e}>");
    }
    if let Err(e) = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await {
        warn!(error = %e, "webhook: draining curl stderr failed");
    }
    String::from_utf8_lossy(&buf).into_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
#[path = "webhook_test.rs"]
mod webhook_test;
